#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json

# Phantom App imports
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Usage of the consts file is recommended
from hyasprotect_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class HyasProtectConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(HyasProtectConnector, self).__init__()

        self._state = None
        self._apikey = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        # self._base_url = None

    def _handle_py_ver_compat_for_input_str(self, input_str):

        """
        This method returns the encoded|original string based on the Python
        version.

        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic
        'input_str - Python 3; encoded input_str -
        Python 2')
        """
        try:
            if input_str and self._python_version < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode(
                    "utf-8")
        except Exception:
            self.debug_print(
                "Error occurred while handling python 2to3 compatibility for "
                "the input string"
            )

        return input_str

    def _get_error_message_from_exception(self, e):
        """This function is used to get appropriate error message from the
        exception.
        :param e: Exception object
        :return: error message
        """
        error_code = HYAS_UNKNOWN_ERROR_CODE_MSG
        error_msg = HYAS_UNKNOWN_ERROR_MSG
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = HYAS_UNKNOWN_ERROR_CODE_MSG
                    error_msg = e.args[0]
        except Exception:
            pass

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = HYAS_TYPE_ERROR_MSG
        except Exception:
            error_msg = HYAS_UNKNOWN_ERROR_CODE_MSG

        return "Error Code: {0}. Error Message: {1}".format(error_code,
                                                            error_msg)

    def _validating_ioc(self, action_result, ioc, val):
        try:
            if ioc in IOC_NAME:
                if ioc == 'ip':
                    return bool(re.fullmatch(IOC_NAME[ioc], val)) or bool(
                        re.fullmatch(IPV6_REG, val))
                else:
                    return bool(re.fullmatch(IOC_NAME[ioc], val))
        except:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to validate the IOC"
                ),
                None,
            )

    def _process_empty_response(self, response, action_result):
        if 200 <= response.status_code < 205:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR,
                "Empty response and no information in the header"
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")

            # Remove the script, style, footer and navigation part from the
            # HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()

            error_text = soup.text.encode("utf-8")
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        error_text = self._handle_py_ver_compat_for_input_str(error_text)

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text
        )

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            self.save_progress("Cannot parse JSON")
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 205:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        # error_info = resp_json.get('error', {})
        if resp_json.get("code") and resp_json.get("message"):
            error_details = {
                "message": self._handle_py_ver_compat_for_input_str(
                    resp_json.get("code")
                ),
                "detail": self._handle_py_ver_compat_for_input_str(
                    resp_json.get("message")
                ),
            }
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error from server, Status Code: {0} data returned: {"
                    "1}".format(
                        r.status_code, error_details
                    ),
                ),
                resp_json,
            )
        else:
            message = self._handle_py_ver_compat_for_input_str(
                r.text.replace("{", "{{").replace("}", "}}")
            )
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error from server, Status Code: {0} data returned: {"
                    "1}".format(
                        r.status_code, message
                    ),
                ),
                resp_json,
            )

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if
        # the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if (200 <= r.status_code < 205) and (not r.text):
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data " \
                  "from server: {1}".format(r.status_code,
                                            self._handle_py_ver_compat_for_input_str(
                                                r.text.replace("{",
                                                               "{{").replace(
                                                    "}", "}}")),
                                            )
        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def indicator_data_points(self, results: dict):
        verdict = results.get("verdict")
        reason = results.get("reasons")
        if len(reason) == 0:
            reason = "N/A"
        row = {"Verdict": verdict, "Reasons": reason}
        return row

    def _make_rest_call(
            self, param,
            endpoint,
            action_result,
            input_param,
            params=None,
            body=None,
            headers=None,
            method="get",
    ):
        # **kwargs can be any additional parameters that requests.request
        # accepts
        # url = BASE_URL + endpoint
        self.save_progress(HYAS_MSG_CREATED_URL)
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            # Set the action_result status to error, the handler function
            # will most probably return as is
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unsupported method: {0}".format(method)
                ),
                None,
            )
        except Exception as e:
            # Set the action_result status to error, the handler function
            # will most probably return as is
            error_message = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Handled exception: {0}".format(error_message)
                ),
                None,
            )

        # Create a URL to connect to

        if endpoint == DOMAIN_TEST_CONN_ENDPOINT:
            url = f"{BASE_URL}{endpoint}{DOMAIN_TEST_VALUE}"
        else:
            url = f"{BASE_URL}{endpoint}{param[input_param]}"

        try:
            response = request_func(url, params=params, data=body,
                                    headers=headers)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error connecting: {0}".format(error_message)
                ),
                None,
            )
        if response.status_code == 401:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR,
                                         HYAS_INVALID_APIKEY_ERROR),
                None,
            )
        return self._process_response(response, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        action_id = self.get_action_identifier()
        self.save_progress(f"In action handler for: {action_id}")
        input_param = DOMAIN_TEST

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.
        endpoint = f"{DOMAIN_TEST_CONN_ENDPOINT}"
        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(
            param,
            endpoint,
            action_result,
            input_param,
            headers=self._headers
        )
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action
            # result should contain all the error details
            # for now the return is commented out, but after implementation,
            # return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

            # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't
        # set the message, but use the summary

    def _handle_all_actions(self, param):
        all_response = {}
        action_id = self.get_action_identifier()
        self.save_progress(f"In action handler for: {action_id}")
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print(action_id_param[action_id])

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        try:
            input_param = action_id_param[action_id]
            if input_param in IOC_DETAILS:
                endpoint = IOC_DETAILS[input_param]["endpoint"]

                validating_ioc = self._validating_ioc(
                    action_result,
                    input_param,
                    param[input_param],
                )
                if validating_ioc:
                    ret_val, response = self._make_rest_call(param,
                                                             endpoint,
                                                             action_result,
                                                             input_param,
                                                             headers=self._headers
                                                             )

                    if phantom.is_fail(ret_val):
                        return ret_val

                    try:
                        all_response[input_param] = self.indicator_data_points(
                            response
                        )
                        action_result.add_data(all_response)
                        return action_result.set_status(phantom.APP_SUCCESS)
                    except:
                        return action_result.set_status(
                            phantom.APP_ERROR,
                            "unable to flatten action json response.",
                            None,
                        )

            else:
                return action_result.set_status(
                    phantom.APP_ERROR, HYAS_ASSET_ERR_MSG, None
                )

        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Unable to retrieve actions results. Error: {str(e)}",
                None,
            )

        return action_result.set_status(
            phantom.APP_ERROR, HYAS_ERR_MSG_INVALID_INDICATOR_VALUE
        )

    def handle_action(self, param):

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id in [
            "ip_verdict",
            "domain_verdict",
            "nameserver_verdict",
            "fqdn_verdict"

        ]:
            return self._handle_all_actions(param)
        elif action_id in "test_connectivity":
            return self._handle_test_connectivity(param)

    def initialize(self):
        """
               # Access values in asset config by the name

               # Required values can be accessed directly
               required_config_name = config['required_config_name']

               # Optional values should use the .get() function
               optional_config_name = config.get('optional_config_name')
               """
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        try:

            config = self.get_config()
            self._apikey = config[API_KEY]
            # self.debug_print(self._apikey)
            self._headers = {APIKEY_HEADER: self._apikey}
            # self.debug_print(self._headers)
        except Exception:
            return phantom.APP_ERROR

        # self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = HyasProtectConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data,
                               headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print(
                "Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = HyasProtectConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
