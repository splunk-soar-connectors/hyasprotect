# pylint: disable=missing-module-docstring
import re

# Define your constants here
IP = "ip"
DOMAIN = "domain"
NAMESERVER = "nameserver"
FQDN = "fqdn"
IP_REG = r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][' \
         r'0-9]|[01]?[0-9][0-9]?)\b([^\/]|$)'
IPV6_REG = r'\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{' \
           r'1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[' \
           r'0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,' \
           r'4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,' \
           r'3}(:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,' \
           r'2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,' \
           r'4}){1,6})|:(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,' \
           r'4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(' \
           r'2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,' \
           r'1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[' \
           r'0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,' \
           r'1}[0-9]){0,1}[0-9]))\b'

DOMAIN_REG = re.compile(
    r"^(?:[a-zA-Z0-9]"  # First character of the domain
    r"(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)"  # Sub domain + hostname
    r"+[A-Za-z0-9][A-Za-z0-9-_]{0,61}"  # First 61 characters of the gTLD
    r"[A-Za-z]$"  # Last character of the gTLD
)
# URL_REG = "((http|https)://)(www.)?[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[
# a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)"
IOC_NAME = {
    "ip": IP_REG,
    "domain": DOMAIN_REG,
    "fqdn": DOMAIN_REG,
    "nameserver": DOMAIN_REG,
}

HYAS_ERR_MSG_INVALID_INDICATOR_VALUE = "Error: Invalid Indicator value"

BASE_URL = "https://api.hyas.com"
IP_REPUTATION_ENDPOINT = "/protect/ip/"
FQDN_REPUTATION_ENDPOINT = "/protect/fqdn/"
NAMESERVER_REPUTATION_ENDPOINT = "/protect/nameserver/"
DOMAIN_REPUTATION_ENDPOINT = "/protect/domain/"

action_id_param = {
    "ip_verdict": IP,
    "domain_verdict": DOMAIN,
    "nameserver_verdict": NAMESERVER,
    "fqdn_verdict": FQDN,
}

# ioc end points
IOC_DETAILS = {
    IP: {"endpoint": IP_REPUTATION_ENDPOINT, "indicator_type": DOMAIN},
    FQDN: {"endpoint": FQDN_REPUTATION_ENDPOINT, "indicator_type": FQDN},
    NAMESERVER: {"endpoint": NAMESERVER_REPUTATION_ENDPOINT,
                 "indicator_type": NAMESERVER},
    DOMAIN: {"endpoint": DOMAIN_REPUTATION_ENDPOINT, "indicator_type": DOMAIN},

}

APIKEY_HEADER = "x-api-key"  # pragma: allowlist secret
API_KEY = "apikey"  # pragma: allowlist secret

DOMAIN_TEST_CONN_ENDPOINT = "/protect/domain/"
DOMAIN_TEST = DOMAIN
DOMAIN_TEST_VALUE = 'google'

# error messages
HYAS_MSG_CREATED_URL = "Created Query URL"
HYAS_UNKNOWN_ERROR_CODE_MSG = "Error code unavailable"
HYAS_UNKNOWN_ERROR_MSG = "Unknown error occurred. Please check the asset " \
                         "configuration and|or action parameters."
HYAS_INVALID_APIKEY_ERROR = "Please provide a valid api key"
HYAS_TYPE_ERROR_MSG = (
    "Error occurred while connecting to the HYAS server. "
    "Please check the asset configuration and|or the action parameters."
)
HYAS_ASSET_ERR_MSG = "Please check the asset configuration and|or action " \
                     "parameters"
