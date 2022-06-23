# Define your constants here
IP = "ip"
DOMAIN = "domain"
NAMESERVER = "nameserver"
FQDN = "fqdn"

HYAS_ERR_MSG_INVALID_INDICATOR_VALUE = "Error: Invalid Indicator value"

BASE_URL = "https://api.hyas.com"
IP_REPUTATION_ENDPOINT = "/protect/ip/"
FQDN_REPUTATION_ENDPOINT = "/protect/fqdn/"
NAMESERVER_REPUTATION_ENDPOINT = "/protect/nameserver/"
DOMAIN_REPUTATION_ENDPOINT = "/protect/domain/"

APIKEY_HEADER = "x-api-key"  # pragma: allowlist secret
API_KEY = "apikey"  # pragma: allowlist secret

DOMAIN_TEST_CONN_ENDPOINT = "/protect/domain/"
DOMAIN_TEST_VALUE = 'google'

# error messages
HYAS_ERR_CODE_MSG = "Error code unavailable"
HYAS_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset " \
                           "configuration and|or action parameters"

HYAS_PARSE_ERR_MSG = "Unable to parse the error message. Please check the " \
                     "asset configuration and|or action parameters"

HYAS_MSG_CREATED_URL = "Created Query URL"
HYAS_UNKNOWN_ERROR_CODE_MSG = "Error code unavailable"
HYAS_INVALID_APIKEY_ERROR = "Please provide a valid api key"
HYAS_ASSET_ERR_MSG = "Please provide the valid indicator value"
IP_REG = r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[' \
                 r'0-4][' \
                 r'0-9]|[01]?[0-9][0-9]?)\b([^\/]|$)'
IPV6_REG = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{" \
                   r"1,4}:){1," \
                   r"7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1," \
                   r"4}|([0-9a-fA-F]{1," \
                   r"4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1," \
                   r"4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1," \
                   r"3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1," \
                   r"2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[" \
                   r"0-9a-fA-F]{1," \
                   r"4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[" \
                   r"0-9a-fA-F]{0," \
                   r"4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0," \
                   r"1}((25[0-5]|(" \
                   r"2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[" \
                   r"0-4]|1{0," \
                   r"1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(" \
                   r"2[" \
                   r"0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{" \
                   r"0," \
                   r"1}[0-9]){0,1}[0-9]))"
DOMAIN_REG = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0," \
                     r"61}[A-Za-z0-9])?\.)+[" \
                     r"A-Za-z0-9][A-Za-z0-9-_]{0,61}[A-Za-z]$"

IOC_NAME = {
            "ip": IP_REG,
            "domain": DOMAIN_REG,
            "fqdn": DOMAIN_REG,
            "nameserver": DOMAIN_REG,
        }
EMPTY_RESPONSE = "Empty response and no information in the header"
ERROR_TEXT = "Cannot parse error details"
UNABLE_TO_FLATTEN_JSON = "unable to flatten action json response."
IP_VERDICT = 'ip_verdict'
DOMAIN_VERDICT = 'domain_verdict'
FQDN_VERDICT = 'fqdn_verdict'
NAMESERVER_VERDICT = 'nameserver_verdict'
TEST_CONNECTIVITY = 'test_connectivity'
