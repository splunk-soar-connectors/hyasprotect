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
