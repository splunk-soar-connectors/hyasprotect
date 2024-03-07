[comment]: # "Auto-generated SOAR connector documentation"
# Hyas Protect

Publisher: Hyas  
Connector Version: 1\.1\.0  
Product Vendor: Hyas  
Product Name: Hyas Protect  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.2\.0  

This app implements investigative actions that return Hyas Protect Verdict for the given Indicators

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) Hyas, 2022-2024"
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Hyas Protect server. Below are the
default ports used by the Splunk SOAR Connector.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Hyas Protect asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apikey** |  required  | password | API KEY

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[ip verdict](#action-ip-verdict) - Perform this action to get the Hyas Verdict for IP  
[domain verdict](#action-domain-verdict) - Perform this action to get the Hyas Verdict for Domain  
[fqdn verdict](#action-fqdn-verdict) - Perform this action to get the Hyas Verdict for FQDN  
[nameserver verdict](#action-nameserver-verdict) - Perform this action to get the Hyas Verdict for Nameserver
[block dns](#action-block-dns) - Perform this action to add domain to deny list

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'ip verdict'
Perform this action to get the Hyas Verdict for IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to get Hyas Verdict | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.\*\.Verdict | string | 
action\_result\.\*\.Reasons | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'domain verdict'
Perform this action to get the Hyas Verdict for Domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get Hyas Verdict | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.\*\.Verdict | string | 
action\_result\.\*\.Reasons | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'fqdn verdict'
Perform this action to get the Hyas Verdict for FQDN

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**fqdn** |  required  | FQDN to get Hyas Verdict | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.fqdn | string | 
action\_result\.\*\.Verdict | string | 
action\_result\.\*\.Reasons | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'nameserver verdict'
Perform this action to get the Hyas Verdict for Nameserver

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**nameserver** |  required  | Nameserver to get Hyas Verdict | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.nameserver | string |  `domain` 
action\_result\.\*\.Verdict | string | 
action\_result\.\*\.Reasons | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |

## action: 'block dns'
Perform this action to add domain to deny list

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to be added to the deny list | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.\*\.message | string |
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 