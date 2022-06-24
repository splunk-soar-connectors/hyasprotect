[comment]: # "Auto-generated SOAR connector documentation"
# Hyas Protect

Publisher: Splunk  
Connector Version: 3.5.0  
Product Vendor: Hyas\
Product Name: Hyas\
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5.2.0

HYAS Protect is a generational leap forward utilizing authoritative knowledge of attacker infrastructure including unrivaled domain-based intelligence to proactively protect enterprises from cyberattacks. HYAS Protect is deployed as a cloud-based DNS security solution or through API integration with existing solutions. HYAS Protect combines infrastructure expertise and multi-variant communication pattern analysis to deliver reputational verdicts for any domain and infrastructure, allowing enterprises to preempt attacks while proactively assessing risk in real-time. HYAS Protect can enforce security, block command and control (C2) communication used by malware, ransomware, and botnets, block phishing attacks, and deliver a high-fidelity threat signal that enhances an enterprise’s existing security and IT governance stack.

This app implements investigative actions that return Hyas Protect Verdict for the object queried.

This app supports Security, Fraud & Compliance, Utilities

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Description of Action Parameters

1.  ### test connectivity (Action Workflow)

    -   This action will test the connectivity with the Hyas Protect server using the provided API key
        value.
    -   The action  validates the required asset parameter value and based on the value API
        response will be displayed.
    -   For successful test connectivity, the response will be "Test Connectivity Passed"

      

2. ### ip verdict

    - This action will get Hyas Protect Verdict for given IP Address.
   
    - **<u>Action Parameter</u> - ip**
        -   The value is IP Address.
        -   Example: 192.18.12.01

      

3. ### domain verdict

    - This action will get Hyas Protect Verdict for given Domain.

    -   **<u>Action Parameter</u> - domain**
        -   The value is a domain string.
        -   Example: hyas.com

      

4. ### fqdn verdict

    - This action will get Hyas Protect Verdict for given FQDN.

    - **<u>Action Parameter</u> - fqdn**
        - The value is a fqdn string.
        - Example: www.hyas.com

5. ### nameserver verdict

    - This action will get Hyas Protect Verdict for given Nameserver.

    - **<u>Action Parameter</u> - nameserver**
        - The value is a nameserver string.
        - Example: ns-380.awsdns-47.com




### Configuration Variables
The below configuration variable are required for this Connector to operate.  These variables are specified when configuring a Hyas Protect asset in SOAR.

| VARIABLE   | REQUIRED | TYPE     | DESCRIPTION |
|------------|----------|----------|-------------|
| **apikey** | required | password | API KEY     |

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity.  
[ip reputation](#action-ip-reputation) - Get Hyas Protect verdict for IP Address.\
[domain reputation](#action-domain-reputation) - Get Hyas Protect verdict for Domain.\
[fqdn reputation](#action-fqdn-reputation) - Get Hyas Protect verdict for FQDN.\
[nameserver reputation](#action-nameserver-reputation) - Get Hyas Protect verdict for Nameserver.


## action: 'test connectivity'
Validate the asset configuration for connectivity.

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action.

#### Action Output
No Output  

## action: 'ip verdict'
Get Hyas Protect verdict for given IP Address.

Type: **investigate**  
Read only: **True**

#### Action Parameters
ip

#### Action Output
| DATA PATH                           | TYPE    | CONTAINS |
|-------------------------------------|---------|----------|
| action\_result\.data\.\*\.Verdict   | string  |          |
| action\_result\.data\.\*\.Reasons   | string  |          |
| action\_result\.status              | string  |          |
| action\_result\.message             | string  |          |
| summary\.total\_objects             | numeric |          |
| summary\.total\_objects\_successful | numeric |          |

## action: 'domain verdict'
Get Hyas Protect verdict for given Domain.

Type: **investigate**  
Read only: **True**

#### Action Parameters
domain

#### Action Output
| DATA PATH                           | TYPE    | CONTAINS |
|-------------------------------------|---------|----------|
| action\_result\.data\.\*\.Verdict   | string  |          |
| action\_result\.data\.\*\.Reasons   | string  |          |
| action\_result\.status              | string  |          |
| action\_result\.message             | string  |          |
| summary\.total\_objects             | numeric |          |
| summary\.total\_objects\_successful | numeric |          |

## action: 'fqdn verdict'
Get Hyas Protect verdict for given FQDN.

Type: **investigate**  
Read only: **True**

#### Action Parameters
fqdn

#### Action Output
| DATA PATH                           | TYPE    | CONTAINS |
|-------------------------------------|---------|----------|
| action\_result\.data\.\*\.Verdict   | string  |          |
| action\_result\.data\.\*\.Reasons   | string  |          |
| action\_result\.status              | string  |          |
| action\_result\.message             | string  |          |
| summary\.total\_objects             | numeric |          |
| summary\.total\_objects\_successful | numeric |          |

## action: 'nameserver verdict'
Get Hyas Protect verdict for given Nameserver.

Type: **investigate**  
Read only: **True**

#### Action Parameters
nameserver

#### Action Output
| DATA PATH                           | TYPE    | CONTAINS |
|-------------------------------------|---------|----------|
| action\_result\.data\.\*\.Verdict   | string  |          |
| action\_result\.data\.\*\.Reasons   | string  |          |
| action\_result\.status              | string  |          |
| action\_result\.message             | string  |          |
| summary\.total\_objects             | numeric |          |
| summary\.total\_objects\_successful | numeric |          |  

