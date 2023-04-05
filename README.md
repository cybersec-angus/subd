# SUBD - An all-in-one subdomain enumeration, recon and hijack scanning tool

SUBD is a cool and simple Python script aimed at both blue teams and red teams that can do the following:

 - Enumerate subdomains based on a word list
 - Scan the subdomains for A records and CNAME records
 - Scan for services running on CNAME records, for example, AWS S3
 - Find de-provisioned services running on CNAME records that may be vulnerable to subdomain hijacking
 - Run port scans on all enumerated subdomains, with options for the most common 22 ports or the top 145 ports
 - Run scheduled scans periodically
 - Email results to an admin email

## Installation
Easy to install:
Step 1:
`cd /desired/install/directory`
Step 2: Install the required dependencies, run:
`pip install -r requirements.txt` 
or 
`pip3 install -r requirements.txt` 

This script requires the following packages:
-   schedule
-   smtplib
-   dnspython
-   requests

## Usage

To run the script, execute the following command from the install directory:
`python3 subd.py -w /path/to/wordlist.txt -d domain.com [other_args]` 

### Arguments
#### Main arguments
|Argument|Description  |
|--|--|
| -w, --wordlist | Path to the wordlist for subdomain enumeration (required) |
| -d, --domains | Domain(s) as either a single domain, multiple domains (domain.com,domain2.com) or CSV file (required) |
| -v, --verbose | Enable verbose output |
| -e, --email | Admin email to send notifications to (requires additional setup, see below) |
| -ps, --port-scan| Enables port scan on discovered subdomains |

#### Scan Options (Mutually Exclusive)
|Argument|Description  |
|--|--|
| -s, --scan | Simple subdomain enumeration. Won't report on service, but will show a CNAME/A record. Can be used in conjunction with the -ps argument to enable port scanning |
| -id, --id | Service identification. Will attempt to identify services that CNAME records are pointing to. Not required if using -hj/--vuln. Note: This is based on a limited dictionary. |
| -hj, --vuln | Enumerates all subdomains, identifies service, and checks if the subdomain is vulnerable to subdomain hijacking. I.E, the CNAME is pointing to a third-party service that longer exists and could be reclaimed by an attacker.|
#### Port Scan Options (Mutually Exclusive)
|Argument|Description  |
|--|--|
| -qs, --quick-port-scan | Quick port scan of the top 22 most common ports. Includes HTTPS, HTTP, SSH, Telnet, etc. See below for more details. |
| -fs, --full-port-scan | Full port scan of the top 145 ports used on web servers. Note: This will take a while. It is recommended to run this alongside the email feature, and leave it to do its thing; Especially with a long wordlist.|
#### Additional Arguments
|Argument|Description  |
|--|--|
| --email-server | SMTP server for sending email notifications |
| --email-port | SMTP server port |
| --email-user | SMTP server username |
| --email-password | SMTP server password |
| -sc, --schedule | Schedule scans to repeat. Value is a number in minutes. Should be used with a --interval argument unless you want to use the default interval of 60 mins. |
| --interval | Scan interval in minutes (As above, default: 60) |

## Examples
#### Example 1:
To run a simple domain enumeration scan, with port scanning enabled, and verbose enabled:
`python3 subd.py -w /path/to/wordlist.txt -d domain.com -v -ps -s` 

**Expected output:**

                              _
              .         _____|___
             .      ___/  o o o  \____
             .     /    ---------     |
              .   |     ---------     |
                8-=\_________________/
           _____ __  ______  ____               
          / ___// / / / __ )/ __ \  ____  __  __
          \__ \/ / / / __  / / / / / __ \/ / / /
         ___/ / /_/ / /_/ / /_/ / / /_/ / /_/ / 
        /____/\____/_____/_____(_) .___/\__, /  
                                /_/    /____/   
       [*] By CyberSec-Angus
       [*] github.com/cybersec-angus
       [*] Starting to find subdomains...
        
    [INFO] Scanning domain(s): ['example.com']
    [INFO] Main domain A record: 1.1.1.1
    [INFO] Trying subdomain.example.com
    [INFO] Open ports on subdomain.example.com: 80 (HTTP), 443 (HTTPS)
    [INFO] Found subdomain.example.com with status code: 200
    [SUBDOMAIN] Subdomain [subdomain.example.com] A record is the same as main domain: 1.1.1.1 | Status code: 200

#### Example 2:
To run a domain enumeration and takeover detection scan with a quick port scan:
`python3 subd.py -w /path/to/wordlist.txt -d domain.com -hj -v -ps -s ` 

**Expected output:**

                              _
              .         _____|___
             .      ___/  o o o  \____
             .     /    ---------     |
              .   |     ---------     |
                8-=\_________________/
           _____ __  ______  ____               
          / ___// / / / __ )/ __ \  ____  __  __
          \__ \/ / / / __  / / / / / __ \/ / / /
         ___/ / /_/ / /_/ / /_/ / / /_/ / /_/ / 
        /____/\____/_____/_____(_) .___/\__, /  
                                /_/    /____/   
       [*] By CyberSec-Angus
       [*] github.com/cybersec-angus
       [*] Starting to find subdomains...
        
    [INFO] Scanning domain(s): ['example.com']
    [INFO] Main domain A record: 1.1.1.1
    [INFO] Trying subdomain.example.com
    [INFO] Open ports on subdomain.example.com: 22 (SSH), 53 (DNS), 80 (HTTP), 443 (HTTPS)
    [INFO] Found subdomain.example.com with status code: 404
    [VULNERABLE] subdomain.example.com pointing to AWS/S3 with CNAME: vuln-aws-link.amazonaws.com Click here to takeover this subdomain: https://aws.amazon.com/ | Status code: 404
This command will use the specified wordlist, scan the domain `example.com`, enable verbose output, perform a port scan, and find live subdomains that could be hijacked.
## More info and FAQs
#### FAQs:
|Question| Answer |
|--|--|
| Why develop SUBD? | SUBD was designed as an all-in-one tool to scan for multiple vulnerabilities, streamlining recon for red teams and proactive defence for blue teams. | 
| What is a subdomain takeover? | A subdomain takeover occurs when a subdomain's CNAME service is no longer active, allowing an attacker to create a new service with the same name and gain control of the subdomain. | 
| Can subdomain hijacking happen with other DNS records? | Although possible with other DNS records, subdomain takeovers are most commonly associated with CNAME records. | 
| What can hijacked subdomains be used for? | Hijacked domains are primarily used for phishing campaigns and cookie harvesting, as the authentic-looking subdomain can trick victims into revealing sensitive information. |
| If the script says a subdomain is vulnerable, does this mean I can hijack it? | Normally, but not always. This depends on the service and some services prevent you from linking a pre-existing domain to their service if it is already in use with a different account.| 
| What can hijacked subdomains be used for? | Hijacked domains are primarily used for phishing campaigns and cookie harvesting, as the authentic-looking subdomain can trick victims into revealing sensitive information. |

#### Future features to be added:
Within the next 6 months, I intend to implement the following features to make SUBD even better for everyone. 
 - API functionality - Will be really useful to be able to create custom web apps around the SUBD script. 
 - Increase dictionary size for services - have even more services to be identified
 - A record service identification - For example, if WordPress is running on a subdomain, the script will be able to identify the service using HTTP response signatures, and other information. 
 - Ability to use a proxy for when HTTP requests are sent, for example with the `get_http_status` function
 - Handle services where deprovisioned services would be non resolving, or have no HTML content signatures. For example, some AWS products that return an `NXDOMAIN` when the service is no longer in use. This is currently handled with a `[POTENTIAL]` output, where the CNAME matches, but there isn't a HTML signature to confirm with. I want to handle these more efficiently. 
## Disclaimer
This script is intended for educational purposes and lawful use only. It should only be used with the explicit permission of the domain owner or within the guidelines of a bug bounty program that permits the use of such tools. The developer of this script is not responsible or liable for any misuse or damage resulting from the improper use of this script. Before using this script in a bug bounty program, please ensure that the program's rules and guidelines allow its use. Use this script responsibly and ethically.
