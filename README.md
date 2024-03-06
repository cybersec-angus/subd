
# Subd - An all-in-one subdomain enumeration, recon and hijack scanning tool

Subd is a cool and simple Python tool aimed at all different types of security functions that can do the following:
 - Enumerate subdomains based on a word list
 - Scan the subdomains for A records and CNAME records
 - Scan for services running on CNAME records, for example, AWS S3
 - Find de-provisioned services running on CNAME records that may be vulnerable to subdomain hijacking
 - Run port scans on all enumerated subdomains, with options for the most common 22 ports, the top 145 ports, or a custom dictionary of ports
 - Scans for MX records and attempts to identify mail providers based on a dictionary of MX records and their providers
 - Run scheduled scans periodically
 - Email results to an admin email*
## Introduction
Public-facing attack surfaces are arguably one of the most important things to monitor and track, as they are the easiest parts of an IT estate to find and enumerate. One such part of a public attack surface is a companies domains, and subdomains. 
#### A bit of info about DNS records
Most subdomains are pointing to one of 4 types of records:
- `A record` - An IPv4 address (or set of IPv4 addresses) normally with a web-server of some description on 
- `AAA record` - An IPv6 address (or set of IPv6 addresses) normally with a web-server of some description on 
- `CNAME record` - AKA a canonical name - Is essentially an alias to another domain. This is very common when using third party services on custom domains. For example, for help centres. Instead of a customer seeing companyname.helpcentre.com the CNAME for the subdomain help.companyname.com would point to companyname.helpcentre.com. These are vulnerable, as described below
- `MX records` - AKA a mail exchange record - Is when a domain or subdomain points to a mail server for the purposes of sending and receiving emails. These are also vulnerable to hijacking if they are pointing to an MX record where the account no longer exists and there is no TXT record verification - Subd can't help with these... yet. 
#### So what is Subdomain Hijacking?
Subdomain hijacking is a very specific type of attack, that involves the discovery of CNAME records where the service behind the CNAME has been de-provisioned, however, the CNAME remains in place. This isn't a risk if the service reserves old and de-provisioned subdomains, as somebody else can't come along and spin up a new service with the same name. But it is an issue if they don't. 

If a service has been de-provisioned, and the CNAME remains in place, then an attacker can essentially create a new resource, with the same name that the CNAME is pointing to, and hijack that domain. This can lead to a number of potential uses for an attacker, and allow the now hijacked subdomain to be used for cookie harvesting or phishing attacks. 

#### How do I stop subdomain hijacking from being an issue?
Use Subd! and scan for potentially vulnerable subdomains. It is also worth keeping an audit of subdomains, and the associated records. This can be done by an internal process whereby all subdomains are requested through an auditable process, implemented and reviewed periodically as to whether they are needed still. Additionally, utilising something like continual scanning and monitoring is also worthwhile. 
## Installation
Subd is really easy to install and get started with:
<br>
<br>
Step 1:
`git clone https://github.com/cybersec-angus/subd/`
<br>
<br>
Step 2:
`cd subd/`
<br>
<br>
Step 3: Install the required dependencies, run:
`pip install -r requirements.txt` 
or 
`pip3 install -r requirements.txt` 
<br>
<br>
This script requires the following packages:
-   schedule
-   smtplib
-   dnspython
-   requests
-   paramiko - Used for the SSH connection tests*


## Usage

To run the script, execute the following command from the install directory:
`python3 subd.py -w /path/to/wordlist.txt -d domain.com [other_args]` 

### Arguments
#### Main arguments
|Argument|Description  |
|--|--|
| -w, --wordlist | Path to the wordlist for subdomain enumeration (required) |
| -d, --domains | Domain(s) as either a single domain, multiple domains* (domain.com,domain2.com) or CSV file (required) |
| -v, --verbose | Enable verbose output |
| -ps, --port-scan| Enables port scan on discovered subdomains |
| -is, --ignore-same| Ignores results where the subdomain is pointing to the same A record or CNAME as the main domain. This is beneficial when your root domain has the record |
| -m, --mail-id| Detects MX records, and attempts to identify the mail provider based on the (currently very limited) dictionary |

#### Scan Options (Mutually Exclusive)
|Argument|Description  |
|--|--|
| -s, --scan | Simple subdomain enumeration. Won't report on service, but will show a CNAME/A record. Can be used in conjunction with the -ps argument to enable port scanning |
| -id, --id | Service identification. Will attempt to identify services that CNAME records are pointing to. Not required if using -hj/--vuln. Note: This is based on a limited dictionary, and is currently only matching the CNAME to the dictionary. In the future, I aim to include service identification based on HTML signatures. |
| -hj, --vuln | Enumerates all subdomains, identifies service, and checks if the subdomain is vulnerable to subdomain hijacking. I.E, the CNAME is pointing to a third-party service that longer exists and could be reclaimed by an attacker.|
#### Port Scan Options (Mutually Exclusive)
|Argument|Description  |
|--|--|
| -qs, --quick-port-scan | Quick port scan of the top 22 most common ports. Includes HTTPS, HTTP, SSH, Telnet, etc. See below for more details. |
| -fs, --full-port-scan | Full port scan of the top 145 ports used on web servers. Note: This will take a while. It is recommended to let it do its thing and return later,  especially with a long wordlist.|
| -cs, --custom-port-scan |Uses the custom port dictionary file `/dictionaries/custom_ports.py` This is useful for two reasons - A) Targeted recon, where you have specific ports to test for, for example, Splunk. B) Where you want to reduce the execution time, and therefore a limited number of ports is beneficial.|
#### Additional Arguments
|Argument|Description  |
|--|--|
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
## FAQs

|Question| Answer |
|--|--|
| Why develop Subd? | Subd was designed as an all-in-one tool to scan for multiple vulnerabilities, streamlining recon for red teams and proactive defence for blue teams. | 
| What is a subdomain takeover? | A subdomain takeover occurs when a subdomain's CNAME service is no longer active, allowing an attacker to create a new service with the same name and gain control of the subdomain. | 
| Can subdomain hijacking happen with other DNS records? | Although possible with other DNS records, subdomain takeovers are most commonly associated with CNAME records. | 
| What can hijacked subdomains be used for? | Hijacked domains are primarily used for phishing campaigns and cookie harvesting, as the authentic-looking subdomain can trick victims into revealing sensitive information. |
| If the tool says a subdomain is vulnerable, does this mean I can hijack it? | Normally, but not always. This depends on the service and some services prevent you from linking a pre-existing domain to their service if it has previously been used with a different account (making the CNAME reserved). In some cases, attackers may be able to use social engineering to free up the reservation and hijack the subdomain, which is why it is still listed.| 
| Who developed Subd? | Subd was developed by CyberSec-Angus, an independent security researcher focused on OSINT, external attack surfaces, and NetSec. You can find out more about him and his work on github.com/cybersec-angus. |
| Why the submarine theme? | Submarines are stealthy, can operate covertly to map out hidden vulnerabilities just below the surface. Subd takes a similar approach to identify subdomains and attack surfaces that may not be obvious. |
| What permissions or authorizations does Subd require? | Subd performs passive scans, queries public records and does not make any changes or interact with target systems. That being said, ensure you have permission before scanning any domains or systems, and refrain from using Subd for illegal purposes. The developer will NOT be help accountable for any illegality. See the disclaimer at the bottom of this readme for more info.  |
| What permissions or authorisations does Subd require? | Subd performs passive scans, queries public records and does not make any changes or interact with target systems. That being said, ensure you have permission before scanning any domains or systems, and refrain from using Subd for illegal purposes. The developer will NOT be help accountable for any illegality. See the disclaimer at the bottom of this readme for more info.  |
| What wordlists should I use? | The world is your oyster. There are loads of great wordlists out there, and it really depends on the purpose of your scanning. I have included three wordlists with this tool. 1) `all.txt` is an open-source wordlist that is used by a lot of enumeration tools and contains over 21mn potential subdomains. This will take ages to complete, so use sparingly. 2) `top-250.txt` a wordlist of the top 250 subdomains, based on the most common subdomains on webservers. 3) A template for testing purposes. |
| How does Subd handle subdomains of subdomains? EG. `subd.home.example.com`| These are handled through the wordlist. If you are wanting to discover these, ensure that you have any potential versions of these in your wordlist. Using the example given, the wordlist would need to contain `subd.home` to get `subd.home.example.com`|

## Break log (stuff that is currently broken):
Unfortunately, some parts of the script are broken, for a few different reasons. These are either due to me needing to fix something else first, or simply not having the time to fix it yet. So far, I am aware of the following things that are broken:

 - When trying to use scan multiple domains, it will scan the first one and exit the script. This is a simple fix, that I just need to get round to sorting
 - Errors aren't handled, which means that the script will close if there's things like an invalid wordlist file
 - The mail sending functionality doesn't work

## Future plans and timeline:
The following features are on my radar to implement and improve over the next few months. See the below timeline (This is from the beginning of March, 2024):
#### 0-3 months:
 - Fix outstanding issues, as per the Break Log
 - Implement connection validation tests, based on the output of the port scan. This will be most beneficial for things like DNS, where the port may be open but the server is not able to resolve DNS queries (for example a DNS server that only accepts queries from specific IP ranges. The tests have (mostly) been written, and the functionality just needs adding to the relevent functions in `utils.py` and `core.py`
 - Increase dictionary size for services - have even more services to be identified
 - A record service identification - For example, if WordPress is running on a subdomain, the script will be able to identify the service using, HTML signatures, HTTP response signatures, and other information. 
 - Ability to use a proxy for when HTTP requests are sent, for example with the `get_http_status` function
 #### 3-6 months:
 - Handle services where de-provisioned services would be non resolving, or have no HTML content signatures. For example, some AWS products that return an `NXDOMAIN` when the service is no longer in use. This is currently handled with a `[POTENTIAL]` output, where the CNAME matches, but there isn't a HTML signature to confirm with. I want to handle these more efficiently.
#### 6 months and beyond:
 - API functionality - Will be really useful to be able to create custom web apps around the Subd script. 

## Change log
Subd follows the Semantic Versioning system for version releases. This means that the version numbers are formatted as follows, based on the example "1.2.3":
1. This is the major version number - This changes when a major release has been implemented, that impacts either the core functionality of the tool or how it interacts with other services. This is also used in the case of full refactoring, as in the case of version 2.0.0.
2. This is the minor version number - This changes when functionality has either been added or removed, but does not change the core functionality of the script. 
3. This is the patch version number - This changes when there has been a patch released, and does not change the function of the code. Also used in break-fixes. 

#### Version 1

 - Version 1.0.0:
	 - Initial release with subdomain enumeration, scanning functionality, and Hijack-ability scanning. 
- Version 1.0.1:
	-  Yellow submarine, like the beetles song.
#### Version 2
- Version 2.0.0:
	- Refactoring of all code, so that it is split across multiple files. This includes the following, which used to be in the same files:
		- `Utils.py` - All of functions referenced in the main script, such as the CNAME identification, port scanning functionality, etc.
		- `readme.md` - This readme file - Also been updated to reflect the changes in the tools functionality. 
		- `Core.py` - The main CLI part of the script, which handles arguments and outputs. All functions called are in Utils.py.
		- `Parse_args.py` - The part of the script responsible for parsing the arguments and outputting the help menu. 
		- `Connection_tests.py` - This *will* be the part of the script responsible for validating connections for certain protocols, such as DNS. See the 'Future plans' section for more info. 
		- `Dictionaries`  - In this folder, you can find all of the python dictionaries needed for the service to run, these have been split up out of the main script, which was the case on the old one. See below for the different dictionaries:
			-  `common_ports.py` - Dictionary of the most common 22 ports
			- `custom_ports.py` - Dictionary for a custom port list, for specific reasons. Edit as appropriate
			- `full_ports.py` - Top 145 ports. May add more to this later
			- `inactive_services.py` - Services and matching HTML signatures for Hijack-able subdomains
			- `main_services.py` - Dictionary of the top mail services, and their respective MX record TLD
			- `services.py` - Dictionary of all the potential services that can be enumerated on Subdomains
			- `takeover_urls.py` - Dictionary of where you can takeover a subdomain, if a subdomain is found to be hijack-able
	- Added a Mail enumeration tool, so that you can enumerate mail services behind both the main domain and any enumerated domains
	- Added the ability to suppress results where the subdomain points to the same A record or CNAME value as the main domain. This is especially useful for hosting providers that attempt to block enumeration efforts by having a wildcard subdomain pointing to the same A record as the root domain. Also useful if the main domain has an A record of `None` so that you don't get loads of false positives
	- Will port scan the root domain and subdomains when port scanning is enabled - Previously, it would only scan any subdomains, now it also scans the root domain first.  
	- Added additional info to the help menu, as well as changing a few colours and texts on the CLI interface. 
- Version 2.0.1 - Fixed the issues previously mentioned in the break log around the mail identification function not working.
# Disclaimer
This script is intended for educational and lawful use only. It should only be used with the explicit permission of the domain owner or within the guidelines of a bug bounty program that permits the use of such tools. The developer of this script is not responsible or liable for any misuse or damage resulting from the improper use of this script. Before using this script in a bug bounty program, please ensure that the program's rules and guidelines allow its use. Use this script responsibly and ethically.

\* Feature not yet working/live.
