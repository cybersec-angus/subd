import sys
from termcolor import colored
import argparse
import socket
from argparse import ArgumentParser
import csv
import requests
import dns.resolver
import time
import smtplib
import re
import requests
from dns.resolver import NoAnswer
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


SERVICES = {
    "Acquia": "*.acquia.com.",
    "ActiveCampaign": "*.activecampaign.com.",
    "Aftership": "*.aftership.com.",
    "Aha": "*.aha.io.",
    "AWS/S3": "*.s3.amazonaws.com.",
    "AWS/Elastic beanstalk": "*.us-east-1.elasticbeanstalk.com.",
    "AWS/Other": "*.amazonaws.com.",
    "Bigcartel": "*.bigcartel.com.",
    "BitBucket": "*.bitbucket.org.",
    "Brightcove": "*.brightcove.com.",
    "Campaignmonitor": "*.campaignmonitor.com.",
    "Cargo": "*.cargo.site.",
    "CloudFront": "*.cloudfront.net.",
    "Desk": "*.desk.com.",
    "Fastly": "*.fastly.net.",
    "FeedPress": "*.feed.press.",
    "GetResponse": "*.getresponse.com.",
    "Ghost": "*.ghost.io.",
    "Github": "*.github.com.",
    "Helpjuice": "*.helpjuice.com.",
    "Helpscout": "*.helpscout.com.",
    "Heroku": "*.herokuapp.com.",
    "Intercom": "*.intercom.com.",
    "Jetbrains": "*.jetbrains.com.",
    "Kajabi": "*.kajabi.com.",
    "Mashery": "*.mashery.com.",
    "Pantheon": "*.pantheon.io.",
    "Pingdom": "*.pingdom.com.",
    "Proposify": "*.proposify.com.",
    "Shopify": "*.myshopify.com.",
    "Simplebooklet": "*.simplebooklet.com.",
    "Smartling": "*.smartling.com.",
    "StatuPage": "*.statuspage.io.",
    "Surge": "*.surge.sh.",
    "Surveygizmo": "*.surveygizmo.com.",
    "Stack FTP (GB)": "ftp.gb.stackcp.com.",
    "Stack FTP (US)": "ftp.us.stackcp.com.",
    "Stack FTP": "ftp.stackcp.com.",
    "Stack Mail": "mail.stackmail.com..",
    "Stack POP3": "pop3.stackmail.com.",
    "Stack IMAP": "imap.stackmail.com.",
    "Tave": "*.tave.com.",
    "TeamWork": "*.teamwork.com.",
    "Thinkific": "*.thinkific.com.",
    "Tictail": "*.tictail.com.",
    "Tilda": "*.tilda.cc.",
    "Tumbler": "*.tumblr.com.",
    "Unbounce": "*.unbounce.com.",
    "Uservoice": "*.uservoice.com.",
    "Vend": "*.vendhq.com.",
    "Webflow": "*.webflow.com.",
    "Wishpond": "*.wishpond.com.",
    "Wordpress": "*.wordpress.com.",
    "ZenDesk": "*.zendesk.com.",
    "feedpress": "*.feed.press.",
    "readme": "*.readme.io.",
    "statuspage": "*.statuspage.io.",
    "zendesk": "*.zendesk.com.",
    "worksites.net": "*.worksites.net.",
    "smugmug": "*.smugmug.com."
}

INACTIVE_SERVICE_HTML = {
    "Acquia": "This website is temporarily unavailable",
    "ActiveCampaign": "The requested URL /login was not found on this server",
    "Aftership": "Sorry, the page you are looking for could not be found",
    "Aha": "404 error page",
    "AWS/S3": "NoSuchBucket",
    "Bigcartel": "Theres nothing here, yet.",
    "BitBucket": "Repository not found",
    "Brightcove": "The page you are looking for could not be found.",
    "Campaignmonitor": "The page you requested could not be found",
    "Cargo": "The requested URL was not found on this server",
    "CloudFront": "404 Not Found",
    "Desk": "Sorry, we couldn't find what you were looking for",
    "Fastly": "Fastly error: unknown domain",
    "FeedPress": "The feed has not been found",
    "GetResponse": "GetResponse 404 - Page not found",
    "Ghost": "The thing you were looking for is no longer here, or never was",
    "Github": "There isn't a GitHub Pages site here.",
    "Helpjuice": "We could not find what you're looking for.",
    "Helpscout": "Page Not Found",
    "Heroku": "No such app",
    "Intercom": "This page is missing or has been moved",
    "Jetbrains": "is not a registered InCloud YouTrack",
    "Kajabi": "Sorry, this page isn't available.",
    "Mashery": "Unrecognized domain",
    "Pantheon": "The gods are wise, but do not know of the site which you seek.",
    "Pingdom": "404 Not Found",
    "Proposify": "Whatever you were looking for doesn't currently exist at this address",
    "Shopify": "Sorry, this shop is currently unavailable.",
    "Simplebooklet": "We couldn't find the page you were looking for.",
    "Smartling": "Domain is not configured",
    "StatuPage": "This page could not be found.",
    "Surge": "project not found",
    "Surveygizmo": "We're sorry, the page you requested could not be found.",
    "Tave": "The page you were looking for doesn't exist.",
    "TeamWork": "Oops - We didn't find your site.",
    "Thinkific": "You may have mistyped the address or the page may have moved.",
    "Tictail": "to target URL: <a href=\"https://tictail.com/\"",
    "Tilda": "Please check that you've entered the correct address",
    "Tumbler": "404 error: Page not found.",
    "Unbounce": "The requested URL was not found on this server",
    "Uservoice": "This UserVoice subdomain is currently available!",
    "Vend": "Looks like you've traveled too far into cyberspace",
    "Webflow": "<!-- Webflow 404 -->",
    "Wishpond": "https://www.wishpond.com/404?campaign=true",
    "Wordpress": "Do you want to register",
    "ZenDesk": "Help Center Closed",
    "feedpress": "The feed has not been found",
    "readme": "Project not found",
    "statuspage": "This page is currently inactive and can only be accessed by account owners.",
    "zendesk": "Help Center Closed",
    "worksites.net": "404 Page Not Found",
    "smugmug": "We're sorry, but the page you requested could not be found."
}

TAKEOVER_URLS = {
    "Acquia": "https://www.acquia.com/",
    "ActiveCampaign": "https://www.activecampaign.com/",
    "Aftership": "https://www.aftership.com/",
    "Aha": "https://www.aha.io/",
    "AWS/S3": "https://aws.amazon.com/s3/",
    "Bigcartel": "https://www.bigcartel.com/",
    "BitBucket": "https://bitbucket.org/",
    "Brightcove": "https://www.brightcove.com/en/",
    "Campaignmonitor": "https://www.campaignmonitor.com/",
    "Cargo": "https://cargo.site/",
    "CloudFront": "https://aws.amazon.com/cloudfront/",
    "Desk": "https://www.desk.com/",
    "Fastly": "https://www.fastly.com/",
    "FeedPress": "https://feed.press/",
    "GetResponse": "https://www.getresponse.com/",
    "Ghost": "https://ghost.org/",
    "Github": "https://pages.github.com/",
    "Helpjuice": "https://www.helpjuice.com/",
    "Helpscout": "https://www.helpscout.com/",
    "Heroku": "https://www.heroku.com/",
    "Intercom": "https://www.intercom.com/",
    "Jetbrains": "https://www.jetbrains.com/youtrack/incloud/",
    "Kajabi": "https://kajabi.com/",
    "Mashery": "https://www.tibco.com/products/cloud-integration/api-management",
    "Pantheon": "https://pantheon.io/",
    "Pingdom": "https://www.pingdom.com/",
    "Proposify": "https://www.proposify.com/",
    "S3Bucket": "https://aws.amazon.com/s3/",
    "Shopify": "https://www.shopify.com/",
    "Simplebooklet": "https://simplebooklet.com/",
    "Smartling": "https://www.smartling.com/",
    "StatuPage": "https://www.statuspage.io/",
    "Surge": "https://surge.sh/",
    "Surveygizmo": "https://www.surveygizmo.com/",
    "Tave": "https://tave.com/",
    "TeamWork": "https://www.teamwork.com/",
    "Thinkific": "https://www.thinkific.com/",
    "Tictail": "https://tictail.com/",
    "Tilda": "https://tilda.cc/",
    "Tumbler": "https://www.tumblr.com/",
    "Unbounce": "https://unbounce.com/",
    "Uservoice": "https://www.uservoice.com/",
    "Vend": "https://www.vendhq.com/",
    "Webflow": "https://webflow.com/dashboard",
    "Wishpond": "https://www.wishpond.com/",
    "Wordpress": "https://wordpress.com/",
    "ZenDesk": "https://www.zendesk.com/",
    "feedpress": "https://feed.press/",
    "readme": "https://readme.com/",
    "statuspage": "https://www.statuspage.io/",
    "zendesk": "https://www.zendesk.com/",
    "worksites.net": "https://www.worksites.net/",
    "smugmug": "https://www.smugmug.com/"
}

COMMON_PORTS_DICT = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    587: "SMTP (TLS)",
    993: "IMAPS",
    995: "POP3S",
    636: "LDAP Secure",
    1723: "PPTP",
    389: "LDAP",
    8008: "HTTP Alternative",
    8080: "HTTP Alternative",
    8081: "HTTP Alternative",
    5900: "VNC"
}

FULL_PORTS_DICT = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    587: "SMTP (TLS)",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    389: "LDAP",
    5900: "VNC",
    8888: "HTTP Alternative",
    1194: "OpenVPN",
    1521: "Oracle SQL Database",
    2222: "SSH Alternative",
    54321: "TCP Wrapper",
    500: "Internet Key Exchange (IKE)",
    8443: "HTTPS Alternative",
    4444: "Metasploit",
    8009: "Apache Tomcat",
    5353: "Multicast DNS (mDNS)",
    5222: "Extensible Messaging and Presence Protocol (XMPP)",
    5800: "VNC Alternative",
    1701: "L2TP",
    22222: "SSH Alternative",
    5901: "VNC Alternative",
    389: "LDAP Secure",
    5000: "UPnP",
    5902: "VNC Alternative",
    8000: "HTTP Alternative",
    123: "NTP",
    1720: "H.323",
    1935: "Adobe Flash Media Server",
    5060: "Session Initiation Protocol (SIP)",
    5903: "VNC Alternative",
    1812: "RADIUS",
    1813: "RADIUS",
    119: "Network News Transfer Protocol (NNTP)",
    139: "NetBIOS",
    1433: "Microsoft SQL Server",
    19350: "Microsoft Skype",
    2404: "IEC 60870-5-104",
    2405: "IEC 60870-5-104",
    3305: "MySQL Alternative",
    3307: "MySQL Alternative",
    3388: "RDP Alternative",
    4321: "Remote Desktop Viewer",
    54322: "TCP Wrapper Alternative",
    5555: "Android Debug Bridge (ADB)",
    5801: "VNC Alternative",
    6000: "X11",
    6666: "IRC Alternative",
    6667: "IRC",
    8008: "HTTP Alternative",
    8080: "HTTP Alternative",
    8081: "HTTP Alternative",
    8447: "DHCPv6",
    8880: "HTTP Alternative",
    9000: "HTTP Alternative",
    9090: "HTTP Alternative",
    9933: "VMware Remote Console",
    102: "ISO Transport Service Access Point (TSAP)",
    1494: "Citrix ICA",
    17089: "Pyongyang RCTV",
    17185: "Vernier Logger Pro",
    27015: "Steam",
    28015: "Rust",
    49152: "Windows Remote Management",
    49153: "Windows Remote Management",
    49154: "Windows Remote Management",
    49155: "Windows Remote Management",
    49156: "Windows Remote Management",
    49157: "Windows Remote Management",
    50000: "SAPRouter",
    514: "Syslog",
    5433: "PostgreSQL Alternative",
    6001: "X11 Alternative",
    8002: "HTTP Alternative",
    8883: "MQTT",
    9418: "Git",
    11211: "Memcached",
    27018: "MongoDB Alternative",
    4000: "SaltStack",
    5672: "Advanced Message Queuing Protocol (AMQP)",
    636: "LDAP Secure",
    9100: "Printer",
    10000: "Webmin",
    2048: "Secure NFS",
    2049: "Network File System (NFS)",
    2375: "Docker",
    54322: "TCP Wrapper Alternative",
    8123: "InfluxDB",
    8800: "HTTP Alternative",
    9091: "HTTP Alternative",
    16010: "HBase",
    1900: "UPnP",
    2087: "cPanel",
    2083: "cPanel",
    222: "Berkeley rshd",
    2379: "etcd",
    2380: "etcd",
    2604: "Zebra",
    27016: "Half-Life",
    32768: "Oracle Secure Backup",
    3310: "Kamailio",
    3659: "OpenView Network Node Manager",
    4848: "GlassFish",
    5001: "Slingbox",
    54323: "TCP Wrapper Alternative",
    5905: "VNC Alternative",
    5984: "CouchDB",
    5985: "Windows Remote Management",
    5986: "Windows Remote Management",
    8005: "Apache Tomcat",
    8069: "OpenERP",
    873: "rsync",
    888: "DDOSIM",
    9415: "Git",
    27015: "SRCDS",
    28960: "Call of Duty",
    50010: "Apache Hadoop",
    50020: "Apache Hadoop",
    50030: "Apache Hadoop",
    54328: "UDP Shell",
    5501: "Hotline",
    5632: "PCAnywhere",
    5802: "VNC Alternative",
    6346: "Gnutella",
    6347: "Gnutella",
    7001: "WebLogic",
    7002: "WebLogic",
    8082: "HTTP Alternative",
    8090: "HTTP Alternative",
    8161: "ActiveMQ",
    8444: "HTTPS Alternative",
    8881: "HTTP Alternative",
    9417: "Git"
}



def parse_arguments():
    parser = argparse.ArgumentParser(description="Find domain takeover vulnerabilities")
    parser.add_argument("-w", "--wordlist", help="Wordlist for subdomain enumeration", required=True)
    parser.add_argument("-d", "--domains", help="Domains (comma-separated) or CSV file", required=True)
    parser.add_argument("-v", "--verbose", help="Enable verbosity to show a detailed output of what is happening.", action="store_true")
    #parser.add_argument("-e", "--email", help="Admin email to send notifications to. Can be used in conjunction with the ")
    parser.add_argument("-ps", "--port-scan", help="Runs port scan on all subdomains that have either a CNAME or an A record. Does not run a port scan on non-resolving hosts. This will take a while, and will increase execution time considerbly. Consider using this with the email feature.", action="store_true")
    
    # Mutually exclusive group for the scan options
    scan_group = parser.add_mutually_exclusive_group(required=True)
    scan_group.add_argument("-s", "--scan", help="Finds subdomains that are live and potentially in use", action="store_true")
    scan_group.add_argument("-id", "--id", help="Enables service identification, does not find vuln subdomains. Does not need choosing if -hj/--vuln is enabled.", action="store_true")
    scan_group.add_argument("-hj", "--vuln", help="Finds subdomains pointing to a CNAME that can be hijacked. Does not identify other subdomains, use -fs for that.", action="store_true")

    scan_group = parser.add_mutually_exclusive_group(required=False)
    scan_group.add_argument("-qs", "--quick-port-scan", help="Quick port scan, of the top 20 most common ports.", action="store_true")
    scan_group.add_argument("-fs", "--full-port-scan", help="Full port scan of the top 100 ports used on web servers. This will take a while. ", action="store_true")


    # Add the remaining arguments
    #parser.add_argument("--email-server", help="SMTP server for sending email notifications")
    #parser.add_argument("--email-port", type=int, help="SMTP server port")
    #parser.add_argument("--email-user", help="SMTP server username")
    #parser.add_argument("--email-password", help="SMTP server password")
    #parser.add_argument("--require-ssl", help="Require SSL for sending email notifications.", action="store_true")
    parser.add_argument("-sc", "--schedule", help="Runs in addition to the --interval argument. You can schedule scans, which will be outputted to the command line. ", action="store_true")
    parser.add_argument("--interval", type=int, help="Scan interval in minutes", default=60)
    args = parser.parse_args()
    return args

def is_valid_subdomain(subdomain):
    if len(subdomain) > 255:
        return False
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in subdomain.split("."))


def load_wordlist(wordlist_file):
    with open(wordlist_file, "r", encoding="ISO-8859-1") as f:
        return [line.strip() for line in f.readlines()]

def get_domains_from_csv(csv_file):
    domains = []
    with open(csv_file, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            domains.append(row[0])
    return domains

def get_http_status(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        return response.status_code
    except requests.exceptions.RequestException:
        return None

# Checks if a subdomain has a CNAME record pointing to a service that can be hijacked
def cname_check(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        for answer in answers:
            cname_value = str(answer.target).lower()

            for service, domain_pattern in SERVICES.items():
                if "*" not in domain_pattern:
                    if domain_pattern.lower() in cname_value:
                        return service, cname_value
                else:
                    # Handles wildcard subdomains
                    domain_parts = domain_pattern.split("*")
                    if len(domain_parts) > 2:
                        continue  # Not a valid wildcard pattern

                    if domain_parts[0] and not cname_value.startswith(domain_parts[0].lower()):
                        continue  # Subdomain does not match the prefix

                    if domain_parts[1] and not cname_value.endswith(domain_parts[1].lower()):
                        continue  # Subdomain does not match the suffix

                    return service, cname_value
    except dns.resolver.NoAnswer:
        return None, None
    except dns.name.LabelTooLong:
        print(f"[WARNING] {subdomain} has a label longer than 63 octets. Skipping this subdomain.")
        return None, None
    except dns.resolver.NXDOMAIN:
        return None, None
    except Exception as e:
        return None, None
    return None, None

# Port scan for the domains - Activated with the -ps argument
def port_scan(subdomain, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((subdomain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            return None, None
    return open_ports

# Checks the A record for a subdomain
def get_a_record(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        for answer in answers:
            return str(answer.address)
    except dns.resolver.NoAnswer:
        return None
    except dns.name.LabelTooLong:
        print(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this domain.")
        return None
    except Exception as e:
        return None

# Checks if the CNAME value is apart of the dictionary of services
def check_cname_exists_in_services(cname_value, services):
    for service in SERVICES.values():
        if service.lower() in cname_value.lower():
            return True
    return False


# checks the status of the service at the end of the CNAME, and then checks if the HTML pattern is apart of the HTML dictionary
def check_service_status(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 404:
            for service, html_pattern in INACTIVE_SERVICE_HTML.items():
                if html_pattern in response.text:
                    return True
    except requests.exceptions.RequestException:
        return False
    return False

# not workin yet, will be updated in the next release.
# def send_email_notification(admin_email, smtp_server, smtp_port, smtp_user, smtp_password, message_body, require_ssl):
#    msg = MIMEMultipart()
#    msg['From'] = smtp_user
#    msg['To'] = admin_email
#    msg['Subject'] = "Domain Takeover Vulnerabilities Report"
#    msg.attach(MIMEText(message_body, 'plain'))
#    if require_ssl:
#        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
#    else:
#        server = smtplib.SMTP(smtp_server, smtp_port)
#        server.starttls()
#    server.login(smtp_user, smtp_password)
#    server.sendmail(smtp_user, admin_email, msg.as_string())
#    server.quit()

def main():
    args = parse_arguments()
    wordlist = load_wordlist(args.wordlist)
    domains = []
    print(colored(f'''
                          _
          .         _____|___
         .      ___/  o o o  \____
         .     /    ---------     |
          .   |     ---------     |
            8-=\__________________|
       _____ __  ______  ____               
      / ___// / / / __ )/ __ \  ____  __  __
      \__ \/ / / / __  / / / / / __ \/ / / /
     ___/ / /_/ / /_/ / /_/ / / /_/ / /_/ / 
    /____/\____/_____/_____(_) .___/\__, /  
                            /_/    /____/  
        ''', "yellow")) 
    print(colored(f'''
   [*] By CyberSec-Angus
   [*] github.com/cybersec-angus
   [*] Starting to find subdomains...
    ''', "green"))
    if args.domains.endswith(".csv"):
        domains = get_domains_from_csv(args.domains)
    else:
        domains = args.domains.split(",")
        print(f"[INFO] Scanning domain(s): {domains}")
    def scan_and_notify():
        # vulnerabilities = []
        for domain in domains:
            main_domain_a_record = get_a_record(domain)
            if args.verbose:
                print(f"[INFO] Main domain A record: {main_domain_a_record}")
            for prefix in wordlist:
                # Creates subdomains based on wordlist
                subdomain = f"{prefix}.{domain}"
                url = f"http://{subdomain}"
                # Checks if the subdomain is valid
                if not is_valid_subdomain(subdomain):
                    continue
                # Outputs the subdomain being attempted if verbose is enabled
                if args.verbose:
                    print(f"[INFO] Trying {subdomain}")
                # Scans ports if enabled, and defines the correct port dictionary to use
                if args.port_scan:
                    if args.quick_port_scan:
                        # Defines the wordlist to scan the common ports, as per the above dictionary
                        open_ports = port_scan(subdomain, COMMON_PORTS_DICT)
                    elif args.full_port_scan:
                        # Defines the wordlist to scan all the common ports and the remaining ports, as per the above FULL_PORTS dictionary
                        open_ports = port_scan(subdomain, FULL_PORTS_DICT)
                    else:
                        # Defines the wordlist to scan all the common ports, as per the above dictionary in the event that the user does not select a port scan type
                        open_ports = port_scan(subdomain, COMMON_PORTS_DICT)

                    open_ports_dict = {port: common_name for port, common_name in COMMON_PORTS_DICT.items() if port in open_ports}
                    # Defines the details of the open ports, and outputs them to the console
                    if open_ports:
                        ports_info = ', '.join([f"{port} ({common_name})" for port, common_name in open_ports_dict.items()])
                        print(colored(f"[PORT SCAN] Open ports on {subdomain}: {ports_info}", "green"))
                # Defines status code
                status_code = get_http_status(url)
                # Prints the subdomain found with status code if verbose is enabled - The A record or CNAME value is printed separately depending on the scan type
                if args.verbose and status_code == 200:
                    print(f"[INFO] Found {subdomain} with status code: {status_code}")
                elif args.verbose and status_code != 200:
                    print(f"[INFO] Attempted {subdomain} | Returned status code: {status_code}")
                # Checks the A records, and the CNAME records of the subdomains and defines them
                subdomain_a_record = get_a_record(subdomain)
                service, cname_value = cname_check(subdomain)
                # Runs basic scan with no service ID and no takeover functionality, just outputs the subdomain and the A record/CNAME value
                # All scan types enumerate domains based on word lists
                if args.scan:
                    if cname_value == domain and status_code == 200:
                        print(colored(f"[SUBDOMAIN] Subdomain [{subdomain}] CNAME is the main domain: {main_domain_a_record} | Status code: {status_code}", "cyan"))
                    elif cname_value == domain and status_code != 200:
                        print(colored(f"[POTENTIAL] Subdomain [{subdomain}] CNAME is the main domain: {main_domain_a_record} | Status code: {status_code}", "yellow"))
                    elif cname_value is not None and status_code == 200:
                        print(colored(f"[SUBDOMAIN] Found subdomain {subdomain} with CNAME record {cname_value}", "green"))
                    elif subdomain_a_record == main_domain_a_record and status_code == 200:
                        print(colored(f"[SUBDOMAIN] Subdomain [{subdomain}] A record is the same as main domain: {main_domain_a_record} | Status code: {status_code}", "cyan"))
                    elif subdomain_a_record == main_domain_a_record and status_code != 200:
                        print(colored(f"[POTENTIAL] Subdomain [{subdomain}] A record is the same as main domain: {main_domain_a_record} | Status code: {status_code}", "yellow"))
                    elif subdomain_a_record is not None and status_code == 200:
                        print(colored(f"[SUBDOMAIN] Found subdomain {subdomain} with A record: {subdomain_a_record}", "green"))
                    elif cname_value is not None and status_code != 200:
                        print(colored(f"[POTENTIAL] Subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}", "yellow"))
                    elif subdomain_a_record is not None and status_code != 200:
                        print(colored(f"[POTENTIAL] {subdomain} responded with A record: {subdomain_a_record} | Status code: {status_code}", "yellow"))
                # Runs scan with service ID, outputs the subdomain and the A record/CNAME value but does not find takeover vulns
                if args.id:
                    if service:
                        if check_cname_exists_in_services(url):
                            print(colored(f"[SERVICE FOUND] {subdomain} pointing to {service} | Response code: {status_code}", "green"))
                        elif cname_value == domain:
                            print(colored(f"[POTENTIAL] {subdomain} pointing to the main domain {domain} | Response code: {status_code}", "yellow"))
                        elif cname_value is not None and status_code != 200:
                            if not check_cname_exists_in_services(cname_value, SERVICES):
                                print(colored(f"[POTENTIAL] {subdomain} pointing to {service} with CNAME: {cname_value}", "yellow"))
                            if check_cname_exists_in_services(cname_value, SERVICES):
                                print(colored(f"[POTENTIAL] {subdomain} pointing to unknown service with CNAME: {cname_value}", "yellow"))
                        elif subdomain_a_record is not None and status_code == 200:
                            print(colored(f"[SUBDOMAIN] Found subdomain {subdomain} with A record: {subdomain_a_record}", "green"))
                        elif cname_value is not None and status_code != 200:
                            print(colored(f"[POTENTIAL] Subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}", "yellow"))
                        elif subdomain_a_record is not None and status_code != 200:
                            print(colored(f"[POTENTIAL] {subdomain} responded with A record: {subdomain_a_record} | Status code: {status_code}", "yellow"))                        
                    else:
                        if subdomain_a_record == main_domain_a_record:
                            print(colored(f"[POTENTIAL] Subdomain [{subdomain}] A record is the same as main domain: {main_domain_a_record} | Response code: {status_code}", "yellow"))
                        elif cname_value is not None:
                            print(colored(f"[NON RESOLVE] Subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}", "red"))
                        elif subdomain_a_record is not None:
                            print(colored(f"[NON RESOLVE] {subdomain} responded with A record: {subdomain_a_record} | Status code: {status_code}", "red"))
                        else:
                            print(colored(f"[ERROR] {subdomain} returned a status code of: {status_code}.", "red"))
                # Does it all, finds the service ID, finds the takeover vulns and outputs the subdomain and the A record/CNAME value to the console
                if args.vuln:
                    if service:
                        if check_service_status(url):
                            takeover_url = TAKEOVER_URLS.get(service, "")
                            print(colored(f"[VULNERABLE] {subdomain} pointing to {service} with CNAME: {cname_value} Click here to takeover this subdomain: {takeover_url} | Status code: {status_code}", "green"))
                        elif cname_value == domain:
                            print(colored(f"[POTENTIAL] {subdomain} pointing to the main domain {domain}.", "yellow"))
                        elif cname_value is not None and status_code != 200:
                            if not check_cname_exists_in_services(cname_value, SERVICES):
                                print(colored(f"[POTENTIAL] {subdomain} pointing to {service} with a non-resolving CNAME of: {cname_value} | Status code: {status_code}", "yellow"))
                            else:
                                print(colored(f"[POTENTIAL] Subdomain {subdomain} is pointing to an unknown service with CNAME: {cname_value} | Status code: {status_code}", "yellow"))
                        elif cname_value is not None and status_code == None:
                            if not check_cname_exists_in_services(cname_value, SERVICES):
                                print(colored(f"[POTENTIAL] {subdomain} pointing to {service} with a non-resolving CNAME. | Status code: {status_code}", "yellow"))
                            else:
                                print(colored(f"[POTENTIAL] Subdomain {subdomain} is pointing to an unknown service with CNAME: {cname_value} | Status code: {status_code}", "yellow"))
                        elif subdomain_a_record == main_domain_a_record and status_code == 200:
                            print(colored(f"[SUBDOMAIN FOUND] Subdomain found {subdomain} has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code}", "green"))
                        elif subdomain_a_record == main_domain_a_record and status_code == 404:
                            print(colored(f"[POTENTIAL] Subdomain found {subdomain} has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code}", "red"))
                        elif subdomain_a_record == main_domain_a_record and status_code != 200:
                            print(colored(f"[POTENTIAL] Subdomain found {subdomain} has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code}", "red"))
                        elif subdomain_a_record != main_domain_a_record and status_code != 200:
                            print(colored(f"[POTENTIAL] Subdomain has the same A name record as {domain} but responded with status code: {status_code} | A name record: {subdomain_a_record}", "cyan"))
                    else:
                        if subdomain_a_record == main_domain_a_record and status_code == 200:
                            print(colored(f"[POTENTIAL] Subdomain has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code} ", "cyan"))
                        elif subdomain_a_record == main_domain_a_record and status_code != 200:
                            print(colored(f"[POTENTIAL] Subdomain has the same A name record as {domain} but responded with status code: {status_code} | A name record: {subdomain_a_record}", "cyan"))
                        else:
                            print(colored(f"[ERROR] {subdomain} returned a status code of {status_code}.", "red"))
            #if vulnerabilities and args.email:
            #   message_body = "Domain Takeover Vulnerabilities Found:\n\n" + "\n".join(vulnerabilities)
            #   send_email_notification(args.email, args.email_server, args.email_port, args.email_user, args.email_password, message_body, args.require_ssl)
            # Schedule feature to re-run the script after a set interval
            if args.schedule:
                interval = args.interval
                print(f"[INFO] Starting script again after interval {interval}")
                if args.interval:
                    time.sleep(args.interval * 60)
                    interval = args.interval
                    print(f"[INFO] Starting script again now")
                else:
                    print(f"[EXITING] No schedule set or an error occured")
                    sys.exit(0)
            else:
                print(colored(f"[EXITING1] Scan complete | Exiting SUBD.py | See output above for results", "green"))
                sys.exit(0)
        #if vulnerabilities and args.email:
        #        message_body = "Domain Takeover Vulnerabilities Found:\n\n" + "\n".join(vulnerabilities)
        #        send_email_notification(args.email, args.email_server, args.email_port, args.email_user, args.email_password, message_body, args.require_ssl)

        if args.schedule:
                if args.interval:
                    time.sleep(args.interval * 60)
                    scan_and_notify()
                else:
                    print(f"[EXITING] No schedule set or an error occured")
                    sys.exit(0)
        else:
            print(colored(f"[EXITING] Scan complete | Exiting SUBD.py | See output above for results", "green"))
            sys.exit(0)
        sys.exit(0)
    scan_and_notify()

if __name__ == "__main__":
    main()
