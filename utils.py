import socket
import requests
import dns.resolver
import re
import csv
import os
from termcolor import colored
from dictionaries.services import SERVICES
from dictionaries.mail_services import MAIL_SERVICES
from dictionaries.inactive_services import INACTIVE_SERVICE_HTML

#validates the subdomain max length is less than 255 characters in length. As per the maximum length DNS supports. 
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
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        return None, None
    return None, None

# Checks the A record for the domain
def get_a_record(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, "A")
        for answer in answers:
            return str(answer.address)
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except dns.name.LabelTooLong:
        print(f"[WARNING] {subdomain} has a label longer than 63 octets. Skipping this domain.")
        return None
    except Exception as e:

        return None

# Port scan for subbdomains - Activated with the -ps argument
def port_scan(subdomain, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((subdomain, port))
            if result == 0:
                open_ports.append(port)
            else:
                pass
            sock.close()
        except socket.error as e:
            print(colored(f"[PORT SCAN ERROR] Unhandled socket error: {e} | Continuing", "light_red"))
            pass
    return open_ports

# Checks if the CNAME value is apart of the dictionary of services
def check_cname_exists_in_services(cname_value, services):
    for service in SERVICES.values():
        if service.lower() in cname_value.lower():
            return True
    return False


def mx_check(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, "MX")
        for answer in answers:
            mx_value = str(answer.exchange).lower()
            for service, domain_pattern in MAIL_SERVICES.items():
                if "*" not in domain_pattern:
                    if domain_pattern.lower() in mx_value:
                        return service, mx_value
                else:
                    # Handles wildcard subdomains
                    domain_parts = domain_pattern.split("*")
                    if len(domain_parts) > 2:
                        continue  # Not a valid wildcard pattern
                    if domain_parts[0] and not mx_value.startswith(domain_parts[0].lower()):
                        continue  # Subdomain does not match the prefix
                    if domain_parts[1] and not mx_value.endswith(domain_parts[1].lower()):
                        continue  # Subdomain does not match the suffix
                    return service, mx_value
    except dns.resolver.NoAnswer:
        return None, None
    except dns.name.LabelTooLong:
        print(f"[WARNING] {subdomain} has a label longer than 63 octets. Skipping this subdomain.")
        return None, None
    except dns.resolver.NXDOMAIN:
        return None, None
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        return None, None
    return None, None

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

def port_scan_domain(domain, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
            else:
                pass
            sock.close()
        except socket.error as e:
            print(colored(f"[PORT SCAN ERROR] Unhandled socket error: {e} | Continuing", "light_red"))
            pass
    return open_ports

def mx_check_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        for answer in answers:
            mx_value = str(answer.exchange).lower()

            for service, domain_pattern in MAIL_SERVICES.items():
                if "*" not in domain_pattern:
                    if domain_pattern.lower() in mx_value:
                        return service, mx_value
                else:
                    # Handles wildcard subdomains
                    domain_parts = domain_pattern.split("*")
                    if len(domain_parts) > 2:
                        continue  # Not a valid wildcard pattern
                    if domain_parts[0] and not mx_value.startswith(domain_parts[0].lower()):
                        continue  # Subdomain does not match the prefix
                    if domain_parts[1] and not mx_value.endswith(domain_parts[1].lower()):
                        continue  # Subdomain does not match the suffix
                    return service, mx_value
    except dns.resolver.NoAnswer:
        return None, None
    except dns.name.LabelTooLong:
        print(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this subdomain.")
        return None, None
    except dns.resolver.NXDOMAIN:
        return None, None
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        return None, None
    return None, None


mx_record_domain = None

def mx_record_check_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        if len(answers) > 0:
            return answers[0]
        else:
            return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.name.LabelTooLong:
        print(f"[WARNING] {domain} has a label longer than 63 octets. Skipping.")
        return False
    except:
        return False
    
# Checks the A record for the domain
def get_a_record_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        for answer in answers:
            return str(answer.address)
    except dns.resolver.NXDOMAIN:
        print (colored(f"[WARNING] {domain} Does NOT exist | EXITING.", 'light_red'))
        exit(0)
    except dns.resolver.NoAnswer:
        print (f"[WARNING] No A record found for {domain}.")
        return None
    except dns.name.LabelTooLong:
        print(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this domain.")
        return None
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        return None

# Checks the CNAME value of the main domain. This is used for the output of when the script is launched.
def get_cname_record_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for answer in answers:
            return str(answer.address)
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except dns.name.LabelTooLong:
        print(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this domain.")
        return None
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        return None
