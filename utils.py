import socket
import requests
import dns.resolver
import re
import csv
import os
import datetime
from termcolor import colored
from dictionaries.services import SERVICES
from dictionaries.mail_services import MAIL_SERVICES
from dictionaries.inactive_services import INACTIVE_SERVICE_HTML

error_log = []

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
        print(colored(f"[WARNING] {subdomain} has a label longer than 63 octets. Skipping this domain.", "light_red"))
        error_log.append(f"[WARNING] {subdomain} has a label longer than 63 octets. Skipping this subdomain.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None, None
    except dns.resolver.NXDOMAIN:
        error_log.append(f"[WARNING] {subdomain} does not exist. Skipping this subdomain.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None, None
    except dns.resolver.NoResolverConfiguration:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING", "light_red"))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()   
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        error_log.append(f"[ERROR] Unhandled error: {e}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
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
        error_log.append(f"[WARNING] {subdomain} does not exist. Skipping this subdomain.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None
    except dns.resolver.NoNameservers:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING "))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING ")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit(0)
    except dns.name.LabelTooLong:
        print(f"[WARNING] {subdomain} has a label longer than 63 octets. Skipping this domain.")
        error_log.append(f"[WARNING] {subdomain} has a label longer than 63 octets. Skipping this subdomain.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None
    except dns.resolver.NoResolverConfiguration:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING", "light_red"))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()   
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e}", "light_red"))
        error_log.append(f"[ERROR] Unhandled error: {e}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
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
        except socket.gaierror:
            error_log.append(f"[PORT SCAN ERROR] Unable to resolve domain: {subdomain}")
            if error_log:
                    with open("error_log.txt", "w") as file:
                        for error in error_log:
                            file.write(error + "\n")
        except socket.error as e:
            print(colored(f"[PORT SCAN ERROR] Unhandled socket error: {e} | Continuing", "light_red"))
            error_log.append(f"[PORT SCAN ERROR] Unhandled socket error: {e}")
            if error_log:
                with open("error_log.txt", "w") as file:
                    for error in error_log:
                        file.write(error + "\n")
            pass
        except Exception as e:
            print(colored(f"[PORT SCAN ERROR] Unhandled error: {e} | Continuing", "light_red"))
            error_log.append(f"[PORT SCAN ERROR] Unhandled error: {e}")
            if error_log:
                with open ("error_log.txt", "a") as file:
                    for error in error_log:
                        file.write(error + "\n")
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
            return None, mx_value    
    except dns.resolver.NoAnswer:
        return None, None
    except dns.name.LabelTooLong:
        print(colored(f"[WARNING] {subdomain} has a label longer than 63 octets. Skipping this domain.", "light_red"))
        error_log.append(f"[WARNING] {subdomain} has a label longer than 63 octets. Skipping this subdomain.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None, None
    except dns.resolver.NXDOMAIN:
        error_log.append(f"[WARNING] {subdomain} does not exist. Skipping this subdomain.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None, None
    except dns.resolver.NoNameservers:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING "))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING ")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit(0)
    except dns.resolver.NoResolverConfiguration:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING", "light_red"))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()    
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        error_log.append(f"[ERROR] Unhandled error: {e}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
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
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        error_log.append(f"[ERROR] Unhandled error: {e}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
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
            error_log.append(f"[PORT SCAN ERROR] Unhandled socket error: {e}")
            if error_log:
                with open("error_log.txt", "w") as file:
                    for error in error_log:
                        file.write(error + "\n")
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
            return None, mx_value
    except dns.resolver.NoAnswer:
        print(colored(f"[WARNING] No answer for {domain}", "light_red"))
        error_log.append(f"[WARNING] No answer for {domain}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None, None
    except dns.resolver.NoNameservers:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING", "light_red"))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()
    except dns.resolver.NoResolverConfiguration:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING", "light_red"))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()
    except dns.name.LabelTooLong:
        print(colored(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this subdomain.", "light_red"))
        error_log.append(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this subdomain.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None, None
    except dns.resolver.NXDOMAIN:
        error_log.append(f"[WARNING] NXDOMAIN for {domain}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None, None
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        error_log.append(f"[ERROR] Unhandled error: {e}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
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
        error_log.append(f"[WARNING] NXDOMAIN for {domain}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return False
    except dns.name.LabelTooLong:
        print(f"[WARNING] {domain} has a label longer than 63 octets. Skipping.")
        error_log.append(f"[WARNING] {domain} has a label longer than 63 octets. Skipping.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return False
    except dns.resolver.NoNameservers:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING "))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING ")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit(0)
    except dns.resolver.NoResolverConfiguration:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING", "light_red"))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        error_log.append(f"[ERROR] Unhandled error: {e}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
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
        error_log.append(f"[WARNING] {domain} Does NOT exist | EXITING.")
        print(colored(f"[WARNING] {domain} Does NOT exist | EXITING.", "light_red"))
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()
    except dns.resolver.NoAnswer:
        print (f"[WARNING] No A record found for {domain}.")
        error_log.append(f"[WARNING] No A record found for {domain}.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None
    except dns.name.LabelTooLong:
        print(colored(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this domain.", "light_red"))
        error_log.append(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this domain.")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None
    except dns.resolver.NoNameservers:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING "))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING ")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()
    except dns.resolver.NoResolverConfiguration:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING", "light_red"))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        error_log.append(f"[ERROR] Unhandled error: {e}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
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
        error_log.append(f"[WARNING] NXDOMAIN for {domain}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None
    except dns.name.LabelTooLong:
        print(colored(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this domain.", "light_red"))
        error_log.append(f"[WARNING] {domain} has a label longer than 63 octets. Skipping this domain.")    
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None
    except dns.resolver.NoNameservers:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING "))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING ")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()
    except dns.resolver.NoResolverConfiguration:
        print(colored(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING", "light_red"))
        error_log.append(f"[ERROR] No Nameservers available | Check internet connectivity | EXITING")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        exit()
    except Exception as e:
        print(colored(f"[ERROR] Unhandled error: {e} | Continuing", "light_red"))
        error_log.append(f"[ERROR] Unhandled error: {e}")
        if error_log:
            today = datetime.date.today()
            with open(f"error_log {today.strftime('%d-%m-%y')}.txt", "w") as file:
                for error in error_log:
                    file.write(error + "\n")
        return None
