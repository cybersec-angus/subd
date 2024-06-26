import time
import datetime
import sys
from termcolor import colored
from dictionaries.takeover_urls import TAKEOVER_URLS
from dictionaries.common_ports import COMMON_PORTS_DICT
from dictionaries.extended_ports import FULL_PORTS_DICT
from dictionaries.custom_ports import CUSTOM_PORTS_DICT
from dictionaries.all_ports import ALL_PORTS_DICT
from dictionaries.mail_services import MAIL_SERVICES
from dictionaries.services   import SERVICES
from utils import mx_check_domain, get_domains_from_csv, mx_check, get_cname_record_domain, port_scan, get_a_record, load_wordlist, is_valid_subdomain, get_http_status, cname_check, check_cname_exists_in_services, check_service_status, get_a_record_domain, port_scan_domain
from parse_args import parse_arguments
from send_email import send_email

def main():
    outputs = []
    error_log = []
    domains = []
    try:
        args = parse_arguments()
        wordlist = load_wordlist(args.wordlist)
    except FileNotFoundError:
        print(colored(f"[ERROR] Wordlist file {args.wordlist} does not exist | EXITING", "light_red"))
        error_log.append(f"[ERROR] Wordlist file {args.wordlist} does not exist")
        exit(0)
    
    print(colored(f'''
                  
                          _
                         |
          .         _____|___
         .      ___/  o o o  \_____
         .     /    ---------      |
          .   |     ---------      |
            8-=\__________________/
        ''', "light_yellow")) 
    print(colored(f'''
       _____ __  ______  ____               
      / ___// / / / __ )/ __ \  ____  __  __
      \__ \/ / / / __  / / / / / __ \/ / / /
     ___/ / /_/ / /_/ / /_/ / / /_/ / /_/ / 
    /____/\____/_____/_____(_) .___/\__, /  
                            /_/    /____/  
        ''', "light_cyan")) 
    print(colored(f'''
   [*] By CyberSec-Angus
   [*] github.com/cybersec-angus
   [*] Version 3.0.0
        ''', "light_green"))
    print(colored(f'''
   [*] Starting my Submarine
   [*] initiating periscope
   [*] All systems go
   [*] Starting to find subdomains...         
    ''', "light_blue")) 
    if args.domains.endswith(".csv"):
        try:
            domains = get_domains_from_csv(args.domains)
        except FileNotFoundError:
            print(colored(f"[ERROR] CSV file {args.domains} does not exist | EXITING", "light_red"))
            error_log.append(f"[ERROR] CSV file {args.domains} does not exist")
            if error_log:
                with open("error_log.txt", "w") as file:
                    for error in error_log:
                        file.write(error + "\n")   
            exit(0)
    else:
        domains = args.domains.split(",")
        if len(domains) > 1:   
            print(colored(f"[INFO] Scanning domains: {domains}", "light_magenta"))
            outputs.append(f"The following domains have been scanned using Subd.py: {domains}")
        else:
            print(colored(f"[INFO] Scanning domain: {domains}", "light_magenta"))
    def scan_and_notify():
        
        # vulnerabilities = []
        for domain in domains:
            try:
                main_domain_a_record = get_a_record_domain(domain)
                main_domain_cname = get_cname_record_domain(domain)
                service, mx_value = mx_check_domain(domain)
                print(colored(f"[INFO] Now scanning domain: {domain}", "light_magenta"))
                outputs.append(f"[INFO] Below is the report for: {domain}")
                print(colored(f"[INFO] A record for ({domain}): {main_domain_a_record}",  "light_magenta"))
                outputs.append(f"[INFO] A record for ({domain}): {main_domain_a_record}")
                print(colored(f"[INFO] CNAME record for: ({domain}): {main_domain_cname}",  "light_magenta"))
                outputs.append(f"[INFO] CNAME record for: ({domain}): {main_domain_cname}")
            except Exception as e:
                print(colored(f"[ERROR] {e}", "light_red"))
                outputs.append(f"[ERROR] {e}")
                error_log.append(f"[ERROR] {e}")
                if error_log:
                    with open("error_log.txt", "w") as file:
                        for error in error_log:
                            file.write(error + "\n")
                continue
            if args.mail_id:
                try:
                    if mx_value == None:
                        if args.verbose:
                            print(colored(f"[MAIL] No MX record found for {domain}", "light_yellow"))
                            outputs.append(f"[MAIL] No MX record found for {subdomain}")
                        else:
                            continue                    
                    elif service != None:
                        print(colored(f"[MAIL] MX record found for: {domain} | MX Value: {mx_value} | Mail provider: {service}", "light_green"))
                        outputs.append(f"[MAIL] MX record found: {mx_value} | Mail provider: {service}")                    
                    elif mx_value != None:
                       print(colored(f"[MAIL] MX record found for: {domain} | MX Value: {mx_value} | Unable to identify mail provider", "light_cyan"))
                       outputs.append(f"[MAIL] MX record found: {mx_value} | Unable to identify mail provider")
                    else:
                       if args.verbose:
                            print(colored(f"[MAIL] No MX record found for {domain}", "light_yellow"))
                       outputs.append(f"[MAIL] No MX record found for {subdomain}")
                except Exception as e:
                    print(colored(f"[MAIL ERROR DOMAIN] Unable to scan for mail provider on {domain} | The mail ID function outputted an unhandled error: {e}", "light_red"))
                    outputs.append(f"[MAIL ERROR] Unable to scan for mail provider on {domain} | The mail ID function outputted an unhandled error: {e}")
                    error_log.append(f"[MAIL ERROR] Unable to scan for mail provider on {domain} | The mail ID function outputted an unhandled error: {e}")
                    if error_log:
                        with open("error_log.txt", "w") as file:
                            for error in error_log:
                                file.write(error + "\n")
                    continue
            if args.port_scan:
                    try:
                        if args.quick_port_scan:
                            # Defines the wordlist to scan the common ports, as per the above dictionary
                            open_ports = port_scan_domain(domain, COMMON_PORTS_DICT)
                            PORTS_DICT = COMMON_PORTS_DICT
                        elif args.extended_port_scan:
                            # Defines the wordlist to scan all the common ports and the remaining ports, as per the above FULL_PORTS dictionary
                            open_ports = port_scan_domain(domain, FULL_PORTS_DICT)
                            PORTS_DICT = FULL_PORTS_DICT
                        elif args.custom_port_scan:
                            # Defines the wordlist to scan all the common ports and the remaining ports, as per the above FULL_PORTS dictionary
                            open_ports = port_scan_domain(domain, CUSTOM_PORTS_DICT)
                            PORTS_DICT = CUSTOM_PORTS_DICT
                        elif args.all_ports_scan:
                            # Defines the wordlist to scan all the common ports and the remaining ports, as per the above FULL_PORTS dictionary
                            open_ports = port_scan_domain(domain, ALL_PORTS_DICT)
                            PORTS_DICT = ALL_PORTS_DICT
                        else:
                            # Defines the wordlist to scan all the common ports, as per the above dictionary in the event that the user does not select a port scan type
                            open_ports = port_scan_domain(domain, COMMON_PORTS_DICT)
                            PORTS_DICT = COMMON_PORTS_DICT
                        open_ports_dict = {port: common_name for port, common_name in PORTS_DICT.items() if port in open_ports}
                        # Defines the details of the open ports, and outputs them to the console
                        if open_ports:
                            ports_info = ', '.join([f"{port} ({common_name})" for port, common_name in open_ports_dict.items()])
                            print(colored(f"[PORT SCAN] Open ports on {domain}: {ports_info}", "light_green"))
                            outputs.append(f"[PORT SCAN] Open ports on {domain}: {ports_info}")
                        else:
                            if args.verbose:
                                print(colored(f"[PORT SCAN INFO] No open ports on {domain} | This indicates the ports are closed, or our port-scanning attempts have been blocked", "light_magenta"))
                                outputs.append(f"[PORT SCAN INFO] No open ports on {domain} | This indicates the ports are closed, or our port-scanning attempts have been blocked")
                    except Exception as e:
                        print(colored(f"[PORT SCAN ERROR] Unable to scan ports on {domain} | The port scan function outputted an unhandled error: {e}", "light_red"))
                        outputs.append(f"[PORT SCAN ERROR] Unable to scan ports on {domain} | The port scan function outputted an unhandled error: {e}")
                        error_log.append(f"[PORT SCAN ERROR] Unable to scan ports on {domain} | The port scan function outputted an unhandled error: {e}")
                        if error_log:
                            with open("error_log.txt", "w") as file:
                                for error in error_log:
                                    file.write(error + "\n")
                        continue
            for prefix in wordlist:
                try:
                    # Creates subdomains based on wordlist
                    subdomain = f"{prefix}.{domain}"
                    url = f"http://{subdomain}"
                    # Checks if the subdomain is valid
                    if not is_valid_subdomain(subdomain):
                        continue
                    # Outputs the subdomain being attempted if verbose is enabled
                    if args.verbose:
                        print(colored(f"[INFO] Trying {subdomain}", "light_magenta"))
                    if args.mail_id:
                        try:
                            service, mx_value = mx_check(subdomain)
                            if mx_value == None:
                                if args.verbose:
                                    print(colored(f"[MAIL] No MX record found for {subdomain}", "light_yellow"))
                                    outputs.append(f"[MAIL] No MX record found for {subdomain}")
                                    continue
                            elif service != None:
                                print(colored(f"[MAIL] MX record found for subdomain: {subdomain} | MX Value: {mx_value} | Mail provider: {service}", "light_green"))
                                outputs.append(f"[MAIL] MX record found for subdomain: {subdomain} | MX Value: {mx_value} | Mail provider: {service}")
                            elif mx_value != False:
                                    print(colored(f"[MAIL] MX record found for subdomain: {subdomain} | MX Value: {mx_value} | Unable to identify mail provider", "light_cyan"))
                                    outputs.append(f"[MAIL] MX record found for subdomain: {subdomain} | MX Value: {mx_value} | Unable to identify mail provider")
                            else:
                                if args.verbose:
                                    print(colored(f"[MAIL] No MX record found for {subdomain}", "light_yellow"))
                                    outputs.append(f"[MAIL] No MX record found for {subdomain}")
                                    continue
                        except Exception as e:
                            print(colored(f"[MAIL ERROR] Unable to check MX record for {subdomain} | The MX record check function outputted an unhandled error: {e}", "light_red"))
                            outputs.append(f"[MAIL ERROR] Unable to check MX record for {subdomain} | The MX record check function outputted an unhandled error: {e}")
                            error_log.append(f"[MAIL ERROR] Unable to check MX record for {subdomain} | The MX record check function outputted an unhandled error: {e}")
                            if error_log:
                                with open("error_log.txt", "w") as file:
                                    for error in error_log:
                                        file.write(error + "\n")    
                    if args.port_scan:
                        try:
                            if args.quick_port_scan:
                                # Defines the wordlist to scan the common ports, as per the above dictionary
                                open_ports = port_scan(subdomain, COMMON_PORTS_DICT)
                                PORTS_DICT = COMMON_PORTS_DICT
                            elif args.extended_port_scan:
                                # Defines the wordlist to scan all the common ports and the remaining ports, as per the above FULL_PORTS dictionary
                                open_ports = port_scan(subdomain, FULL_PORTS_DICT)
                                PORTS_DICT = FULL_PORTS_DICT
                            elif args.custom_port_scan:
                                # Defines the wordlist to scan all the common ports and the remaining ports, as per the above FULL_PORTS dictionary
                                open_ports = port_scan(subdomain, CUSTOM_PORTS_DICT)
                                PORTS_DICT = CUSTOM_PORTS_DICT
                            elif args.all_ports_scan:
                                # Defines the wordlist to scan all the common ports and the remaining ports, as per the above FULL_PORTS dictionary
                                open_ports = port_scan(subdomain, ALL_PORTS_DICT)
                                PORTS_DICT = ALL_PORTS_DICT
                            else:
                                # Defines the wordlist to scan all the common ports, as per the above dictionary in the event that the user does not select a port scan type
                                open_ports = port_scan(subdomain, COMMON_PORTS_DICT)
                                PORTS_DICT = COMMON_PORTS_DICT
                            open_ports_dict = {port: common_name for port, common_name in PORTS_DICT.items() if port in open_ports}
                            # Defines the details of the open ports, and outputs them to the console
                            if open_ports:
                                ports_info = ', '.join([f"{port} ({common_name})" for port, common_name in open_ports_dict.items()])
                                print(colored(f"[PORT SCAN] Open ports on {subdomain}: {ports_info}", "light_green"))
                                outputs.append(f"[PORT SCAN] Open ports on {subdomain}: {ports_info}")
                            else:
                                if args.verbose:
                                    print(colored(f"[PORT SCAN] No open ports on {subdomain} | This indicates the ports are closed, or our port-scanning attempts have been blocked", "light_magenta"))
                                    outputs.append(f"[PORT SCAN INFO] No open ports on {subdomain} | This indicates the ports are closed, or our port-scanning attempts have been blocked")
                        except Exception as e:
                            print(colored(f"[PORT SCAN ERROR] Unable to scan ports on {subdomain} | The port scan function outputted an unhandled error: {e}", "light_red"))
                            outputs.append(f"[PORT SCAN ERROR] Unable to scan ports on {subdomain} | The port scan function outputted an unhandled error: {e}")
                            error_log.append(f"[PORT SCAN ERROR] Unable to scan ports on {subdomain} | The port scan function outputted an unhandled error: {e}")
                            if error_log:
                                with open("error_log.txt", "w") as file:
                                    for error in error_log:
                                        file.write(error + "\n")
                    # Defines status code
                    status_code = get_http_status(url)
                    # Prints the subdomain found with status code if verbose is enabled - The A record or CNAME value is printed separately depending on the scan type
                    if args.verbose and status_code == 200:
                        print(colored(f"[INFO] Found {subdomain} with status code: {status_code}", "light_magenta"))
                        outputs.append(f"[INFO] Found {subdomain} with status code: {status_code}")
                    elif args.verbose and status_code != 200:
                        print(colored(f"[INFO] Attempted a HTTP(S) connection to {subdomain} | Returned status code: {status_code} | This does not always mean the subdomain is invalid.", "light_magenta"))
                        outputs.append(f"[INFO] Attempted a HTTP(S) connection to {subdomain} | Returned status code: {status_code} | This does not always mean the subdomain is invalid.")
                    # Checks the A records, and the CNAME records of the subdomains and defines them
                    subdomain_a_record = get_a_record(subdomain)
                    service, cname_value = cname_check(subdomain)
                    # Runs basic scan with no service ID and no takeover functionality, just outputs the subdomain and the A record/CNAME value
                    # All scan types enumerate domains based on word lists
                    if args.scan:
                        try:
                            if cname_value == domain and status_code == 200:
                                if args.ignore_same:
                                    continue
                                else:
                                    print(colored(f"[SUBDOMAIN] Subdomain [{subdomain}] CNAME is the main domain: {main_domain_a_record} | Status code: {status_code}", "cyan"))
                                    outputs.append(f"[SUBDOMAIN] Subdomain [{subdomain}] CNAME is the main domain: {main_domain_a_record} | Status code: {status_code}")
                            elif cname_value == domain and status_code != 200:
                                if args.ignore_same:
                                    continue
                                else:
                                    print(colored(f"[POTENTIAL] Subdomain [{subdomain}] CNAME is the main domain: {main_domain_a_record} | Status code: {status_code}", "light_cyan"))
                                    outputs.append(f"[POTENTIAL] Subdomain [{subdomain}] CNAME is the main domain: {main_domain_a_record} | Status code: {status_code}")
                            elif cname_value is not None and status_code == 200:
                                print(colored(f"[SUBDOMAIN] Found subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}", "light_green"))
                                outputs.append(f"[SUBDOMAIN] Found subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}")
                            elif subdomain_a_record == main_domain_a_record and status_code == 200:
                                if args.ignore_same:
                                    continue
                                else:
                                    print(colored(f"[SUBDOMAIN] Subdomain [{subdomain}] A record is the same as main domain: {main_domain_a_record} | Status code: {status_code}", "cyan"))
                                    outputs.append(f"[SUBDOMAIN] Subdomain [{subdomain}] A record is the same as main domain: {main_domain_a_record} | Status code: {status_code}")
                            elif subdomain_a_record == main_domain_a_record and status_code != 200:
                                if args.ignore_same:
                                    continue
                                else:
                                    print(colored(f"[POTENTIAL] Subdomain [{subdomain}] A record is the same as main domain: {main_domain_a_record} | Status code: {status_code}", "light_cyan"))
                                    outputs.append(f"[POTENTIAL] Subdomain [{subdomain}] A record is the same as main domain: {main_domain_a_record} | Status code: {status_code}")
                            elif subdomain_a_record is not None and status_code == 200:
                                print(colored(f"[SUBDOMAIN] Found subdomain {subdomain} with A record: {subdomain_a_record} | Status code: {status_code}", "light_green"))
                                outputs.append(f"[SUBDOMAIN] Found subdomain {subdomain} with A record: {subdomain_a_record} | Status code: {status_code}")
                            elif cname_value is not None and status_code != 200:
                                print(colored(f"[POTENTIAL] Subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}", "light_cyan"))
                                outputs.append(f"[POTENTIAL] Subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}")
                            elif subdomain_a_record is not None and status_code != 200:
                                print(colored(f"[POTENTIAL] {subdomain} responded with A record: {subdomain_a_record} | Status code: {status_code}", "light_cyan"))
                                outputs.append(f"[POTENTIAL] {subdomain} responded with A record: {subdomain_a_record} | Status code: {status_code}")
                        except Exception as e:
                            print(colored(f"[ERROR] {e}", "light_red"))
                            outputs.append(f"[ERROR] {e}")
                            error_log.append(f"[ERROR] {e}")
                            if error_log:
                                with open("error_log.txt", "w") as file:
                                    for error in error_log:
                                        file.write(error + "\n")
                    # Runs scan with service ID, outputs the subdomain and the A record/CNAME value but does not find takeover vulns
                    if args.id:
                        try:    
                            if service:
                                if check_cname_exists_in_services(url):
                                    print(colored(f"[SERVICE FOUND] {subdomain} pointing to {service} | Status code: {status_code}", "light_green"))
                                    outputs.append(f"[SERVICE FOUND] {subdomain} pointing to {service} | Status code: {status_code}")
                                elif cname_value == domain:
                                    if args.ignore_same:
                                        continue
                                    else:
                                        print(colored(f"[POTENTIAL] {subdomain} pointing to the main domain {domain} | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] {subdomain} pointing to the main domain {domain} | Status code: {status_code}")
                                elif cname_value is not None and status_code != 200:
                                    if not check_cname_exists_in_services(cname_value, SERVICES):
                                        print(colored(f"[POTENTIAL] {subdomain} pointing to {service} with CNAME: {cname_value} | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] {subdomain} pointing to {service} with CNAME: {cname_value} | Status code: {status_code}")
                                    if check_cname_exists_in_services(cname_value, SERVICES):
                                        print(colored(f"[POTENTIAL] {subdomain} pointing to unknown service with CNAME: {cname_value} | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] {subdomain} pointing to unknown service with CNAME: {cname_value} | Status code: {status_code}")
                                elif subdomain_a_record is not None and status_code == 200:
                                    print(colored(f"[SUBDOMAIN] Found subdomain {subdomain} with A record: {subdomain_a_record} | Status code: {status_code}", "light_green"))
                                    outputs.append(f"[SUBDOMAIN] Found subdomain {subdomain} with A record: {subdomain_a_record} | Status code: {status_code}")
                                elif cname_value is not None and status_code != 200:
                                    print(colored(f"[POTENTIAL] Subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}", "light_cyan"))
                                    outputs.append(f"[POTENTIAL] Subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}")
                                elif subdomain_a_record is not None and status_code != 200:
                                    print(colored(f"[POTENTIAL] {subdomain} responded with A record: {subdomain_a_record} | Status code: {status_code}", "light_cyan"))  
                                    outputs.append(f"[POTENTIAL] {subdomain} responded with A record: {subdomain_a_record} | Status code: {status_code}")                      
                            else:
                                if subdomain_a_record == main_domain_a_record:
                                    if args.ignore_same:
                                        continue
                                    else:
                                        print(colored(f"[POTENTIAL] Subdomain [{subdomain}] A record is the same as main domain: {main_domain_a_record} | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] Subdomain [{subdomain}] A record is the same as main domain: {main_domain_a_record} | Status code: {status_code}")
                                elif cname_value is not None:
                                    print(colored(f"[NON RESOLVE] Subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}", "light_yellow"))
                                    outputs.append(f"[NON RESOLVE] Subdomain {subdomain} with CNAME record {cname_value} | Status code: {status_code}")
                                elif subdomain_a_record is not None:
                                    print(colored(f"[NON RESOLVE] {subdomain} responded with A record: {subdomain_a_record} | Status code: {status_code}", "light_yellow"))
                                    outputs.append(f"[NON RESOLVE] {subdomain} responded with A record: {subdomain_a_record} | Status code: {status_code}")
                                else:
                                    print(colored(f"[ERROR] {subdomain} returned a status code of: {status_code}.", "light_yellow"))
                                    outputs.append(f"[ERROR] {subdomain} returned a status code of: {status_code}.")
                                    error_log.append(f"{subdomain} returned a status code of: {status_code}.")
                                    if error_log:
                                        with open("error_log.txt", "w") as file:
                                            for error in error_log:
                                                file.write(error + "\n")
                        except Exception as e:
                            print(colored(f"[ERROR] {e}", "light_red"))
                            outputs.append(f"[ERROR] {e}")
                            error_log.append(f"[ERROR] {e}")
                            if error_log:
                                with open("error_log.txt", "w") as file:
                                    for error in error_log:
                                        file.write(error + "\n")
                    if args.vuln:
                        try:    
                            if service:
                                if check_service_status(url):
                                    takeover_url = TAKEOVER_URLS.get(service, "")
                                    print(colored(f"[VULNERABLE] {subdomain} pointing to {service} with CNAME: {cname_value} Click here to takeover this subdomain: {takeover_url} | Status code: {status_code}", "light_green"))
                                    outputs.append(f"[VULNERABLE] {subdomain} pointing to {service} with CNAME: {cname_value} Click here to takeover this subdomain: {takeover_url} | Status code: {status_code}")
                                elif cname_value == domain:
                                    if args.ignore_same:
                                        continue
                                    else:
                                        print(colored(f"[POTENTIAL] {subdomain} pointing to the main domain {domain}.", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] {subdomain} pointing to the main domain {domain}.")
                                elif cname_value is not None and status_code != 200:
                                    if not check_cname_exists_in_services(cname_value, SERVICES):
                                        print(colored(f"[POTENTIAL] {subdomain} pointing to {service} with a non-resolving CNAME of: {cname_value} | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] {subdomain} pointing to {service} with a non-resolving CNAME of: {cname_value} | Status code: {status_code}")
                                    else:
                                        print(colored(f"[POTENTIAL] Subdomain {subdomain} is pointing to an unknown service with CNAME: {cname_value} | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] Subdomain {subdomain} is pointing to an unknown service with CNAME: {cname_value} | Status code: {status_code}")
                                elif cname_value is not None and status_code == None:
                                    if not check_cname_exists_in_services(cname_value, SERVICES):
                                        print(colored(f"[POTENTIAL] {subdomain} pointing to {service} with a non-resolving CNAME. | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] {subdomain} pointing to {service} with a non-resolving CNAME. | Status code: {status_code}")
                                    else:
                                        print(colored(f"[POTENTIAL] Subdomain {subdomain} is pointing to an unknown service with CNAME: {cname_value} | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] Subdomain {subdomain} is pointing to an unknown service with CNAME: {cname_value} | Status code: {status_code}")
                                elif subdomain_a_record == main_domain_a_record and status_code == 200:
                                    if args.ignore_same:
                                        continue
                                    else:
                                        print(colored(f"[SUBDOMAIN] Subdomain found {subdomain} has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code}", "light_green"))
                                        outputs.append(f"[SUBDOMAIN] Subdomain found {subdomain} has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code}")
                                elif subdomain_a_record == main_domain_a_record and status_code == 404:
                                    if args.ignore_same:
                                        continue
                                    else:
                                        print(colored(f"[POTENTIAL] Subdomain found {subdomain} has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] Subdomain found {subdomain} has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code}")
                                elif subdomain_a_record == main_domain_a_record and status_code != 200:
                                    if args.ignore_same:
                                        continue
                                    else:
                                        print(colored(f"[POTENTIAL] Subdomain found {subdomain} has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] Subdomain found {subdomain} has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code}")
                                elif subdomain_a_record != main_domain_a_record and status_code != 200:
                                    if args.ignore_same:
                                            continue
                                    else:
                                        print(colored(f"[POTENTIAL] Subdomain has the same A name record as {domain} but responded with status code: {status_code} | A name record: {subdomain_a_record}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] Subdomain has the same A name record as {domain} but responded with status code: {status_code} | A name record: {subdomain_a_record}")
                            else:
                                if subdomain_a_record == main_domain_a_record and status_code == 200:
                                    if args.ignore_same:
                                        continue
                                    else:
                                        print(colored(f"[POTENTIAL] Subdomain has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code} ", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] Subdomain has the same A name record as {domain} | A name record: {subdomain_a_record} | Status code: {status_code} ")
                                elif subdomain_a_record == main_domain_a_record and status_code != 200:
                                    if args.ignore_same:
                                        continue
                                    else:
                                        print(colored(f"[POTENTIAL] Subdomain has the same A name record as {domain} but responded with status code: {status_code} | A name record: {subdomain_a_record}", "light_cyan"))
                                        outputs.append(f"[POTENTIAL] Subdomain has the same A name record as {domain} but responded with status code: {status_code} | A name record: {subdomain_a_record}")
                                else:
                                    print(colored(f"[ERROR] {subdomain} returned a status code of {status_code}.", "light_red"))
                                    outputs.append(f"[ERROR] {subdomain} returned a status code of {status_code}.")
                                    error_log.append(f"[ERROR] {subdomain} returned a status code of {status_code}.")
                                    if error_log:
                                        with open("error_log.txt", "w") as file:
                                            for error in error_log:
                                                file.write(error + "\n")
                        except Exception as e:
                            print(colored(f"[ERROR] {e}", "light_red"))
                            outputs.append(f"[ERROR] {e}")
                            error_log.append(f"[ERROR] {e}")
                            if error_log:
                                with open("error_log.txt", "w") as file:
                                    for error in error_log:
                                        file.write(error + "\n")
                            continue
                except KeyboardInterrupt:
                    print(colored(f"\n[ABORTED] Scan aborted by user.", "light_red"))
                    error_log.append(f"[ABORTED] Scan aborted by user.")
                    if error_log:
                        with open("error_log.txt", "w") as file:
                            for error in error_log:
                                file.write(error + "\n")
                    exit(0)
                except Exception as e:
                    print(colored(f"[ERROR] {subdomain} returned an error: {e}", "light_red"))
                    outputs.append(f"[ERROR] {subdomain} returned an error: {e}")
                    error_log.append(f"[ERROR] {subdomain} returned an error: {e}")
                    if error_log:
                        with open("error_log.txt", "w") as file:
                            for error in error_log:
                                file.write(error + "\n")
                    continue
        if args.output:
            with open(args.output, "w") as file:
                for output in outputs:
                    file.write(output + "\n")
        if args.email:
            try:
                now = datetime.datetime.now()
                subject = (f"Subd Scan Results | {now.strftime('%B %d, %Y %H:%M:%S')}")
                body = "\n".join(outputs)
                send_email(subject, body)
            except Exception as e:
                print(colored(f"[ERROR] {e}", "light_red"))
                outputs.append(f"[ERROR] {e}")
                error_log.append(f"[ERROR] {e}")
                if error_log:
                    with open("error_log.txt", "w") as file:
                        for error in error_log:
                            file.write(error + "\n")
    while True:
        scan_and_notify()
        if args.schedule:
            try:
                interval = args.interval
                if interval == 1:
                    print(colored(f"[WAITING] Scan complete | Will scan again after {interval} minute", "light_green"))
                else:
                    print(colored(f"[WAITING] Scan complete | Will scan again after {interval} minutes", "light_green"))
                time.sleep(args.interval * 60) 
            except KeyboardInterrupt:
                print(colored(f"\n[ABORTED] Scan aborted by user.", "light_red"))
                error_log.append("[ABORTED] Scan aborted by user.")
                if error_log:
                    with open("error_log.txt", "w") as file:
                        for error in error_log:
                            file.write(error + "\n")
                exit(0)   
            except Exception as e:
                print(colored(f"[ERROR] Unhandled error: {e}", "light_red"))
                error_log.append(f"[ERROR] Unhandled error: {e}")
                if error_log:
                    with open("error_log.txt", "w") as file:
                        for error in error_log:
                            file.write(error + "\n")
                continue
        else:
            break
    print(colored("[EXITING] Scan complete", "light_green"))