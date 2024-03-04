import argparse
from termcolor import colored

help_text = colored("""
             __  __          ___                          
            /\ \/\ \        /\_ \                         
            \ \ \_\ \     __\//\ \    _____               
             \ \  _  \  /'__`\\ \ \  /\ '__`\             
              \ \ \ \ \/\  __/ \_\ \_\ \ \L\ \            
               \ \_\ \_\ \____\/\____\\ \ ,__/            
                \/_/\/_/\/____/\/____/ \ \ \/             
                                        \ \_\             
                                         \/_/             
                                    __             __     
                                   /\ \           /\ \    
              ___      __     __   \_\ \     __   \_\ \   
            /' _ `\  /'__`\ /'__`\ /'_` \  /'__`\ /'_` \  
            /\ \/\ \/\  __//\  __//\ \L\ \/\  __//\ \L\ \ 
            \ \_\ \_\ \____\ \____\ \___,_\ \____\ \___,_\
            
             \/_/\/_/\/____/\/____/\/__,_ /\/____/\/__,_ /
            """, "light_blue")
faq = colored("""
            [*] What can I do with Subd?
                 - Find subdomains
                 - Port scan found subdomains
                 - Check if subdomains are pointing to any services and if they are Hijackable
                 - Check if subdomains are pointing to any MX records, and attempt to identify the email provider
                 - Master attack suface reduction and monitoring
            [*] Who developed Subd?
                Subd was developed by CyberSec-Angus, an independent security researcher focused on OSINT, external attack surfaces, and NetSec. You can find out more about him and his work on github.com/cybersec-angus.
            [*] Why the submarine theme?
                Submarines are stealthy, can operate covertly to map out hidden vulnerabilities just below the surface. Subd takes a similar approach to identify subdomains and attack surfaces that may not be obvious.
            [*] What permissions or authorizations does Subd require?
                Subd performs passive scans, queries public records and does not make any changes or interact with target systems. That being said, ensure you have permission before scanning any domains or systems, and refrain from using Subd for illegal purposes. The developer will NOT be help accountable for any illegality. 
            [*] How do I run Subd?
                At a minimum, you need to run the following from the root directory: "python3 subd.py -d example.com -w /path/to/wordlist.txt" and then you can optionally add additional flags after the -w flag. 
""", "light_green")
class CustomFormatter(argparse.RawDescriptionHelpFormatter):
    def _split_lines(self, text, width):
        return text.splitlines() 

def parse_arguments():
    parser = argparse.ArgumentParser(formatter_class=CustomFormatter,description=f"{help_text}\n\n{faq}")
    parser.add_argument("-w", "--wordlist", help="Wordlist for subdomain enumeration", required=True)
    parser.add_argument("-d", "--domains", help="Domains (comma-separated) or CSV file", required=True)
    parser.add_argument("-v", "--verbose", help="Enable verbosity to show a detailed output of what is happening.", action="store_true")
    #parser.add_argument("-e", "--email", help="Admin email to send notifications to. Can be used in conjunction with the", "action="store_true")
    parser.add_argument("-ps", "--port-scan", help="Runs port scan on all subdomains that have either a CNAME or an A record. This will take a while, and will increase execution time considerbly. Will only output no ports when verbose. If you want to see scan failures, use the -v argument.", action="store_true")
    parser.add_argument("-is", "--ignore-same", help="Will supress results where the DNS record of the subdomain and the main domain are the same.", action="store_true")
    parser.add_argument("-m", "--mail-id", help="Will output any MX records for the domain and subdomain, and attempt to match the MX records to an email provider based on the MX record", action="store_true")

    # Mutually exclusive group for the scan options
    scan_group = parser.add_mutually_exclusive_group(required=True)
    scan_group.add_argument("-s", "--scan", help="Finds subdomains that are live and potentially in use", action="store_true")
    scan_group.add_argument("-id", "--id", help="Enables service identification, does not find vuln subdomains. Does not need choosing if -hj/--vuln is enabled.", action="store_true")
    scan_group.add_argument("-hj", "--vuln", help="Finds subdomains pointing to a CNAME that can be hijacked. Does not identify other subdomains, use -fs for that.", action="store_true")

    scan_group = parser.add_mutually_exclusive_group(required=False)
    scan_group.add_argument("-qs", "--quick-port-scan", help="Quick port scan, of the top 20 most common ports.", action="store_true")
    scan_group.add_argument("-fs", "--full-port-scan", help="Full port scan of the top 100 ports used on web servers. This will take a while. ", action="store_true")
    scan_group.add_argument("-cs", "--custom-port-scan", help="This will use the custom port dictionary, found in the file custom_ports.py. This is useful if you have a specific set of ports you want to tests on hosts, but don't want to alter the other dictionaries.", action="store_true")

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