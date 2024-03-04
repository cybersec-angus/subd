import requests
import paramiko
import ftplib
import dns.resolver
import telnetlib

# Validate HTTP connection
def test_http(target):
  try:
    response = requests.get("http://" + target)
    return response.status_code
  except requests.exceptions.ConnectionError:
    return "Connection error"
  except requests.exceptions.Timeout:
    return "Timeout"
  except:
    return "Other error"

# Validate HTTPS
def test_https(target):
  try:  
    response = requests.get("https://" + target)
    return response.status_code
  except requests.exceptions.SSLError:
    return "SSL error"
  except requests.exceptions.ConnectionError:
    return "Connection error"
  except:
    return "Other error"

  
# Query DNS to test for public DNS access
def test_dns(target):
  try:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [target]
    resolver.resolve("example.com")
    return "Query succeeded" 
  except dns.exception.DNSException:
    return "DNS query failed"
  except:
    return "Other error"

# Validates SSH is publicly accessible
def test_ssh(target):
  try:
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
    ssh_client.connect(target, username='test', password='test', timeout=10)
    return "Connected"
  except paramiko.ssh_exception.AuthenticationException:
    return "Authentication failed"
  except paramiko.ssh_exception.SSHException:
    return "SSH error"
  except:
    return "Other error"

# Validates FTP is publicly accessible
def test_ftp(target):
  try:
    ftp = ftplib.FTP(target)
    ftp.login('anonymous','me@example.com')
    return "Logged in"
  except ftplib.error_perm:
    return "Login failed"
  except:
    return "Other error"

# Validates Telnet is publicly accessible
def test_telnet(target):
  try:
    tn = telnetlib.Telnet(target)
    tn.read_until(b"Login: ")
    return "Connected"
  except ConnectionRefusedError:
    return "Connection refused"
  except:
    return "Other error" 
# Validates RDP is publicly accessible
def test_rdp(target):
  try:
    rdp = RDP(target)
    rdp.connect()
    return "Connected"
  except:
    return "Connection failed"