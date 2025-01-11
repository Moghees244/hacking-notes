# Active Reconnaissance

## Fingerprinting

- Fingerprinting focuses on extracting technical details about the technologies powering a website or web application.

### Banner Grabbing
```shell
# Banner grabbing
curl -I <target_domain>
# Firewall enumeration
wafw00f <target_domain>
# Footprinting using nikto
nikto -h <target_domain> -Tuning b
```

### Analysing HTTP Headers
- The Server header typically discloses the web server software.
- X-Powered-By header might reveal additional technologies like frameworks.

### Probing for Specific Responses
- Sending specially crafted requests can elicit unique responses that reveal specific technologies or versions.
- For example, certain error messages are characteristic of particular web servers or software components.

### Analysing Page Content
- A web page's content provides clues about the underlying technologies. 
- For example, There may be a copyright header that indicates specific software being used.
- `Wappalyzer` extension can help to identify web technologies, including CMSs, frameworks, and more.
- Using web crawlers to fetch links, emails, comments, js files and external files.


## DNS Zone Transfers

- A DNS zone transfer is all DNS records within a zone (a domain and its subdomains) from one name server to another.
- This maintains consistency and redundancy across DNS servers.
- If not secured, unauthorised parties can download the entire zone file.

1. Secondary server send AXFR request to Primary server
2. Primary server sends SOA Record (Start of Authority)
3. Primary server send DNS Record
4. Zone Transfer Complete
5. Secondary server sends Acknowledgement

```shell
dig @<name_server> <target_domain> AXFR
```


## Subdomain Bruteforcing

- Subdomain Brute-Force Enumeration is a powerful active subdomain discovery technique that leverages pre-defined lists of potential subdomain names.
- A wordlist is provided to a tool which iterates through it and append each word with the main domain. Then a DNS query is performed for each potential subdomain to check if it resolves to an IP address. This is typically done using the A or AAAA record type.

```shell
dnsenum --enum $DOMAIN -f <wordlist_file> -r
ffuf -w <wordlist_file>:FUZZ -u http://FUZZ.<target_domain>
```

```shell
Note: While using ffuf, you should use flags like -fs, -fc, -mc, -ms etc to match or filter the responses.
run ffuf -h for details
```


## VHOST Fuzzing

- Web servers are designed to host multiple websites or applications on a single server.
- They achieve this through virtual hosting, which allows them to differentiate between domains, subdomains, or even separate websites with distinct content.
- This is achieved by using the HTTP Host header.

```shell
gobuster vhost -u http://<target_domain> -w <wordlist_file> --append-domain -t 10 -o vhosts.txt
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/ -H 'Host: FUZZ.<target_domain>'
```


## Checking Common Files

- When performing reconnaissance on a web server, it's essential to check for common files that may contain
 useful information or reveal critical metadata about the website.

### Key Files to Check:
- `robots.txt`: Provides directives for web crawlers, which can sometimes reveal sensitive or restricted areas of the website.
- `.well-known/` Directory: This directory is used to store various important metadata files for standardized protocols
 and configurations.

```shell
# Robots exclusion file
/robots.txt

# Common .well-known URLs
# Contact information for security issues
/.well-known/security.txt
# URL for changing user passwords
/.well-known/change-password
# OpenID Connect configuration (IMP)
/.well-known/openid-configuration
# App links verification for Android
/.well-known/assetlinks.json
# Mail Transfer Agent (MTA) Strict Transport Security policy
/.well-known/mta-sts.txt
```


## Directory and Page Fuzzing

```shell
# Directory fuzzing
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/FUZZ
# Extension fuzzing
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/indexFUZZ
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/<directory>/indexFUZZ
# Page fuzzing
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/<directory>/FUZZ.php
# Using multiple wordlists
ffuf -w <dir_wordlist_file>:FUZZ1 <ext_wordlist_file>:FUZZ2 -u http://<target_domain>/<directory>/FUZZ1.FUZZ2
# Recursive fuzzing
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/FUZZ -recursion -recursion-depth 1
# Recursive fuzzing with extension
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/FUZZ -recursion -recursion-depth 1 -e <extension>
```


## Parameter Fuzzing

```shell
# GET request fuzzing
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/<page.ext>?FUZZ=key

# POST request fuzzing
# Note: In PHP, "POST" data "content-type" only accepts
# "application/x-www-form-urlencoded". So, we can set that in
# "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'"
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/<page.ext> -X POST -d 'FUZZ=key'
# For PHP based web apps
ffuf -w <wordlist_file>:FUZZ -u http://<target_domain>/<page.ext> -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'

# Use the same methods for Fuzzing values, once you find params
```


## Automating Recon

Automating reconnaissance can significantly speed up the information-gathering process. 
Below are some powerful tools that can help automate various aspects of web reconnaissance:

### 1. theHarvester Framework
`theHarvester` helps collect emails, subdomains, and other open-source intelligence from popular
 sources like Google, Bing, and LinkedIn.

```shell
# Perform reconnaissance on a target domain using multiple
# search engines and save the output as an HTML report
theHarvester -d <domain> -b google,bing,linkedin -f report.html
```

### 2. FinalRecon Framework  
`FinalRecon` provides a comprehensive reconnaissance solution, allowing for automated gathering
 of information across multiple domains.  

- Config File: `~/.config/finalrecon/config.json`
- Installation: `sudo apt install finalrecon`

```shell
# Use FinalRecon with your API keys to gather full reconnaissance data
python3 finalrecon.py -k '<API NAME>@<API KEY>' --full --url <target_domain>
```  

### 3. **Spiderfoot Framework**  
`Spiderfoot` automates the process of gathering information on various entities, such as
 IP addresses, domains, emails, and more.

- **Targets**:  
  - IP address  
  - Domain/sub-domain  
  - Hostname  
  - Network subnet (CIDR)  
  - Email address  
  - Phone number  
  - Username  
  - Person's name  

- Repo: `git clone https://github.com/smicallef/spiderfoot.git`
- Starting the Server: `python3 ./sf.py -l 127.0.0.1:5001`


## Common Wordlists

```shell
# Subdomains and Vhosts wordlists
seclists/Discovery/DNS/subdomains-top1million-110000.txt
# Directory wordlists
seclists/Discovery/Web-Content/directory-list-2.3-small.txt
# Extensions Wordlists
seclists/Discovery/Web-Content/web-extensions.txt
# Parameters wordlists
seclists/Discovery/Web-Content/burp-parameter-names.txt
```