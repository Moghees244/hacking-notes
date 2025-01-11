# Passive Reconnaissance

## WHOIS

- WHOIS is a widely used query and response protocol designed to access databases that store information about
 registered internet resources.
- Primarily associated with domain names, WHOIS can also provide details about IP address blocks and autonomous systems. 
- Think of it as a giant phonebook for the internet, letting you look up who owns or is responsible for various online assets.
- It offers valuable insights into the target organisation's digital footprint and potential vulnerabilities.
- It provides Key Personnel, Network infrastructure and Historical Data Analysis. We can get Registrar, Registrant Contact, Administrative Contact, Technical Contact, Creation and Expiration, Name Servers

```shell
 whois <domain_name>
 
 # This website can provide more details
 https://whoisfreaks.com/
```


## DNS

- The Domain Name System (DNS) acts as the internet's GPS, guiding your online journey from memorable landmarks (domain names) to precise numerical coordinates (IP addresses).
- The zone file, a text file residing on a DNS server, defines the resource records (discussed below) within this zone, providing crucial information for translating domain names into IP addresses.

```shell
 # Performs a default A record lookup for the domain.
dig <domain>
# Retrieves the IPv4 address (A record) associated with the domain.
dig <domain> A
# Retrieves the IPv6 address (AAAA record) associated with the domain.
dig <domain> AAAA
# Finds the mail servers (MX records) responsible for the domain.
dig <domain> MX
# Identifies the authoritative name servers for the domain.
dig <domain> NS
# Retrieves any TXT records associated with the domain.
dig <domain> TXT
# Retrieves the canonical name (CNAME) record for the domain.
dig <domain> CNAME
# Retrieves the start of authority (SOA) record for the domain.
dig <domain> SOA
# Specifies a specific name server to query; in this case 8.8.8.8
dig @8.8.8.8 <domain>
# Shows the full path of DNS resolution.
dig +trace <domain>
# Performs a reverse lookup on the IP address to find the associated host name.
dig -x <IP Address>
# Provides a short, concise answer to the query.
dig +short <domain>
# Displays only the answer section of the query output.
dig +noall +answer <domain>
# Retrieves all available DNS records for the domain.
# Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse, as per RFC 8482.
dig <domain> ANY
# If you dont want any other info
dig +short <domain>
```

## Subdomain Enumeration

- Subdomain enumeration is the process of systematically identifying and listing these subdomains. 
- From a DNS perspective, subdomains are typically represented by A (or AAAA for IPv6) records, which map the subdomain name to its corresponding IP address.
- CNAME records might be used to create aliases for subdomains, pointing them to other domains or subdomains.

```shell
# Following sites can be used to get subdomain info
https://crt.sh/
https://search.censys.io/

# crt.sh provides API which can also be used
curl -s "https://crt.sh/?q=<DOMAIN>&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```

## Search Engine Discovery

```shell
# Find all publicly accessible pages
site:<DOMAIN>
# Finding Login Pages
site:<DOMAIN> inurl:login
site:<DOMAIN> (inurl:login OR inurl:admin)
site:<DOMAIN> AND (allintext:admin password reset OR allinurl:admin panel)
# Identifying Exposed Files
site:<DOMAIN> filetype:pdf
site:<DOMAIN> (filetype:xls OR filetype:docx)
site:<DOMAIN> filetype:pdf user* manual
# Uncovering Configuration Files
site:<DOMAIN> inurl:config.php
site:<DOMAIN> (ext:conf OR ext:cnf)
# Locating Database Backups
site:<DOMAIN> inurl:backup
site:<DOMAIN> filetype:sql
# Finding info within the text of website
site:<DOMAIN> intext:"TEXT_TO_FIND"
```

## Web Archives

- The Wayback Machine is a digital archive of the World Wide Web and other information on the Internet. It has been archiving websites since 1996.
- We can use it for: Tracking Changes and Identifying Patterns, Uncovering Hidden Assets and Vulnerabilities, Gathering Intelligence
- URL: https://web.archive.org/