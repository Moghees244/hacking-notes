# Enumeration

## Uncredentialed Enumeration

Once you are in the network and have enumerated live hosts using nmap, tcpdump or whatever tool.
We need to find a way to establish foothold in domain by gttng username and credentials (clear text or NTLM hash).
It is important to get this access in the early stages of pentest so we can perform more enumeration and attacks.


### LLMNR Poisoning

We can go for attacks like [LLMNR Poisoning](active-directory-penetration-testing/llmnr-poisoning.md)


### Users Enumeration

- Do some OSINT and try to get information related to people of the target company.
- kerbrute is a stealthy option for domain account enumeration.
- It uses kerberos protocol to check if the username is valid or not.
- It takes advantage of kerberos pre-authentication, as the failures will not trigger logs or alerts

 ```shell
 kerbrute userenum -d $DOMAIN --dc $DC_IP wordlist.txt -o valid_ad_users
 ```


### Password Spraying

- Be careful not to lock accounts while spraying.
- Try to get domain password policy and prepare password list accordingly.
- We can get password policy from `SMB NULL Session` or `LDAP Anonymous Bind`.

- SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, 
such as a complete listing of users, groups, computers, user account attributes, and the domain password policy.
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

- LDAP Anonymous Bind allow unauthenticated attackers to retrieve information from the domain, such as a complete
 listing of users, groups, computers, user account attributes, and the domain password policy.
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
- If we have a password of any domain user, we can easily get the password policy.

 ```shell
 crackmapexec smb $DC_IP -u username -p password --pass-pol
 ```



## Credentialed Enumeration