# Domain Enumeration From Windows

For credentialed enumeration, we must have a user's cleartext password, NTLM 
password hash, or SYSTEM access on a domain-joined host.

Once we have any of the above, we should start enumerating domain. We are 
interested in domain users and computers attributes, group membership,
Group Policy Objects, permissions, ACLs, trusts and more.


## ActiveDirectory PowerShell Module

[Documentation for Windows AD Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)


 ```shell
 # List all available modules
 Get-Module

 # Loading AD module if not loaded
 Import-Module Active-Directory

 # If AD module is not available, install it
 # Need Administrative privileges
 Get-Module -ListAvailable -Name ActiveDirectory
 Install-WindowsFeature RSAT-AD-PowerShell

 # Get domain info
 Get-ADDomain

 # Get AD users
 Get-ADUser

 # Get user accounts with SPN property populated
 Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

 # Checking For Trust Relationships
 Get-ADTrust -Filter *

 # Get groups info
 Get-ADGroup -Filter *

 # Detailed group info
 Get-ADGroup -Identity "Group Name"

 # Get members of the group
 Get-ADGroupMember -Identity "Group Name"
 ```


## PowerView

PowerView is a tool written in PowerShell to help us gain situational awareness within an AD environment.
Following are the commonly used commands of powerview:

 ```shell
 # Convert a User or group name to its SID value
 ConvertTo-SID
 # Requests the Kerberos ticket for a specified 
 # Service Principal Name (SPN) account
 Get-DomainSPNTicket
 # Append results to a CSV file
 Export-PowerViewCSV
 ```

### Domain/LDAP Functions

 ```shell
 # Will return the AD object for the current (or specified) domain
 Get-Domain
 # Return a list of the Domain Controllers for the specified domain
 Get-DomainController
 # Will return all users or specific user objects in AD
 Get-DomainUser
 # Will return all computers or specific computer objects in AD
 Get-DomainComputer
 # Will return all groups or specific group objects in AD
 Get-DomainGroup
 # Search for all or specific OU objects in AD
 Get-DomainOU
 # Finds object ACLs in the domain with modification rights set to non-built in objects
 Find-InterestingDomainAcl
 # Will return the members of a specific domain group
 Get-DomainGroupMember
 # Returns a list of servers likely functioning as file servers
 Get-DomainFileServer
 # Returns a list of all distributed file systems for the current (or specified) domain
 Get-DomainDFSShare
 ```

### GPO Functions

 ```shell
 # Will return all GPOs or specific GPO objects in AD
 Get-DomainGPO
 # Returns the default domain policy or the domain controller
 # policy for the current domain
 Get-DomainPolicy
 ```

### Computer Enumeration Functions

 ```shell
 # Enumerates local groups on the local or a remote machine
 Get-NetLocalGroup
 # Enumerates members of a specific local group
 Get-NetLocalGroupMember
 # Returns open shares on the local (or a remote) machine
 Get-NetShare
 # Will return session information for the local (or a remote) machine
 Get-NetSession
 # Tests if the current user has administrative access to the local (or a remote) machine
 Test-AdminAccess
 ```

### Threaded 'Meta'-Functions

 ```shell
 # Finds machines where specific users are logged in
 Find-DomainUserLocation
 # Finds reachable shares on domain machines
 Find-DomainShare
 # Searches for files matching specific criteria on readable shares in the domain
 Find-InterestingDomainShareFile
 # Find machines on the local domain where the current user has local administrator access
 Find-LocalAdminAccess
 ```

### Domain Trust Functions

 ```shell
 # Returns domain trusts for the current domain or a specified domain
 Get-DomainTrust
 # Returns all forest trusts for the current forest or a specified forest
 Get-ForestTrust
 # Enumerates users who are in groups outside of the user's domain
 Get-DomainForeignUser
 # Enumerates groups with users outside of the group's domain and returns each foreign member
 Get-DomainForeignGroupMember
 # Will enumerate all trusts for the current domain and any others seen
 Get-DomainTrustMapping
 ```

Using filters with PowerView functions:

 ```shell
 # Domain User Information
 Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

 # Recursive Group Membership
 # Adding the -Recurse switch tells PowerView that if it finds any groups
 # that are part of the target group (nested group membership) to list out
 # the members of those groups.
 Get-DomainGroupMember -Identity "Group Name" -Recurse

 # Finding users with SPN property set
 Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

 # Test for local admin access on either the current machine or a remote one.
 Test-AdminAccess -ComputerName ComputerName
 ```

## SharpView

SharpView is a .NET port of PowerView. Many of the same functions supported by
PowerView can be used with SharpView.

 ```shell
 # Get user information
 .\SharpView.exe Get-DomainUser -Identity username
 ```

## Enumerating shares using Snaffler

Snaffler is a tool that can help us acquire credentials or other sensitive data in an 
Active Directory environment. Snaffler works by obtaining a list of hosts within the domain
and then enumerating those hosts for shares and readable directories. Snaffler requires that 
it be run from a domain-joined host or in a domain-user context.

 ```shell
 Snaffler.exe -s -d $DOMAIN -o snaffler.log -v data
 ```

## BloodHound

Bloodhound is an exceptional open-source tool that can identify attack paths within an AD environment
by analyzing the relationships between objects.

- First, we must authenticate as a domain user from a Windows attack host that is positioned within the 
network but it doesn't need to be joined to the domain as long as creds are provided.

 ```shell
 # Make sure the sharphound version is compatible
 # with your bloodhound version
 .\SharpHound.exe -c All --zipfilename domain_data
 ```

- Now we can upload zipfile to bloodhound and start analysis
- Type `domain: $DOMAIN_NAME` in search bar to filter info related to a specific domain
- There are some pre-built queries in `Analysis` tab.
- Some queries that are useful:

 ```shell
 Find Computers with Unsupported Operating Systems
 Find Computers where Domain Users are Local Admin
 ```

Things to Keep in mind:
- If you find a host running old OS, report it as it can cause issues.
It is better to segement it from rest of the network.
- Make sure the host is Live before reporting it.

- Sometimes users are provided local admin roles for some specific task but it was not
revoked. YOu will sometimes also find excessive local admin rights.

> [Misconfiguration Module HTB](https://academy.hackthebox.com/module/143/section/1276)

## Exchange Groups

- The group `Exchange Windows Permissions` is not listed as a protected group, but members are granted the ability to write a DACL to the domain object. This can be leveraged to give a user DCSync privileges.

- The Exchange group `Organization Management` is another extremely powerful group (effectively the "Domain Admins" of Exchange) and can access the mailboxes of all domain users. This group also has full control of the OU called Microsoft Exchange Security Groups, which contains the group Exchange Windows Permissions.


## Miscellaneous Misconfigurations

- Finding Passwords in the Description Field using Get-Domain User

```shell
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```

- Domain accounts with the `passwd_notreqd` field set in the userAccountControl attribute are not subject to the current password policy length. They could have a shorter password or no password at all (if empty passwords are allowed in the domain). 

```shell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

- Credentials in SMB Shares and SYSVOL Scripts

- Group Policy Preferences (GPP) Passwords

```shell
crackmapexec smb $TARGET_IP -u $USER -p $PASSWORD -M gpp_autologin

# They can also be decrypted
gpp-decrypt $ENCRYPTED_PASSWORD
```

- Group Policy Object (GPO) Abuse
```shell
# Enumerating GPOs
Get-GPO -All | Select DisplayName

# Enumerating domain users GPOs rights
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

# Converting GPO GUID to Name
Get-GPO -Guid $GUID
```

> Use automated tools like group3r, ADRecon, PingCastle, SharpGPOAbuse

- Check Deleted Objects in AD:

```shell
Import-Module ActiveDirectory
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
Restore-ADObject -Identity <object_gid>
Enable-ADAccount -Identity <object_name>
```

- The `PrivExchange attack` results from a flaw in the Exchange Server PushSubscription feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP. 

- Printer bug:

```shell
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName $COMPUTER_FQDN
```

- MS14-068 was a flaw in the Kerberos protocol, which could be leveraged along with standard domain user credentials to elevate privileges to Domain Admin. [Tool](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek)

- Sniffing LDAP Credentials, the application has a test connection function that we can use to gather credentials by changing the LDAP IP address to that of our attack host and setting up a netcat listener on LDAP port 389. When the device attempts to test the LDAP connection, it will send the credentials to our machine, often in cleartext.

- Enumerate DNS records and find hidden records. [Tool](https://github.com/dirkjanm/adidnsdump)


## Automated Scanning

- We can create an AD Snapshot with `Active Directory Explorer` tool.

```shell
# https://github.com/adrecon/ADRecon
.\ADRecon.ps1

# group3r for group policies
group3r.exe -f <filepath-name.log> 

# PingCastle for full domain audit
PingCastle.exe --healthcheck --server $DC_IP --filedir reports/ --zipfile output.zip
```
