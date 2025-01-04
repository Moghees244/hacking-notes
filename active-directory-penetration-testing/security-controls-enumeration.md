# Security Controls Enumeration

- Once we get foothold in domain, it is important to enumerate security controls.
- As some security controls may effect our tools. We may need to work at 
"living off the land" by using tools that exist natively on the hosts.

 ```shell
 # This will change the policy for our current process using
 # the -Scope parameter.
 Get-ExecutionPolicy -List
 Set-ExecutionPolicy Bypass -Scope Process

 # Windows Defender, if RealTimeProtectionEnabled=True means
 # defender is active
 sc query windefend
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

 # Check Windows Firewall settings
 netsh advfirewall show allprofiles


 ```

## Oppsec Tactics

- Sometimes older versions of powershell can be found on the host, and defenders are unaware of them.
- Powershell logging was introduces in v3.0, so you can use older version of powershell, if successful
our actions wont be logged in Event Viewer.

 ```shell
 # Get details of host containing current version
 # of powershell used
 Get-host
 # Downgrading powershell to version 2
 powershell.exe -version 2
 ```

- Now checks if logs are saved:
 `Applications and Services Logs > Microsoft > Windows > PowerShell > Operational`
 `Applications and Services Logs > Windows PowerShell`

- Our actions after will be masked since Script Block Logging does not work below PowerShell 3.0

- `net.exe` commands are typically monitored by EDR solutions and can quickly give up our location.
- Some organizations configure their monitoring tools to throw alerts if certain commands are run by
 users in specific OUs, such as a Marketing Associate's account running commands such as whoami, and
 net localgroup administrators, etc.
- Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.
 

## Checking other logged in Users

- When you get foothold on a host, you need to check if there are any other users logged in.
- If you start running commands on that host, other users may notice you and report you.
- They may also change password and you could lose foothold on that host.

 ```shell
 qwinsta
 ```