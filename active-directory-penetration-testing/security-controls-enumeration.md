# Security Controls Enumeration

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