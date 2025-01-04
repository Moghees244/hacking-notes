# Security Controls Bypass and Oppsec Tactics

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