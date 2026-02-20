# Triage

- If we gain elevated access to a computer, we can extract Kerberos tickets that are currently cached in memory.
- Rubeus' `triage` command will enumerate every logon session present and their associated tickets.
- If multiple logon session exist, TGTs and service tickets for those users can be extracted and re-used.

```powershell
.\Rubeus.exe triage
```

- Rubeus' `dump` command with no additional parameters will extract every single ticket.
- Use the `/service` or `/luid` parameters to target a specific service or logon session.

> Tickets with krbtgt as the service are TGTs, other tickets are service tickets.

```powershell
.\Rubeus.exe dump /luid:$LUID /service:krbtgt /nowrap
```

## OPSEC Advantage

- The major OPSEC advantage of dumping tickets from memory is that it does not touch LSASS in the same way that dumping hashes does (e.g. with Mimikatz sekurlsa).  
- The ticket data are recovered using LSA APIs such as LsaCallAuthenticationPackage, rather than pulling them directly from LSASS memory. This means we never obtain a handle to the LSASS process and therefore won't be logged via kernel callbacks.


## Renewing TGTs

- Once a TGT has expired, it can no longer be used to request service tickets.  Running Rubeus describe against a ticket will show you its StartTime, EndTime, and RenewTill fields.

```powershell
.\Rubeus.exe describe /ticket:$TICKET
```

> `RenewTill` is the date beyond which tickets can no longer be renewed (this won't make 100% sense just yet).  This is 7 days after the StartTime by default.

- TGTs issued by a KDC are only valid for a limited length of time.  When they are due to expire, Windows will transparently renew the ticket without the user having to provide their password again.  We can renew a ticket manually using Rubeus' renew command.

```powershell
.\Rubeus.exe renew /ticket:$TICKET
```

> This means that we can renew a TGT every 10 hours, up until the RenewTill date is reached.  After that, we'd have to dump a fresh TGT.

> RalfHacker has a number of Kerberos BOFs that are useful for instances where you don't want to use Rubeus with execute-assembly.  The included Aggressor scripts adds a few new Beacon commands, such as krb_triage and krb_dump.