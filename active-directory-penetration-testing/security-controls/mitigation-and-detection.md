# Mitigation and Detection of Attacks

## LLMNR Poisoning

### Remediation

- Mitre ATT&CK lists this technique as ID: T1557.001, Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay.
- Disable LLMNR and NBT-NS.
- We can disable LLMNR in Group Policy by going to Computer Configuration --> Administrative Templates --> Network --> DNS Client and enabling "Turn OFF Multicast Name Resolution."
- NBT-NS cannot be disabled via Group Policy but must be disabled locally on each host. We can write a script for the GPO and add it to startup properties.


### Detection

- It is not always possible to disable LLMNR and NetBIOS, and therefore we need ways to detect this type of attack behavior.
- One way is to use the attack against the attackers by injecting LLMNR and NBT-NS requests for non-existent hosts across different subnets
 and alerting if any of the responses receive answers which would be indicative of an attacker spoofing name resolution responses.
- Furthermore, hosts can be monitored for traffic on ports UDP 5355 and 137, and event IDs 4697 and 7045 can be monitored for.
- Finally, we can monitor the registry key HKLM\Software\Policies\Microsoft\Windows NT\DNSClient for changes to the EnableMulticast DWORD value.
 A value of 0 would mean that LLMNR is disabled.


## Password Spraying

### Remediation

- No single solution will prevent it, a defense-in-depth approach will make it difficult for attackers.
- Following are some methods to prevent it:
    - Multi-factor Authentication
    - Restricting Access (principle of least privilege)
    - Reducing Impact of Successful Exploitation (seperate accounts for admin activities)
    - Password Hygiene

### Detection

- event ID 4625: An account failed to log on over a short period may indicate a password spraying attack.
- event ID 4771: Kerberos pre-authentication failed, which may indicate an LDAP password spraying attempt