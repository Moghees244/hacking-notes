# Enumeration

## skipping nmap scanning part for now

## Identifying Users

Once you are in the network and have enumerated live hosts using nmap, tcpdump or whatever tool.
We need to find a way to establish foothold in domain by gttng username and credentials (clear text or NTLM hash).
It is important to get this access in the early stages of pentest so we can perform more enumeration and attacks.

### Username Enumeration

- kerbrute is a stealthy option for domain account enumeration.
- It uses kerberos protocol to check if the username is valid or not.
- It takes advantage of kerberos pre-authentication, as the failures will not trigger logs or alerts

 ```yaml
 kerbrute userenum -d $DOMAIN --dc $DC_IP wordlist.txt -o valid_ad_users
 ```

 