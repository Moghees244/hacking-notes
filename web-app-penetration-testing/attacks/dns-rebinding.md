# DNS Rebinding

- In a DNS rebinding attack, an attacker configures a low TTL on their domain and changes the IP address the domain resolves to between subsequent requests.

## Bypassing SSRF Filters

- We need to provide the web application with a domain under our control so that we can change its DNS configuration.
- We will configure the DNS server to resolve our domain to any IP address that is not blacklisted, such as 1.1.1.1, and assign it a very low TTL.
- When we provide the web application with the URL of our domain, it will resolve the domain name to 1.1.1.1 and verify that it is not an internal IP address.
- Subsequently, we will rebind the DNS configuration for our domain to resolve to 127.0.0.1 instead of 1.1.1.1. 
- Due to the low TTL assigned to our domain, the web application will resolve it again.
- At last, due to the DNS rebinding, the second DNS resolution will resolve the domain name to 127.0.0.1 such that the web application accesses the URL http://127.0.0.1/secret and fetches the data for us.


### Exploitation

- For exploitation of public apps we can use [rbndr.us](https://lock.cmpxchg8b.com/rebinder.html)
- To achieve our bypass, we can supply the URL http://7f000001.01010101.rbndr.us/flag to the web application. Since the domain name resolves randomly to one of the two IP addresses, we might require multiple attempts as we need the first resolution to resolve to 1.1.1.1 and the second to 127.0.0.1.

- We can also use [DNS Rebinder Script](https://github.com/mogwailabs/DNSrebinder), this can be used on public and internal applications.

```shell
sudo python3 dnsrebinder.py --domain attacker.com --rebind 127.0.0.1 --ip 1.1.1.1 --counter 1 --tcp --udp
```

> These attack will work depending on application structure.

> For internal web apps, you may need to get into internal DNS server. 


## Same-Origin Policy Bypass

- 