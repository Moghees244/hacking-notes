# Attacking Common Services

### Getting IPs of web servers
```shell
for i in $(cat subdomainlist);do host $i | grep "has address" | grep $DOMAIN | cut -d" " -f1,4;donev
```

### Server info using Shodan
```shell
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

