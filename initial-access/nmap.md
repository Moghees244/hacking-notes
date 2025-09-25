# Network Scanning Using Nmap

### Ping Sweep
```shell
sudo nmap -sn $TARGET_NET -oA live_hosts --stats-every 5s | grep 'for' | cut -d" " -f5
```

### Scan Hosts from a List
```shell
sudo nmap -sn -iL $HOSTS_LIST -oA tnet | grep 'for' | cut -d" " -f5
```

### Scan Types
```shell
# IPv6 Scan
nmap -6 $TARGET_IPv6

# Full TCP Connect Scan (3-Way Handshake)
sudo nmap -sT $TARGET_IP
# Stealth SYN Scan
sudo nmap -sS $TARGET_IP
# UDP Scan
sudo nmap -sU $TARGET_IP
#ACK Scan (Firewall Rule Discovery)
sudo nmap -sA $TARGET_IP
```

### Firewall Evasion
```shell
# Spoof Source IP 
sudo nmap $TARGET_IP -n -Pn -p 445 -O -S $SPOOFED_IP -e tun0
# Spoof Source Port (e.g., Port 53)
sudo nmap -sS -Pn --source-port 53 $TARGET_IP
# Connect to Discovered Service
ncat -nv --source-port 53 $TARGET_IP $TARGET_PORT
# Decoy Scan (Using Random IPs)
-D RND:5
```

### Useful Options
```shell
# ICMP Echo Requests
-PE
# Disable ARP Ping
--disable-arp-ping
# Show Reason for Host State
--reason
# Scan Top 10 Ports
--top-ports 10
#Fast Scan (100 Common Ports)
-F
# Detect Services and Versions
-sV
# Using NSE
--script vuln,discovery
# Set Timing Template (0 = Paranoid, 5 = Insane)
-T5
# Set Minimum Packet Rate
-min-rate 300
# Use a Specific Network Interface:
-e $INTERFACE
```