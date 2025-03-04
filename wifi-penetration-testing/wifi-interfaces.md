# Wi-Fi Interfaces

- Wireless interfaces are a cornerstone of wi-fi penetration testing. Our machines transmit
and receive this data through these interfaces.

## How to Choose the Right Interface for the Job

- We should look for the following in our interface:

    1. IEEE 802.11ac or IEEE 802.11ax support
    2. Supports at least monitor mode and packet injection

- Not all interfaces are equal when it comes to wi-fi penetration testing. 
- Not all operating systems have complete support for each card
- The chipset of a Wi-Fi card and its driver are crucial factors in penetration testing.


## Interface Strength

- The card should be strong enough to operate at larger ranges.
- The range of wifi card are mostly set according to the country 
specified in our OS.
- We can check on this with the `iw reg get` command in Linux.
- Most of the time, this might be `DFS-UNSET`, which is not helpful for us since it limits our cards to `20 dBm`.

**Chaning the Region Settings for our Interface**

```shell
# Changing region
sudo iw reg set US

# Set interface to its max power
sudo ifconfig wlan0 down
sudo iwconfig wlan0 txpower 30
sudo ifconfig wlan0 up
```

**Note**:

```

- The default TX power of a wireless interface is typically 
set to 20 dBm.

- It can be increased to 30 dBm using certain methods (may be
illegal in some countries). 

- Some wireless models may not support these settings

- The TX power of the wireless interface can be modified using 
the above commands.

- In certain instances, this change may not take effect, which 
could indicate that the kernel has been patched to prevent such
modifications.

# Checking driver capabilities for our interface
iw list

```


### Scanning Available WiFi Networks

```shell
# Scan available wifi networks
iwlist wlan0 scan |  grep 'Cell\|Quality\|ESSID\|IEEE'

# Changing Channel of interface
sudo ifconfig wlan0 down
# Channel 64 operates at a frequency of 5.32 GHz
sudo iwconfig wlan0 channel 64
sudo ifconfig wlan0 up

# View channel of interface
iwlist wlan0 channel

# Changing frequency  of interface
sudo ifconfig wlan0 down
sudo iwconfig wlan0 freq "5.52G"
sudo ifconfig wlan0 up

# View frequency of interface
iwlist wlan0 frequency | grep Current
```

### Connecting to WiFi Networks

- Connecting to WEP Network

```shell
# Create a conf file
network={
	ssid="name"
    key_mgmt=NONE
    wep_key0=key
    wep_tx_keyidx=0
}

# Connect using wpa_supplicant
sudo wpa_supplicant -c wep.conf -i wlan0
```

- Connecting to WPA Personal and Enterprise Networks

```shell
# Create a configuration file
# WPA Personal
network={
	ssid="name"
    psk="password"
}

# WPA Enterprise
network={
  ssid="name"
  key_mgmt=WPA-EAP
  identity="username"
  password="password"
}

# Connect using wpa_supplicant
sudo wpa_supplicant -c wpa.conf -i wlan0
```

- Obtain IP address by using `dhclient` utility.

```shell
# Kill any old client process
sudo dhclient wlan0 -r
# Obtain IP address
sudo dhclient wlan0 
```

## Interface Modes

### Managed Mode

- Managed mode is when we want our interface to act as a client or a station.
- This mode allows us to authenticate and associate to an access point. 
- In this mode, our card will actively search for nearby networks (APs) to 
which we can establish a connection.
- This is mostly the default mode of our interface.

```shell
# Setup managed mode
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode managed
sudo ifconfig wlan0 up

# Connect to a network
sudo iwconfig wlan0 essid network_name
```

### Ad-hoc Mode

- This mode is peer to peer and allows wireless interfaces to communicate directly to one another.
- Their band that is utilized for AP-to-AP communications and range extension.
- This mode is not extender mode, as in most cases that is actually two interfaces bridged together.

```shell
# Setup Ad-hoc mode
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode ad-hoc
sudo ifconfig wlan0 up
```

### Master Mode

- The opposite of managed mode is master mode (access point/router mode).
- We act as Access point.
- We can set this mode through management daemon. 
- Management daemon is responsible for responding to stations or clients connecting to our network.

```shell
# Create a conf file
nano open.conf

# Write this data in it this will
# bring up an open network
interface=wlan0
driver=nl80211
ssid=network_name
channel=2
hw_mode=g

# Start the open network
sudo hostapd open.conf
```


### Mesh Mode

- Mesh Mode is a special operating mode for Wi-Fi interfaces that allows devices to form
 a self-configuring, self-healing network without requiring a traditional (AP)-client relationship.
- In Mesh Mode, Wi-Fi devices act as mesh nodes that communicate with each other directly.
- There is no need for a central router—each node can route traffic dynamically.
- If a node fails, the network automatically finds an alternative path (self-healing).
- The entire network operates as a single SSID.

```shell
# Setup mesh mode
sudo iw dev wlan0 set type mesh
```


### Monitor Mode

- Monitor mode, also known as promiscuous mode, is a specialized operating mode for wireless network interfaces.
- In this mode, the network interface can capture all wireless traffic within its range, regardless of the intended recipient.

```shell
sudo ifconfig wlan0 down
sudo iw wlan0 set monitor control
sudo ifconfig wlan0 up
```