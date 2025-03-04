## IEEE 802.11

### IEEE 802.11 MAC Frame

- All 802.11 frames utilize the MAC frame. This frame is the foundation for all other
fields and actions that are performed between the client and access point.

- The MAC data frame consists of 9 fields:

    - Frame Control: This field contains information such as type, subtype, protocol version, to ds
     (distribution system), from DS, Order, etcetera.
    - Duration/ID: This ID clarifies the amount of time in which the wireless medium is occupied.
    - Address 1, 2, 3, and 4: These fields clarify the MAC addresses involved in the communication, 
    but they could mean different things depending on the origin of the frame. These tend to include
    the BSSID of the access point and the client MAC address, among others.
    - SC: The sequence control field allows additional capabilities to prevent duplicate frames.
    - Data: Simply put, this field is responsible for the data that is transmitted from the sender to the receiver.
    - CRC: The cyclic redundancy check contains a 32-bit checksum for error detection.


### IEEE 802.11 Frame Types

- IEEE frames can be put into different categories for what they do and what actions they are involved in:

    - Management (00): These frames are used for management and control, and allowing the access point and 
    client to control the active connection.
    - Control (01): Control frames are used for managing the transmission and reception of data frames 
    within wi-fi networks. We can consider them like a sense of quality control.
    - Data (10): Data frames are used to contain data for transmission.


### Connection Cycle

- The typical connection process between clients and access points, known as the connection cycle.
- The general connection cycle of WPA2 follows this sequence:

    - Beacon frames from the access point:
    ```
    (wlan.fc.type == 0) && (wlan.fc.type_subtype == 8)
    ```

    - Probe request frames:
    ```
    (wlan.fc.type == 0) && (wlan.fc.type_subtype == 4)
    ```

    - Probe response frames from the access point:
    ```
    (wlan.fc.type == 0) && (wlan.fc.type_subtype == 5)
    ```

    - The authentication process between the client and the access point:
    ```
    (wlan.fc.type == 0) && (wlan.fc.type_subtype == 11)
    ```

    - After the authentication process is complete, the station's association request:
    ```
    (wlan.fc.type == 0) && (wlan.fc.type_subtype == 0)
    ```

    - The access point's association response:
    ```
    (wlan.fc.type == 0) && (wlan.fc.type_subtype == 1)
    ```

    - Once the connection process is complete, the termination of the connection can be viewed by
     identifying which party (client or access point) initiated the disconnection.
    ```
    (wlan.fc.type == 0) && (wlan.fc.type_subtype == 12) or (wlan.fc.type_subtype == 10)
    ```


## WiFi Authentication

- There are two primary authentication systems used in WiFi networks:
    - Open System Authentication
    - Shared Key Authentication


### Open System Authentication

- Open system authentication does not require any shared secret or credentials right away.
- This authentication type is commonly found for open networks that do not require a password. 
- For Open System Authentication, it tends to follow this order:

    - The client (station) sends an authentication request to the access point to begin the authentication process.
    - The access point then sends the client back an authentication response, which indicates whether the authentication was accepted.
    - The client then sends the access point an association request.
    - The access point then responds with an association response to indicate whether the client can stay connected.


### Shared Key Authentication Types

- Shared key authentication does involve a shared key
- In this authentication system, the client and access point prove their identities through the computation of a challenge.
- Following are the types of wifi Shared Key Authentication:

    - WEP:
    - WPA
    - WPA2
        - WPA2-PSK/WPA2-Personal
        - WPA2 Enterprise (EAP-TTLS, PEAP-MSCHAPv2 AND EAP-TLS)
    - WPA3
        - WPA3-SAE/WPA3-Personal
        - WPA3 Enterprise (EAP-TLS)


**WEP (Wired Equivalent Privacy):**

- The original WiFi security protocol, WEP, provides basic encryption but is now considered outdated and
insecure due to vulnerabilities that make it easy to breach.
- Encryption: RC4
- Message Integrity: CRC-32


**WPA (WiFi Protected Access):**

- An improvement over WEP, WPA offers better encryption through TKIP (Temporal Key Integrity Protocol),
but it is still less secure than newer standards.
- Encryption: WEP with TKIP
- Message Integrity: MIC


**WPA2 (WiFi Protected Access II):**

- An advancement over WPA. It has been the standard for many years, providing strong protection for most networks.
- Encryption: AES
- Message Integrity: CCM


**WPA3 (WiFi Protected Access III):**

- The latest standard, WPA3, enhances security with features like individualized data encryption and more robust
password-based authentication, making it the most secure option currently available.