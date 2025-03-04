# WEP (Wired Equivalent Privacy)

- The original WiFi security protocol, WEP, provides basic encryption but is now considered outdated and
insecure due to vulnerabilities that make it easy to breach.
- Encryption: RC4
- Message Integrity: CRC-32


## Authentication with WEP

- Authentication request: Initially, the client sends the access point an authentication request.
- Challenge: The access point then responds with a custom authentication response which includes challenge text for the client.
- Challenge Response: The client then responds with the encrypted challenge, which is encrypted with the WEP key.
- Verification: The AP then decrypts this challenge and sends back either an indication of success or failure.