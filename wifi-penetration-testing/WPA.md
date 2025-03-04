# WPA (WiFi Protected Access)

- An improvement over WEP, WPA offers better encryption through TKIP (Temporal Key Integrity Protocol),
but it is still less secure than newer standards.
- Encryption: WEP with TKIP
- Message Integrity: MIC

## Authentication with WPA

- Authentication Request: The client sends an authentication request to the AP to initiate the authentication process.
- Authentication Response: The AP responds with an authentication response, which indicates that it is ready to proceed with authentication.
- Pairwise Key Generation: The client and the AP then calculate the PMK from the PSK (password).
- Four-Way Handshake: The client and access point then undergo each step of the four way handshake, which involves nonce exchange, derivation, among other actions to verify that the client and AP truly know the PSK.