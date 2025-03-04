# WPA (WiFi Protected Access)

- An improvement over WEP, WPA offers better encryption through TKIP (Temporal Key Integrity Protocol),
but it is still less secure than newer standards.
- Encryption: WEP with TKIP
- Message Integrity: MIC

## Authentication with WPA

- **Authentication Request:** The client sends an authentication request to the AP to initiate the authentication process.
- **Authentication Response:** The AP responds with an authentication response, which indicates that it is ready to proceed with authentication.
- **Pairwise Key Generation:** The client and the AP then calculate the PMK from the PSK (password).
- **Four-Way Handshake:** The client and access point then undergo each step of the four way handshake, which involves nonce exchange, derivation, among other actions to verify that the client and AP truly know the PSK.


### PMK (Pairwise Master Key) Calculation Process:
1. Inputs:
   - PSK (Password)
   - SSID
   - SSID Length

2. Derivation Function:
   The PMK is generated using PBKDF2-HMAC-SHA1:
   
   ```plaintext
   PMK = PBKDF2-HMAC-SHA1(PSK, SSID, SSID_LENGTH, 4096, 256 bits)
   ```
   - PBKDF2: A password-based key derivation function.
   - HMAC-SHA1: A hashing function used in the process.
   - 4096 iterations: Strengthens security by making brute-force attacks harder.
   - 256-bit key output: The resulting PMK is 256 bits (32 bytes) long.

3. Usage of PMK:
   - The **PMK** is then used in the **4-way handshake** to generate session keys.
   - These session keys secure the communication between the **Client (Supplicant)**
    and the **Access Point (Authenticator)**.
