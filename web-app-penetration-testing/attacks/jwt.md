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

### Attacking the Signing Secret

- Brute force the signing secret and modify the token.

```shell
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

### Algorithm Confusion

- Algorithm confusion is a JWT attack that forces the web application to use a different algorithm to verify the JWT's signature than the one used to create it.