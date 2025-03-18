## Same-Origin Policy (SOP)

The same-origin policy (SOP) is a security feature implemented in web browsers to restrict how resources from different origins interact. It prevents a web page from making requests to a different origin and accessing the response unless explicitly permitted.  

- A web page can send requests to other domains.  
- However, it cannot access responses from those domains unless they allow it.  
- This restriction protects users from malicious websites trying to steal data from authenticated sessions.  

---

## Cross-Origin Resource Sharing (CORS)

Cross-Origin Resource Sharing (CORS) is a mechanism that extends the same-origin policy by allowing controlled access to resources from different origins. It uses a set of HTTP headers to define trusted origins.  

> ⚠ CORS is not a security mechanism; it is a relaxation of SOP. It does not prevent cross-origin attacks such as Cross-Site Request Forgery (CSRF) or Cross-Site Scripting (XSS).  

CORS relies on server-defined headers to grant or restrict cross-origin access:  
- `Access-Control-Allow-Origin`: Defines which domains can access resources.  
- `Access-Control-Allow-Credentials`: Determines if cookies or authentication headers are sent.  


## Server-Generated ACAO Header Based on Client-Specified Origin

Some web applications dynamically reflect the client's `Origin` header in the `Access-Control-Allow-Origin` (ACAO) response header. This allows multiple domains to access resources.   

### Request from an attacker-controlled website:  

```http
GET /endpoint HTTP/1.1
Host: vulnerable-website.com
Origin: https://attacker-website.com
Cookie: session=valid-session-cookie
```

### Vulnerable Server Response:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker-website.com
Access-Control-Allow-Credentials: true
```

## Errors in Parsing Origin Headers

Many websites attempt to implement a CORS whitelist, but due to misconfigurations, they remain vulnerable:  

🔹 Regular Expression Mistakes  
- Some websites use regex-based checks, but poor regex patterns can be bypassed.  
- Example: If the whitelist includes `"*.trusted.com"`, an attacker could use `"attacker.trusted.com"`.  

🔹 Prefix/Suffix Matching
- Some servers match only a prefix or suffix, allowing malicious subdomains.  
- Example: Whitelisting `"example.com"` may unintentionally allow `"attack-example.com"`.  


## **Whitelisted `null` Origin Value**  

The `Origin` header can take the special value `null` in certain situations:  

🔹 Cross-origin redirects 
🔹 Requests from `file://` protocol (local files)  
🔹 Sandboxed iframes
🔹 Requests from `data:` URLs or serialized data


## Exploiting XSS via CORS

If a web application allows a vulnerable origin (one with XSS), an attacker can:  

1. Inject JavaScript via XSS on the trusted origin.  
2. Use CORS to steal data from another domain that trusts the vulnerable site.  

## Breaking TLS Security with Poor CORS Configurations

If a secure HTTPS website trusts an HTTP origin, an attacker can downgrade security:  

1. A secure website (`https://secure.com`) allows `http://trusted.com` as a trusted origin.  
2. An attacker intercepts the request and modifies responses on `trusted.com`.  
3. The attacker steals session tokens or injects malicious scripts.  


## CORS Attacks on Intranet Resources

Most CORS-based attacks rely on the victim's browser sending authentication credentials.  
If `Access-Control-Allow-Credentials: false`,

- The victim’s browser won't send cookies, making session-based attacks difficult.  
- But CORS can still be abused in internal networks (intranet attacks).  
