# HTTP Verb Tampering

- HTTP verb tampering involves manipulating the HTTP methods used in requests to bypass security measures.
- Web servers typically support several HTTP methods:
`HEAD`, `PUT`, `POST`, `GET`, `DELETE`, `OPTIONS`, `PATCH`, `TRACE`, `CONNECT`

1. Security Filters Bypass:
    - Insecure coding practices can lead to security vulnerabilities. For instance, a developer might secure
    a specific method (e.g., `GET`) against SQL Injection (SQLi) but neglect others like `POST`.
    - Attackers can exploit this oversight by using a different HTTP method to bypass security checks and perform
    malicious actions such as SQLi.

2. Bypassing Access Controls:
    - HTTP verb tampering can be used to bypass `401 Unauthorized` and `403 Forbidden` responses if security
    controls are improperly implemented across different HTTP methods.

3. Bypassing Basic HTTP Authentication:
    - Changing the HTTP request method can sometimes bypass basic authentication mechanisms, further highlighting
    the risks of insecure handling of HTTP methods.

- While automated security tools can detect issues arising from insecure server configurations, they often
miss vulnerabilities caused by poor coding practices.
- Manual testing is essential to uncover these verb-based vulnerabilities, especially those that automated tools might overlook.
- Check [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/403-and-401-bypasses.html)
for more methods.