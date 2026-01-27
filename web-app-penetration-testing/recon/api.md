# API Attacks

- OWASP Top 10 for APIs: [https://owasp.org/www-project-api-security](https://owasp.org/www-project-api-security/)


### API Recon

- Try to Fuzz all API endpoints and craft HTTP requests by fuzzing the required parameters.
- Find API documentation endpoints. You can use [OpenAPI Parser](https://portswigger.net/bappstore/6bf7574b632847faaaa4eb5e42f1757c)

```txt
/api
/api/swagger
/api/swagger/v1
/swagger/index.html
/openapi.json
```

- You can also gather a lot of information by browsing applications that use the API. This is often worth doing even if you have access to API documentation, as sometimes documentation may be inaccurate or out of date.
- You can use Burp Scanner to crawl the application, then manually investigate interesting attack surface using Burp's browser.
- Burp Scanner automatically extracts some endpoints during crawls, but for a more heavyweight extraction, use the [JS Link Finder BApp](https://portswigger.net/bappstore/0e61c786db0c4ac787a08c4516d52ccf).
- API endpoint may support different HTTP methods. It's therefore important to test all potential methods when you're investigating API endpoints.
- Changing the content type may enable you to:
    - Trigger errors that disclose useful information.
    - Bypass flawed defenses.
    - Take advantage of differences in processing logic. For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML.
    - Use [Content Type Converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278)
- Find hidden parameters:
    - Use ffuf or burp intruder for fuzzing params
    - Use [Param Miner BApp](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)
    - Use [Content Discovery tool](https://portswigger.net/burp/documentation/desktop/tools/engagement-tools/content-discovery) to discover content that isn't linked from visible content that you can browse to, including parameters.