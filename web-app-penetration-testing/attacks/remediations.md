# Remediations

## HTTP Verb Tampering

- always allow/deny all HTTP verbs and methods.
- If we want to specify a single method, we can use safe keywords, like LimitExcept in Apache, http-method-omission in Tomcat, and add/remove in ASP.NET, which cover all verbs except the specified ones.
- Finally, to avoid similar attacks, we should generally consider disabling/denying all HEAD requests unless specifically required by the web application
- To avoid HTTP Verb Tampering vulnerabilities in our code, we must be consistent with our use of HTTP methods and ensure that the same method is always used for any specific functionality across the web application.


## SQL Injection

- User Input Sanitization
- Input Validation
- We should ensure that the user querying the database only has minimum permissions.
- Parameterized Queries (Prepared statements)


## Cross Origin Resource Sharing Attacks

- The origin should be properly specified in the `Access-Control-Allow-Origin` header. 
- Avoid whitelisting `null` origin.
- Avoid wildcards in internal networks.
- Web servers should continue to apply protections over sensitive data, such as authentication and session management, in addition to properly configured CORS. 


## XPath Injection

- Proper (manual) sanitization is the only universal method of preventing XPath injection vulnerabilities.
- The simplest and most secure way is to implement a whitelist that only allows alphanumeric characters in the user input inserted into the XPath query.
- Additionally, verifying the expected data type and format when performing sanitization is crucial. If the web application expects an integer, it must verify that the user input consists of only digits.

## LDAP Injection

- Remove parenthesis, asterisk, backslash and null byte from the user input.
- Use pre defined ldap escape functions is available.
- Give the account used to bind to the DS the least privileges required to perform the search operation for our specific task.
- When using LDAP for authentication, it is more secure to perform a bind operation with the credentials provided by the user, rather than performing a search operation.

## PDF Generation Exploits

- Many PDF generation libraries default to a configuration that allows access to external resources. Setting this option to false effectively prevents SSRF vulnerabilities. In the DomPDf library, this option is called enable_remote.
- The DomPDF library has a configuration option called isPhpEnabled that enables PHP code execution; this option should be disabled because it's a security risk.
- HTML-entity encoding the user input.
- JavaScript code should not be executed under any circumstances.
- Access to local files should be disallowed.
- Access to external resources should be disallowed or limited if it is required.

## NoSQL Injection

- If the web app framework is weakly typed, Cast the user input to strings to avoid anything arrays being passed.
- Implement input validation.
- According to the developers of MongoDB, you should only use $where if it is impossible to express a query any other way.
- If you don't use any queries which evaluate JavaScript in your project, then a good idea would be to completely disable server-side JavaScript evaluation, which is enabled by default.