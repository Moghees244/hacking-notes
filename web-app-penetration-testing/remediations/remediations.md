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