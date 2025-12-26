# Parameter Pollution

- Server-side parameter pollution occurs when a website embeds user input in a server-side request to an internal API without adequate encoding. This means that an attacker may be able to manipulate or inject parameters, which may enable them to:

    - Override existing parameters
    - Modify the application behavior
    - Access unauthorized data

- This vulnerability is sometimes called HTTP parameter pollution. However, this term is also used to refer to a web application firewall (WAF) bypass technique.


## Detection

- To test for server-side parameter pollution in the query string, place query syntax characters like `#`, `&`, and `=` in your input and observe how the application responds.

### Truncating Query Strings

- You can use a URL-encoded `#` character to attempt to truncate the server-side request. To help you interpret the response, you could also add a string after the `#` character.

```shell
# For example, you could modify the query string to the following:
GET /userSearch?name=peter%23foo&back=/home

# The front-end will try to access the following URL:
GET /users/search?name=peter#foo&publicProfile=true

# Review the response for clues about whether the query has been truncated.
# For example, if the response returns the user peter, the server-side query
# may have been truncated. If an Invalid name error message is returned, the 
# application may have treated foo as part of the username. This suggests that
# the server-side request may not have been truncated.
```

### Injecting invalid parameters

- Use an URL-encoded `&` character to attempt to add a second parameter to the server-side request.

```shell
# For example, you could modify the query string to the following:
GET /userSearch?name=peter%26foo=xyz&back=/home

# This results in the following server-side request to the internal API:
GET /users/search?name=peter&foo=xyz&publicProfile=true

# Review the response for clues about how the additional parameter is parsed.
# For example, if the response is unchanged this may indicate that the parameter
# was successfully injected but ignored by the application.
```

- If you're able to modify the query string, you can then attempt to add a second `valid parameter` to the server-side request.

### Overriding existing parameters

- Try to override the original parameter. Do this by injecting a second parameter with the same name.

```shell
GET /userSearch?name=peter%26name=carlos&back=/home

# This results in the following server-side request to the internal API:
GET /users/search?name=peter&name=carlos&publicProfile=true
```

- The internal API interprets two name parameters. The impact of this depends on how the application processes the second parameter.
- This varies across different web technologies. For example:

> PHP parses the last parameter only. This would result in a user search for carlos.
> ASP.NET combines both parameters. This would result in a user search for peter,carlos, which might result in an Invalid username error message.
> Node.js / express parses the first parameter only. This would result in a user search for peter, giving an unchanged result.

- If you're able to override the original parameter, you may be able to conduct an exploit.
- For example, you could add name=administrator to the request. This may enable you to log in as the administrator user.

### Pollution in REST APIs

- A RESTful API may place parameter names and values in the URL path, rather than the query string.
- An attacker may be able to manipulate server-side URL path parameters to exploit the API. To test for this vulnerability, add path traversal sequences to modify parameters and observe how the application responds.

```shell
# You could submit URL-encoded peter/../admin as the value of the name parameter:
GET /edit_profile.php?name=peter%2f..%2fadmin

#This may result in the following server-side request:
GET /api/private/users/peter/../admin
# If the server-side client or back-end API normalize this path, 
# it may be resolved to /api/private/users/admin.
```

### Polluting Structured Data Formats

- An attacker may be able to manipulate parameters to exploit vulnerabilities in the server's processing of other structured data formats, such as a JSON or XML.
- To test for this, inject unexpected structured data into user inputs and see how the server responds.

```shell
# Consider an application that enables users to edit their profile
POST /myaccount
name=peter

#This results in the following server-side request:
PATCH /users/7312/update
{"name":"peter"}

#You can attempt to add the access_level parameter to the request as follows:
POST /myaccount
name=peter","access_level":"administrator

# This may result in the user peter being given administrator access.
```

- Use tools like param miner to find hidden parameters.

### Automated Tools

- Burp Scanner automatically detects suspicious input transformations when performing an audit.
- You can also use the Backslash Powered Scanner BApp to identify server-side injection vulnerabilities. [Link](https://portswigger.net/research/backslash-powered-scanning-hunting-unknown-vulnerability-classes)