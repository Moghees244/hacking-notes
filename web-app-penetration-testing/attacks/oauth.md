# OAuth Vulnerabilities

- OAuth is a standard that enables secure authorization between services and applications. As such, OAuth is commonly used in Single Sign-On (SSO) scenarios, enabling users to log in to a single service to access multiple different services. OAuth achieves this without sharing the user's credentials between services.


## How does OAuth work?

There are 3 parties involved in OAuth authentication:

- Client application: The website or web application that wants to access the user's data.
- Resource owner: The user whose data the client application wants to access.
- OAuth service provider: The website or application that controls the user's data and access to it.
- Resource Server: The server hosting the resources the client requests to access

> Note that it is not required for these entities to be physically separate. For instance, the authorization and resource servers may be the same system.

- There are numerous different ways that the actual OAuth process can be implemented. These are known as OAuth "flows" or "grant types". 

- The grant types involve the following stages:

    - The client application requests access to a subset of the user's data, specifying which grant type they want to use and what kind of access they want.
    - The user is prompted to log in to the OAuth service and give their consent for the requested access.
    - The client application receives an access token that proves they have permission.
    - The client application uses this access token to make API calls fetching the relevant data from the resource server.

## Identifying OAuth Authentication

- If you see an option to log in using your account from a different website, this is a strong indication that OAuth is being used.
- Regardless of which OAuth grant type is being used, the first request of the flow will always be a request to the `/authorization` endpoint containing a number of query parameters that are used specifically for OAuth which include `client_id, redirect_uri, response_type parameters`. 


## Recon

- If an external OAuth service is used, you should be able to identify the specific provider from the hostname to which the authorization request is sent.
- Once you know the hostname of the authorization server, try sending a `GET` request to the following standard endpoints:

```shell
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```

- These will often return a JSON configuration file containing key information.

## Exploiting OAuth authentication vulnerabilities

- Vulnerabilities can arise in the client application's implementation of OAuth as well as in the configuration of the OAuth service itself.


### Vulnerabilities in the OAuth client application

- Client applications will often use a reputable, battle-hardened OAuth service that is well protected against widely known exploits. However, their own side of the implementation may be less secure.


**Improper implementation of the implicit grant type**

- In Implicit grant type, the access token is sent from the OAuth service to the client application via the user's browser as a URL fragment. 
- The client application then accesses the token using JavaScript. 
- If the application wants to maintain the session after the user closes the page, it needs to store the current user data normally a user ID and the access token.

- To solve this problem, the client application will often submit this data to the server in a `POST` request and then assign the user a session cookie.
- This request is roughly equivalent to the form submission request that might be sent as part of a classic, password-based login.
- However, in this scenario, the **server does not have any secrets or passwords to compare with the submitted data**, which means that it is implicitly trusted.

- This POST request is exposed to attackers via their browser. This behavior can lead to a serious vulnerability if the client application doesn't properly check that the access token matches the other data in the request. 
- In this case, an attacker can simply change the parameters sent to the server to impersonate any user.

**Flawed CSRF protection**

- The `state` parameter should ideally contain an unguessable value, such as the hash of something tied to the user's session when it first initiates the OAuth flow.
- This value is then passed back and forth between the client application and the OAuth service as a form of CSRF token for the client application. 
- Therefore, if you notice that the authorization request does not send a state parameter, this is extremely interesting from an attacker's perspective.
- It potentially means that they can initiate an OAuth flow themselves before tricking a user's browser into completing it, similar to a traditional CSRF attack. This can have severe consequences depending on how OAuth is being used by the client application.

- Consider a website that allows users to log in using either a classic, password-based mechanism or by linking their account to a social media profile using OAuth.
- In this case, if the application fails to use the state parameter, an attacker could potentially hijack a victim user's account on the client application by binding it to their own social media account.


### Vulnerabilities in the OAuth service

**Leaking authorization codes and access tokens**

- A request is sent from the client to /auth endpoint containing client_id (client application) and 
redirect_uri.
- If the OAuth service doesnot validate redirect_uri properly, the attackers might be able to perform
CSRF attack and redirect the response containing the code to their own website.
- The code can then be used to takeover the account.

- Note that sometimes, OAuth service validated redirect_uri through  a whitelist. In this case we can
try to bypass the whitelist filter by trying different methods like: [bypassing SSRF defences](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses), [server side parameter pollution](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution) etc.
