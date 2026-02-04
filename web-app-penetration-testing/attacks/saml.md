# Secure Assertion Markup Language (SAML) Attacks

- Secure Assertion Markup Language (SAML) is an XML-based standard that enables authentication and authorization between parties and can be used to implement SSO. 
- The data is exchanged in digitally signed XML documents to ensure data integrity.


### SAML Components

- SAML comprises the following components:
    - Identity Provider (IdP): The entity that authenticates users. The IdP provides identity information to other components and issues SAML assertions.
    - Service Provider (SP): The entity that provides a service or a resource to the user. It relies on SAML assertions provided by the IdP.
    - SAML Assertions: XML-based data that contains information about a user's authentication and authorization status.

### SAML Flow

- The user accesses a resource provided by the SP.
- Since the user is not authenticated, the SP initiates authentication by redirecting the user to the IdP with a SAML request.
- The user authenticates with the IdP.
- The IdP generates a SAML assertion containing the user's information, digitally signs the SAML assertion, and sends it in the HTTP response to the browser. The browser sends the SAML assertion to the SP.
- The SP verifies the SAML assertion.
- The user requests the resource.
- The SP provides the resource.


### Signature Exclusion

- If a web application is severely misconfigured, it may skip the signature verification entirely if the SAML response does not contain a signature XML element. This would enable us to manipulate the SAML response arbitrarily.
- To conduct the signature exclusion, we must remove all signatures from the SAML response, which are the `ds:Signature` XML elements.

### Signature Wrapping Attack

- This discrepancy is achieved by injecting XML elements into the SAML response that do not invalidate the signature but potentially confuse the application, resulting in the application using the injected and unsigned authentication information instead of the signed authentication information.
