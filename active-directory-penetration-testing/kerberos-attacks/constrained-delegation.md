
- Constrained delegation is more restrictive type of delegation. 
- In this, a service has the right to impersonate a user to a well-defined list of services.
- While configuring, the `Trust this computer for delegation to specified services only` option should be chosen.
- A list of services allowed for delegation is stored in the `msDS-AllowedToDelegateTo` attribute of the service account in charge of the delegation.

## How it Works

- If the service account wishes to authenticate to a resource on behalf of the user, it must make a special TGS request to the domain controller.
- Two fields will be modified compared to a classic TGS request.

    - The additional tickets field will contain a copy of the TGS ticket or Service Ticket the user sent to the service.
    - The cname-in-addl-tkt flag will be set to indicate to the Domain Controller that it should not use the server information but the ticket information in additional tickets.
- The Domain Controller will then verify that the service has the right to delegate authentication to the requested resource and that the copy of the TGS ticket or Service Ticket is `forwardable`.

## S4U2Proxy

- Service for User to Proxy (S4U2proxy) allows a service to obtain a service ticket on behalf of a user to a different service (e.g. an HTTP service requesting a service ticket to the MSSQLSvc service).  This is known as "constrained delegation".

## S4U2Self

- Service for User to Self (S4U2self) This allows a service to obtain a service ticket on behalf of a user to itself.
- This is intended to be used when a user authenticates to the service in a way other than Kerberos.
- The service can perform an S4U2self to get a service ticket for the user as though they did authenticate using Kerberos, and then use that with S4U2proxy to get a service ticket for another service. This is known as "protocol transition".

- If the `Use Kerberos only` option is chosen, then the service account cannot do protocol transition, therefore, cannot use the S4U2Self extension.
- On the other hand, if the `Use any authentication protocol` option is set, then the service account can use the S4U2Self extension and, therefore, can create a TGS ticket for an arbitrary user.



# GOT MESSY
# HTB have missing details so use CRTO for reference in future
