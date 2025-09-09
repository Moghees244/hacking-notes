# Security

Google cloud security services:
- Cloud Identity
- Google Cloud Directory Sync
- Managed Microsoft Active Directory
- Identity Platform


## IDaaS
- Identity as a service solution
- Provides admin console to manage users, groups and domain wide security settings
- Tied to unique DNS domain this is enabled for receiving emails.
- Upto 600 domains can be associated with your organizations google account.
- admin.google.com is admin console
- standalone and combined with workspace services
- We can create free acccount if we dont use workspace services


## Google Cloud Directory Sync
- Syncs google workspace with AD or LDAP
- Following are the steps:
    - Data is exported from LDAP server or AD
    - GCDS connects to google domain and generates list of users, groups and shared contacts that you specify.
    - GCDS compares list and updated google domain to match data.
    - Once done, report is emailed.
- Only performs one way sync
- Auto provision and deprovision.


## Managed MS Active Directory
- Runs actual MS AD controllers
- Is virtually maintainance free
- Support both hybrid and standalone cloud domain
- Tools liks group policy and RSAT
- Flexible and multi regional


## Google Auth & SSO
- Google auth is primary for google cloud


## Identity Platform
- Customer identity and access management system
- add iam to apps etc
- google auth integrated with your products


Tips:
- Manage groups instead of individual users
- Have atleast 2 org admins
- By default, all users are granted project creator and billing account creator roles. Manager it


## IAM

### Resource Manager
- Can manage access controls on organization, folders, projects, resources, memebers and roles
- Role or permission on a folder means on all projects under the folder

### IAM Roles
- Three types of roles: Basic, Predefined, Custom
- Three types of basic roles: Owner + Billing Owner, Editor, Viewer

### Service Accounts
- Control service to service interaction:
    - Auth from one service to another
    - Control privs used by resources
- Two types of service accounts:
    - Google managed (cant view or access them directly, public key can be used for max 2 weeks, google rotates them)
    - User Managed (create upto 100 in a project)
- Use RSA keys for auth. Create jwt bearer and get access token.
- Having access to RSA key is like knowing the password.
- User can create upto 10 keys per account. (They dont expire but should be rotated)

### Workload Identity Federation
- Grant apps running outside google cloud access to data without service account keys.
- Uses temporary creds or tokens
- Steps:
    - Create a worload identity pool in project. (no superadmin privs needed)
    - Project can have mulitple pool.
    - Create an IAM policy that allows identities in worload identity pool to impersonate service accounts.
    - You can control permissions granted to identities.
    - App connects to identity pool and gets creds.
    - App calls security token service and gets shortlived google cloud access token.
    - Use token to impersonate service account and access resources.

### IAM & Organization Policies
- Policy is set of roles and role members attached to a resource.
- Resources inherit policies from parents.
- Rosource policies are union of parent and resource policies.
- Less restrictive parent policy overwrites more retrictive resource policy. (allow policies)
- Deny policy overrides access policy.
- Org policy gives you centralized control over organizations cloud resources.

### Policy Intelligence
- Helps to inderstand and improve policies for better security.

Tips:
- Use principal of least prvilege