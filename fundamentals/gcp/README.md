# Google Cloud Services Overview

## Categories of Services
- **Compute**: Virtual machines and container hosting.
- **Storage**: Object, block, and file storage options.
- **Big Data**: Tools for processing and analyzing large datasets.
- **Machine Learning**: AI/ML models and services.
- **Application Services**: Platforms for app deployment and scaling.

## Compute Services
- **Compute Engine**: Infrastructure as a Service (IaaS) — provides virtual machines.
- **App Engine**: Platform as a Service (PaaS) — deploy code without managing infrastructure.

## Serverless
- **Cloud Run**: Run containerized applications in a fully managed environment.
- **Cloud Functions**: Execute functions in response to events without managing servers.

## Managed Options
- **Managed Services**: Services where Google handles operations like scaling and patching.
- **Managed Resources**: Resources managed by Google but under user configuration control.

## SaaS
- **Software as a Service**: Complete applications delivered and maintained by Google (e.g., Gmail, Google Docs).

---

# Google Cloud Network Structure

- **Location Hierarchy**:
  - **Location** > **Region** > **Zones**

- **Spanner Multi-Region Configuration**:
  - Cloud Spanner can be deployed across multiple regions and zones for high availability and performance.

---

# Google Security Infrastructure

## Hardware Infrastructure Layer
- Custom hardware design and trusted supply chain.
- Secure boot ensures only verified software runs.
- Physical security at data center premises.

## Service Deployer Layer
- Encrypted communication between services.

## User Identity Layer
- Centralized identity management and authentication.

## Storage Services Layer
- Data encryption at rest and in transit.

## Internet Communication Layer
- Google Front End (GFE) terminates user connections securely.
- DDoS protection systems mitigate external threats.

## Operational Security Layer
- Intrusion detection systems monitor threats.
- Insider risk reduction strategies.
- Employees use U2F for strong authentication.
- Secure software development lifecycle practices.

---

# Google Cloud Observability

- Tools for **logging**, **monitoring**, and **tracing** to gain visibility into cloud infrastructure and services.

---

# Google Cloud Resource Hierarchy

- **Organization Node > Folder > Project > Resources**
  - Resources include VMs, tables, etc.
  - Policies can be applied at Folder, Project, or Resource level.

## Project Metadata
- **Project ID**: Globally unique and immutable.
- **Project Number**: Numeric identifier.
- **Project Name**: Mutable.

## Resource Manager
- Tool used to get, create, and manage projects.

## Folders
- Can contain projects and other folders.

## Organization Node Roles
- **Org Policy Admin**: Manages organization-level policies.
- **Project Creator**: Can create projects.

## Workspace Customers vs Non-Customers
- Additional capabilities may be available to Workspace customers (e.g., advanced admin tools).

---

# Identity and Access Management (IAM)

- Controls **who can do what** on **which resource**.
- 'Who' is called a **principal** and can be:
  - Google account
  - Google group
  - Service account
  - Cloud Identity domain

## Policy Inheritance
- Policies apply to children of the node (e.g., project inherits folder policies).
- **Deny policies** are evaluated first.

## Types of Roles
- **Basic Roles**: Owner, Editor, Viewer, Billing Admin
- **Predefined Roles**: Granular roles like Compute Instance Admin
- **Custom Roles**: Created at the project or organization level

## Service Accounts
- Allow applications (e.g., running in VMs) to access cloud resources securely using assigned permissions.
- Use keys for authentication.

---

## Cloud Identity

- Admins manage users and policies from the admin console.
- Integration with LDAP or Active Directory.
- Enables organization-wide identity and access controls.

---

# Ways to Interact with Google Cloud

1. **Console**: Web interface
2. **Google Cloud SDK**: CLI tools (includes Cloud Shell)
3. **APIs**: REST-based access to resources
4. **Google Cloud App**: Mobile app for basic management

---

# Virtual Private Cloud (VPC)

- Provides a **secure, private** cloud environment inside Google's public cloud.
- Connects cloud resources and the internet.
- Supports **network segmentation**, **firewall rules**, **static routes**.

## Key Concepts
- VPCs are **global**, but subnets are **regional**.
- Resources can exist in different **zones** but still be in the same **subnet**.
- Enables internal communication between instances **without external IPs**.
- **Global distributed firewalls** support rules based on **network tags**.

## Inter-VPC Communication
- Use **VPC Peering** or **Shared VPC** to connect VPCs across projects.

---

# Compute Engine

- Run fully customizable **virtual machines** in Google Cloud.
- **Billing** is per second (minimum 1 minute).
- Supports **autoscaling** and custom configurations.

## Marketplace
- Offers pre-configured VM images and software stacks.

## Discounts
- **Sustained use discounts**: Applied automatically for long-running VMs.
- **Committed use discounts**: Pay upfront for usage commitment to get lower prices.

---

# Preemptible and Spot VMs

- Cost-effective VM options with limited runtime.
- Run for **up to 24 hours**.
- Have fewer features (e.g., no live migration or guaranteed availability).

---

# VPC Compatibility Features

- Built-in routing; no need to define custom routes for internal communication.
- Traffic forwarding possible **across instances**, **zones**, and **regions** in the same network.
- **Firewall rules** are global and tag-based.
- Each VPC is tied to a **project**.
- **Shared VPC** and **VPC peering** allow cross-project communication.

---

# Load Balancing

- **Cloud Load Balancing**: Distributes traffic across multiple backend resources.
- Handles **cross-region** traffic and provides **multi-region failover**.
- Supports both **Layer 4 (TCP/UDP)** and **Layer 7 (HTTP/HTTPS)** traffic.
- **Application Load Balancer** (L7): Acts as a reverse proxy.
  - External (Global or Regional)
  - Internal (Regional or Cross-region)
- **Network Load Balancer** (L4): Can operate in **proxy** or **pass-through** mode.

---

# Google DNS

- Public DNS: `8.8.8.8`
- **Cloud DNS**: Google Cloud’s managed DNS service.
  - Low latency, scalable, highly available.
  - Uses **edge caches** to improve performance.
- **Cloud CDN**: Content Delivery Network integrated with Cloud Load Balancing and Cloud Storage.

---

# Connecting VPC with Other Networks

- **Cloud VPN**: Connects on-premise networks to Google Cloud VPC using VPN with BGP (Border Gateway Protocol).
- **Direct Peering**: Connects through a router in the same datacenter as Google’s PoP.
- **Carrier Peering**: Uses a service provider’s network for direct access.
- **Dedicated Interconnect**: Private, high-speed connection directly to Google; can be backed up by Cloud VPN.
- **Partner Interconnect**: Use a supported service provider for connectivity.
- **Cross-Cloud Interconnect**: Connects Google Cloud to other public cloud providers.

---

# Storage

## Data Types
- **Structured**, **Unstructured**, **Transactional**, **Relational**

## 1. Cloud Storage
- **BLOB object storage**: Store binary + metadata (e.g., images, backups).
- Organized into **buckets**.
- **Immutable** objects with optional versioning.
- Access controlled via **IAM** (preferred) or **ACLs**.
- **Lifecycle policies** for auto-deletion or transition.
- Storage classes:
  - **Standard**: Frequent access
  - **Nearline**: Access ~once/month
  - **Coldline**: Access ~once/90 days
  - **Archive**: Rare access (e.g., yearly)
- Features:
  - **Unlimited** storage
  - **Geo-redundancy**
  - **Global access**
  - **Autoclass**: Automatically optimizes storage class
  - **Transfer Options**: Online transfer, Storage Transfer Service, Transfer Appliance

## 2. Cloud SQL
- Fully managed **relational** database.
- Supports auto-backups, patches, replication.
- Scales to large CPU/RAM/storage configurations.
- Built-in **network firewall** support.
- Internal and external access available.
- Compatible with **Compute Engine**.

## 3. Cloud Spanner
- Globally distributed **relational** DB.
- Horizontal scaling and strong global consistency.
- Designed for high loads.

## 4. Firestore
- Fully managed **NoSQL** document DB.
- Organizes data in **collections and documents**.
- Data is **indexed by default**.
- Real-time sync with devices and **offline caching** support.

## 5. Bigtable
- Fully managed **NoSQL big data** database.
- Designed for **IoT**, **analytics**, and **high-throughput workloads**.
- Supports both **streaming** and **batch** data processing.

---

# Infrastructure as a Service (IaaS)

- Provides **virtual machines** and other compute resources.
- User manages the OS and application stack.

---

# Containers

- Lightweight, isolated environments for running applications.
- Faster deployment, scalability, and resource efficiency.

---

# Kubernetes

- Open-source container orchestration system.
- Automates deployment, scaling, and management of containers.

---

# Google Kubernetes Engine (GKE)

- Managed Kubernetes platform.
- Handles node OS updates, load balancing, and cluster operations.

---

# Cloud Run

- Fully managed platform to run **stateless containers**.
- Built on **Knative**, can also run on **GKE**.
- Supports container-based and source-based (buildpacks) workflows.
- Handles **SSL**, auto-scaling, and high availability.
- **Pay-per-use** billing model.
- Only supports **Linux x64** containers.

---

# Cloud Run Functions

- Event-driven serverless platform.
- Ideal for lightweight functions triggered by events.
- Supports auto-scaling and HTTP-based invocation.
