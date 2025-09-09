# Google Cloud Networking

## VPC Networks
- Virtual version of physical network.
- connects VMs
- builtin internal passthoriugh load balancers and proxy for internal app load balancers
- distributes traffic from external load balancers to backends
- Porjects can have multiple VPCs
- New projects start with default network and one subnet in each region.
- Better to make custom network.

- Use an internal IP to communicate within network.
- Use external IP to communicate accross networks.

## Firewalls
- Firewalls rules can be applied in following ways:
    - All instances in network
    - instances with specific tags
    - Instances using specific account
- Rules are stateful
- Rules with low priority number has higher priority.
- If there are rules with same priority, deny rule overrides the other.

Tips:
- Use model of least privilege
- Develop standard namming convention for firewall rules.
- Consider service account firewall rules instead of tag based rules.

### Load Balancing & SSL
### VPC Peering
### VPC Service Controls
### Private Google API Access
### Access Context Manager
### VPC Flow Logs
### Cloud IDS
