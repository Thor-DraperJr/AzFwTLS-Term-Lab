# Multi-Region Azure Firewall TLS Inspection Lab Strategy

The secondary region supports lab capacity, cross-region routing tests, certificate distribution exercises, and recovery planning.

## Architecture

- The primary region hosts Azure Firewall Premium, its policy, Key Vault, and the hub virtual network.
- The secondary region hosts the certificate authority and test client workloads.
- Peering and route tables direct approved test traffic through the firewall.

## Validation Scenarios

1. Verify cross-region routing through Azure Firewall.
2. Measure latency and throughput for inspected traffic.
3. Validate certificate issuance, storage, and trust across regions.
4. Exercise recovery procedures without using production resources.

## Connection Data

Resolve current resource addresses with Azure CLI and retrieve credentials from an approved secret store at runtime. Do not store environment identifiers or credentials in this document.

## Operational Notes

- Keep both regions isolated from production networks.
- Restrict management access to approved source addresses.
- Record sanitized evidence only.
- Delete resources when the lab is no longer in use.
