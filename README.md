# Azure Firewall TLS Inspection Lab

A reproducible Azure lab for testing Azure Firewall Premium TLS inspection with an enterprise certificate authority. The repository combines Bicep infrastructure, certificate automation, validation scripts, and deployment guidance.

> This repository is intended for isolated lab use. Review the templates, costs, access controls, and security settings before deploying anything to an Azure subscription.

## Architecture

The lab uses:

- Azure Firewall Premium for TLS inspection
- Azure Key Vault for certificate storage
- An enterprise certificate authority for issuing the intermediate certificate
- A test client for generating HTTPS traffic
- Virtual networks and routes that send test traffic through the firewall

## Repository Layout

- `main.bicep`: primary infrastructure entry point
- `modules/`: reusable Bicep modules
- `parameters/`: environment-specific deployment parameters
- `scripts/`: deployment, certificate, validation, and reporting automation
- `docs/`: architecture, setup, testing, and troubleshooting guidance

## Prerequisites

- An Azure subscription with permission to deploy the required resources
- Azure CLI
- PowerShell 7 or a compatible shell for the selected scripts
- Bicep tooling
- Familiarity with Azure Firewall, Key Vault, networking, and PKI

## Getting Started

1. Review the Bicep templates and parameter files.
2. Choose unique, non-production resource names and a supported Azure region.
3. Deploy the infrastructure with the documented deployment script or Azure CLI.
4. Configure the certificate authority and store the required certificate in Key Vault.
5. Enable TLS inspection in the firewall policy.
6. Run the validation scripts and review the generated evidence.
7. Remove the lab resources when testing is complete.

See `docs/enterprise-ca-complete-automation-guide.md` for the enterprise CA workflow and `docs/testing-reference.md` for validation guidance.

## Security

- Never commit passwords, tokens, subscription identifiers, public IP addresses, private keys, or live connection details.
- Store local configuration in ignored environment files or an approved secret store.
- Use least-privilege identities and tightly scoped network access.
- Treat generated certificates and deployment evidence as sensitive.
- Rotate any credential that has appeared in Git history, even after removing it from the current branch.
- Do not reuse lab credentials in another environment.

## Validation

Validation should demonstrate:

- Infrastructure deployment succeeds from reviewed templates.
- The firewall policy references the intended Key Vault certificate.
- Test traffic follows the expected route.
- TLS inspection succeeds for the approved test destination.
- Logs and reports contain no credentials or unnecessary environment identifiers.

## Cleanup

Azure Firewall Premium and supporting resources can incur ongoing charges. Delete the lab resource groups and verify that dependent resources are gone after testing.
