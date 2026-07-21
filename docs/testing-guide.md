# Azure Firewall TLS Inspection Testing Guide

This guide assumes the lab infrastructure is deployed and the operator has selected the intended Azure subscription.

## Before Testing

1. Confirm Azure CLI authentication with `az account show`.
2. Retrieve VM and certificate credentials from the approved secret store.
3. Restrict management access to your current source network.
4. Confirm the test resources are isolated from production.

## Configure The Certificate Authority

Use `ca-quick-setup.ps1` or the enterprise CA automation documented in `enterprise-ca-complete-automation-guide.md`. Pass the PFX password as a runtime `SecureString`; never place it in a command file, parameter file, or repository document.

## Upload The Certificate

Set the PFX password only in the local process environment, run the upload helper, and clear it afterward:

```bash
read -s -p "PFX password: " PFX_PASSWORD
export PFX_PASSWORD
./scripts/upload-certificates.sh
unset PFX_PASSWORD
```

## Validate

```bash
./scripts/quick-tls-test.sh
./scripts/remote-test-suite.sh
```

For a manual check, obtain the current client address from Azure, connect with a credential from the approved secret store, browse to an approved HTTPS destination, inspect the certificate chain, and confirm the matching firewall log entry.

## Success Criteria

- The certificate is enabled in Key Vault.
- The firewall policy references the expected certificate authority.
- Test traffic follows the expected route.
- The client trusts the lab root certificate.
- The observed certificate chain and firewall logs demonstrate TLS inspection.

Remove the resources after testing to stop charges and reduce exposure.
