# Azure Firewall TLS Inspection Testing Reference

Use the scripts in `scripts/` to validate the lab without storing connection details in the repository.

## Automated Checks

- `remote-test-suite.sh`: runs the remote infrastructure and TLS checks.
- `quick-tls-test.sh`: checks the firewall, certificate, and client HTTPS path.
- `test-tls-inspection.sh`: prints a compact resource summary and manual validation sequence.

Run each script from an authenticated Azure CLI session. Select the intended subscription before running a check:

```bash
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
./scripts/quick-tls-test.sh
```

## Manual Validation

1. Resolve current VM connection information from Azure rather than documentation.
2. Retrieve credentials from the approved secret store.
3. Connect from an allowed source network.
4. Browse to an approved HTTPS test destination.
5. Inspect the certificate chain for the lab certificate authority.
6. Confirm matching Azure Firewall application-rule logs.

## Expected Evidence

- Azure Firewall Premium is provisioned successfully.
- The Key Vault certificate exists and is enabled.
- The firewall policy references the intended certificate authority.
- The client can reach the approved HTTPS destination through the expected route.
- The observed certificate chain and firewall logs demonstrate inspection.

## Security

Never record passwords, private keys, subscription identifiers, public addresses, or live connection details in this repository or generated reports. Rotate any value that was previously committed.
