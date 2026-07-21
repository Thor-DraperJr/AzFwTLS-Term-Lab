# Enterprise CA Automation Reference

The former end-to-end automation passed certificate passwords through embedded
scripts and Azure VM Run Command. Those wrappers are retired because command
parameters and logs are not appropriate secret channels.

## Supported flow

1. Resolve resource names from Azure at runtime.
2. Export the certificate with `ca-quick-setup.ps1` or
   `ca-simple-setup.ps1`, supplying `-PfxPassword` as a `SecureString`.
3. Set `PFX_PASSWORD` only in the local process environment.
4. Run `scripts/upload-certificates.sh`.
5. Remove `PFX_PASSWORD` from the environment and delete temporary certificate
   artifacts after validation.

Example:

```bash
export RESOURCE_GROUP="rg-azfw-tls-lab"
export RESOURCE_GROUP_WEST="rg-azfw-tls-lab-west"
export CERTIFICATE_NAME="azure-firewall-intermediate-ca"

read -rsp "PFX password: " PFX_PASSWORD
echo
export PFX_PASSWORD
./scripts/upload-certificates.sh
unset PFX_PASSWORD
```

## Security requirements

- Retrieve administrator credentials from an approved secret store.
- Never commit passwords, subscription identifiers, public addresses, PFX files,
  private keys, or generated connection scripts.
- Avoid passing secrets through command-line arguments or Azure VM Run Command.
- Use least-privilege Key Vault access and remove temporary permissions.
- Treat any value previously committed to Git as permanently compromised.

## Validation

Use the repository's readiness and test scripts to verify resource state and TLS
inspection behavior. Resolve current addresses from Azure rather than recording
them in reports or documentation.