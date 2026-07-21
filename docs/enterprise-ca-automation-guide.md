# Enterprise CA Certificate Workflow

This repository keeps certificate export and Azure upload as separate steps so
the PFX password is never embedded in source, generated scripts, or Azure VM Run
Command parameters.

## Export the certificate

Run the PowerShell export locally or in an approved administrative session:

```powershell
$PfxPassword = Read-Host "PFX password" -AsSecureString
./ca-quick-setup.ps1 -PfxPassword $PfxPassword
```

`ca-simple-setup.ps1` supports the same `SecureString` input when the simpler
export path is appropriate.

## Upload to Azure

Set the matching password only in the local process environment, then run the
upload script:

```bash
read -rsp "PFX password: " PFX_PASSWORD
echo
export PFX_PASSWORD
./scripts/upload-certificates.sh
unset PFX_PASSWORD
```

Do not store the password in `.env`, shell history, scripts, documentation, or
committed configuration. Delete local PFX files after the import is validated.

## Validate

Confirm that:

- the certificate import completed successfully;
- the firewall policy references the intended Key Vault certificate;
- test HTTPS traffic follows the expected TLS inspection path;
- logs and generated artifacts contain no credentials or public connection data.

The legacy end-to-end shell wrappers remain at their original paths as retirement
notices. They intentionally exit before running.