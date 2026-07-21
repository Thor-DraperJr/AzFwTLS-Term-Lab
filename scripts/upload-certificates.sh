#!/bin/bash
set -euo pipefail

KV_NAME="${KV_NAME:-azfw-tls-lab-kv-2025}"
RG_PRIMARY="${RG_PRIMARY:-rg-azfw-tls-lab}"
FW_POLICY="${FW_POLICY:-azfw-tls-lab-policy}"
PFX_FILE="${PFX_FILE:-azfw-intermediate-ca.pfx}"
ROOT_CERT_FILE="${ROOT_CERT_FILE:-azfw-root-ca.cer}"

if [[ -z "${PFX_PASSWORD:-}" ]]; then
    echo "PFX_PASSWORD must be supplied in the local process environment." >&2
    exit 1
fi

if [[ ! -f "$PFX_FILE" || ! -f "$ROOT_CERT_FILE" ]]; then
    echo "Required certificate files were not found." >&2
    exit 1
fi

az keyvault certificate import --vault-name "$KV_NAME" --name azfw-intermediate-ca --file "$PFX_FILE" --password "$PFX_PASSWORD"
az keyvault certificate import --vault-name "$KV_NAME" --name azfw-root-ca --file "$ROOT_CERT_FILE"

certificate_id=$(az keyvault certificate show --vault-name "$KV_NAME" --name azfw-intermediate-ca --query id --output tsv)
az network firewall policy update --resource-group "$RG_PRIMARY" --name "$FW_POLICY" --enable-tls-inspection true --certificate-authority "$certificate_id"

echo "Certificates uploaded and firewall policy updated. Clear PFX_PASSWORD from the process environment."
