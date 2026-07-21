#!/bin/bash
set -euo pipefail

RG_PRIMARY="${RG_PRIMARY:-rg-azfw-tls-lab}"
RG_SECONDARY="${RG_SECONDARY:-rg-azfw-tls-lab-west}"
KV_NAME="${KV_NAME:-azfw-tls-lab-kv-2025}"
FW_NAME="${FW_NAME:-azfw-tls-lab-firewall}"
CERT_NAME="${CERT_NAME:-azfw-tls-cert}"

certificate_enabled=$(az keyvault certificate show --vault-name "$KV_NAME" --name "$CERT_NAME" --query attributes.enabled --output tsv 2>/dev/null || true)
firewall_state=$(az network firewall show --resource-group "$RG_PRIMARY" --name "$FW_NAME" --query provisioningState --output tsv 2>/dev/null || true)
firewall_tier=$(az network firewall show --resource-group "$RG_PRIMARY" --name "$FW_NAME" --query sku.tier --output tsv 2>/dev/null || true)
client_result=$(az vm run-command invoke --resource-group "$RG_SECONDARY" --name client-vm --command-id RunPowerShellScript --scripts "(Invoke-WebRequest -Uri 'https://www.microsoft.com' -UseBasicParsing -TimeoutSec 15).StatusCode" --query 'value[0].message' --output tsv 2>/dev/null || true)

printf 'Certificate enabled: %s\n' "${certificate_enabled:-unknown}"
printf 'Firewall state: %s\n' "${firewall_state:-unknown}"
printf 'Firewall tier: %s\n' "${firewall_tier:-unknown}"
printf 'Client HTTPS result: %s\n' "${client_result:-unavailable}"
