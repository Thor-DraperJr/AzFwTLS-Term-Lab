#!/bin/bash
set -euo pipefail

RG_PRIMARY="${RG_PRIMARY:-rg-azfw-tls-lab}"
RG_SECONDARY="${RG_SECONDARY:-rg-azfw-tls-lab-west}"
POLICY_NAME="${POLICY_NAME:-azfw-tls-lab-policy}"

echo "Azure Firewall TLS Inspection Test"
az network firewall show --resource-group "$RG_PRIMARY" --name azfw-tls-lab-firewall --query "{State:provisioningState,Tier:sku.tier}" --output table
az network firewall policy show --resource-group "$RG_PRIMARY" --name "$POLICY_NAME" --query "{State:provisioningState,Certificate:transportSecurity.certificateAuthority.name}" --output table
az vm list --resource-group "$RG_SECONDARY" --show-details --query "[].{Name:name,State:powerState}" --output table

echo "For manual testing, resolve the current client address from Azure and retrieve credentials from the approved secret store."
echo "Inspect an approved HTTPS destination and confirm the certificate chain and matching firewall logs."
