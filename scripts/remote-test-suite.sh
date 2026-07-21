#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

echo "Azure Firewall TLS Inspection Remote Test Suite"
"$SCRIPT_DIR/quick-tls-test.sh"

echo
echo "Firewall policy summary:"
az network firewall policy show \
    --resource-group "${RG_PRIMARY:-rg-azfw-tls-lab}" \
    --name "${POLICY_NAME:-azfw-tls-lab-policy}" \
    --query "{State:provisioningState,Certificate:transportSecurity.certificateAuthority.name}" \
    --output table

echo "No credentials or public connection addresses are included in this report."
