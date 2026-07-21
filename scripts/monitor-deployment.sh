#!/bin/bash
set -euo pipefail

RG_PRIMARY="${RG_PRIMARY:-rg-azfw-tls-lab}"
RG_SECONDARY="${RG_SECONDARY:-rg-azfw-tls-lab-west}"

echo "Azure Firewall TLS Inspection Lab - Deployment Monitor"
echo "Checked: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

for resource_group in "$RG_PRIMARY" "$RG_SECONDARY"; do
    echo
    echo "Resource group: $resource_group"
    if az group show --name "$resource_group" >/dev/null 2>&1; then
        az resource list --resource-group "$resource_group" --query "[].{Name:name,Type:type,State:properties.provisioningState}" --output table
    else
        echo "Not found or inaccessible."
    fi
done

echo
echo "Connection addresses and credentials are intentionally omitted. Resolve addresses from Azure and retrieve credentials from the approved secret store."
