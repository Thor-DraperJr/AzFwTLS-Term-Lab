#!/bin/bash
set -euo pipefail

RG_PRIMARY="${RG_PRIMARY:-rg-azfw-tls-lab}"
RG_SECONDARY="${RG_SECONDARY:-rg-azfw-tls-lab-west}"
KV_NAME="${KV_NAME:-azfw-tls-lab-kv-2025}"

echo "Azure Firewall TLS Inspection Lab - Readiness"
az account show --query "{Name:name,Tenant:tenantId}" --output table
az network firewall list --resource-group "$RG_PRIMARY" --query "[].{Name:name,State:provisioningState,Tier:sku.tier}" --output table
az vm list --resource-group "$RG_SECONDARY" --show-details --query "[].{Name:name,State:powerState}" --output table
az keyvault certificate list --vault-name "$KV_NAME" --query "[].{Name:name,Enabled:attributes.enabled}" --output table

echo "Retrieve connection addresses from Azure and credentials from the approved secret store."
