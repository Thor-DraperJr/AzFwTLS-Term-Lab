#!/bin/bash

# Quick Azure Resource Status Check
# This provides a fast overview of your lab resources

echo "🔍 Azure Firewall TLS Lab - Quick Status Check"
echo "=============================================="
echo ""

# Check if both resource groups exist and show their resources
echo "📍 East US Deployment (rg-azfw-tls-lab):"
echo "----------------------------------------"
az resource list --resource-group rg-azfw-tls-lab --output table 2>/dev/null || echo "❌ Resource group not found or empty"
echo ""

echo "📍 West US 2 Backup (rg-azfw-tls-lab-west):"
echo "-------------------------------------------"
az resource list --resource-group rg-azfw-tls-lab-west --output table 2>/dev/null || echo "⚪ Resource group empty or not found"
echo ""

# Quick health check of key services in East US
echo "🏥 Health Check Summary:"
echo "----------------------"

# Check Firewall status
fw_status=$(az network firewall show --name azfw-tls-lab-firewall --resource-group rg-azfw-tls-lab --query "provisioningState" --output tsv 2>/dev/null | tr -d '\r\n' || echo "NotFound")
if [ "$fw_status" = "Succeeded" ]; then
    echo "✅ Azure Firewall: Ready"
else
    echo "❌ Azure Firewall: $fw_status"
fi

# Check Key Vault status
kv_status=$(az keyvault show --name azfw-tls-lab-kv-2025 --resource-group rg-azfw-tls-lab --query "properties.provisioningState" --output tsv 2>/dev/null | tr -d '\r\n' || echo "NotFound")
if [ "$kv_status" = "Succeeded" ]; then
    echo "✅ Key Vault: Ready"
else
    echo "❌ Key Vault: $kv_status"
fi

# Check if any VMs exist
vm_count=$(az vm list --resource-group rg-azfw-tls-lab --query "length(@)" --output tsv 2>/dev/null | tr -d '\r\n' || echo "0")
if [ ! -z "$vm_count" ] && [ "$vm_count" -gt 0 ] 2>/dev/null; then
    echo "✅ Virtual Machines: $vm_count found"
    az vm list --resource-group rg-azfw-tls-lab --show-details --output table --query "[].{Name:name,PowerState:powerState,ProvisioningState:provisioningState}" 2>/dev/null
else
    echo "⚪ Virtual Machines: None deployed yet"
fi

echo ""
echo "🚀 Next Steps:"
echo "- To deploy missing VMs: ./scripts/deploy-lab.sh -r rg-azfw-tls-lab-west"
echo "- For continuous monitoring: ./scripts/wait-for-resources.sh wait -g rg-azfw-tls-lab"
echo "- For help: ./scripts/wait-for-resources.sh help"
