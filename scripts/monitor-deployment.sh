#!/bin/bash

# Azure Firewall TLS Lab - Deployment Monitor
# This script monitors the deployment status of resources across regions

echo "🔍 Azure Firewall TLS Inspection Lab - Deployment Monitor"
echo "=========================================================="
echo "Monitoring Time: $(date)"
echo ""

# Function to check resource group status
check_resource_group() {
    local rg_name=$1
    local region=$2
    
    echo "📍 Checking Resource Group: $rg_name ($region)"
    
    # Get resource group status
    rg_status=$(az group show --name $rg_name --query "properties.provisioningState" -o tsv 2>/dev/null)
    
    if [ "$rg_status" = "Succeeded" ]; then
        echo "   ✅ Resource Group: $rg_status"
        
        # List all resources in the group
        echo "   📋 Resources:"
        az resource list --resource-group $rg_name --query "[].{Name:name, Type:type, State:properties.provisioningState}" --output table 2>/dev/null | sed 's/^/      /'
        
    elif [ "$rg_status" = "Running" ]; then
        echo "   🔄 Resource Group: $rg_status (Deployment in progress)"
    elif [ -z "$rg_status" ]; then
        echo "   ❌ Resource Group: Not found"
    else
        echo "   ⚠️  Resource Group: $rg_status"
    fi
    echo ""
}

# Function to check specific deployments
check_deployments() {
    local rg_name=$1
    
    echo "🚀 Active Deployments in $rg_name:"
    
    # Get active deployments
    active_deployments=$(az deployment group list --resource-group $rg_name --query "[?properties.provisioningState=='Running'].{Name:name, State:properties.provisioningState, Started:properties.timestamp}" --output table 2>/dev/null)
    
    if [ -n "$active_deployments" ] && [ "$active_deployments" != "[]" ]; then
        echo "$active_deployments" | sed 's/^/   /'
    else
        echo "   ✅ No active deployments"
    fi
    echo ""
}

# Function to get Key Vault status
check_key_vault() {
    local rg_name=$1
    
    echo "🔐 Key Vault Status:"
    kv_name=$(az keyvault list --resource-group $rg_name --query "[0].name" -o tsv 2>/dev/null)
    
    if [ -n "$kv_name" ]; then
        echo "   📦 Key Vault: $kv_name"
        
        # Check certificates
        cert_count=$(az keyvault certificate list --vault-name $kv_name --query "length(@)" -o tsv 2>/dev/null)
        echo "   📜 Certificates: $cert_count"
        
        # Check secrets
        secret_count=$(az keyvault secret list --vault-name $kv_name --query "length(@)" -o tsv 2>/dev/null)
        echo "   🔒 Secrets: $secret_count"
    else
        echo "   ❌ No Key Vault found"
    fi
    echo ""
}

# Function to check Azure Firewall status
check_firewall() {
    local rg_name=$1
    
    echo "🔥 Azure Firewall Status:"
    fw_name=$(az network firewall list --resource-group $rg_name --query "[0].name" -o tsv 2>/dev/null)
    
    if [ -n "$fw_name" ]; then
        fw_state=$(az network firewall show --resource-group $rg_name --name $fw_name --query "provisioningState" -o tsv 2>/dev/null)
        fw_sku=$(az network firewall show --resource-group $rg_name --name $fw_name --query "sku.tier" -o tsv 2>/dev/null)
        
        echo "   🔥 Firewall: $fw_name"
        echo "   📊 Status: $fw_state"
        echo "   🏷️  SKU: $fw_sku"
        
        # Check firewall policy
        policy_id=$(az network firewall show --resource-group $rg_name --name $fw_name --query "firewallPolicy.id" -o tsv 2>/dev/null)
        if [ -n "$policy_id" ]; then
            policy_name=$(basename $policy_id)
            echo "   📋 Policy: $policy_name"
        fi
    else
        echo "   ❌ No Azure Firewall found"
    fi
    echo ""
}

# Main monitoring loop
echo "🌍 PRIMARY REGION (East US)"
echo "=========================="
check_resource_group "rg-azfw-tls-lab" "East US"
check_deployments "rg-azfw-tls-lab"
check_firewall "rg-azfw-tls-lab"
check_key_vault "rg-azfw-tls-lab"

echo ""
echo "🌎 BACKUP REGION (West US 2)"
echo "============================"
check_resource_group "rg-azfw-tls-lab-west" "West US 2"
check_deployments "rg-azfw-tls-lab-west"

# Show next steps
echo ""
echo "📝 NEXT STEPS:"
echo "=============="
echo "1. ✅ VNet, Firewall, and Key Vault deployed in East US"
echo "2. 🔄 VMs deploying in West US 2 (due to East US capacity)"
echo "3. ⏳ Once VMs are ready: Configure AD CS on CA server"
echo "4. 🔐 Generate and upload intermediate CA certificate"
echo "5. 🔍 Enable TLS inspection in firewall policy"
echo "6. 🧪 Test end-to-end TLS inspection"
echo ""

# Provide connection information if VMs are ready
echo "🔗 CONNECTION INFO:"
echo "=================="
ca_pip=$(az network public-ip show --resource-group rg-azfw-tls-lab-west --name ca-server-pip --query "ipAddress" -o tsv 2>/dev/null)
client_pip=$(az network public-ip show --resource-group rg-azfw-tls-lab-west --name client-vm-pip --query "ipAddress" -o tsv 2>/dev/null)

if [ -n "$ca_pip" ] && [ "$ca_pip" != "null" ]; then
    echo "   🖥️  CA Server RDP: $ca_pip:3389"
    echo "   👤 Username: azureadmin"
    echo "   🔑 Password: <REMOVED_FROM_HISTORY>"
else
    echo "   ⏳ CA Server: Still deploying..."
fi

if [ -n "$client_pip" ] && [ "$client_pip" != "null" ]; then
    echo "   🖥️  Client VM RDP: $client_pip:3389"
    echo "   👤 Username: azureadmin"
    echo "   🔑 Password: <REMOVED_FROM_HISTORY>"
else
    echo "   ⏳ Client VM: Still deploying..."
fi

echo ""
echo "🔄 Run this script again to check updated status"
echo "📊 Estimated VM deployment time: 5-10 minutes"
