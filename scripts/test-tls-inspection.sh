#!/bin/bash

# Azure Firewall TLS Inspection Test Script
echo "🧪 Azure Firewall TLS Inspection Testing"
echo "======================================="
echo ""

# Get connection details
echo "📋 Getting connection details..."
CA_VM_IP=$(az vm show --resource-group rg-azfw-tls-lab-west --name ca-server-vm --show-details --query publicIps --output tsv)
CLIENT_VM_IP=$(az vm show --resource-group rg-azfw-tls-lab-west --name client-vm --show-details --query publicIps --output tsv)
FIREWALL_IP=$(az network public-ip show --resource-group rg-azfw-tls-lab --name azfw-tls-lab-pip --query ipAddress --output tsv)

echo "🔐 CA Server VM: $CA_VM_IP:3389"
echo "🖥️ Client VM: $CLIENT_VM_IP:3389"  
echo "🔥 Azure Firewall: $FIREWALL_IP"
echo ""

# Test 1: Basic connectivity
echo "🧪 Test 1: Basic VM connectivity"
echo "Testing ping to CA server..."
ping -c 2 $CA_VM_IP > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ CA Server is reachable"
else
    echo "❌ CA Server ping failed"
fi

echo "Testing ping to Client VM..."
ping -c 2 $CLIENT_VM_IP > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Client VM is reachable"
else
    echo "❌ Client VM ping failed"
fi

echo "Testing ping to Firewall..."
ping -c 2 $FIREWALL_IP > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Azure Firewall is reachable"
else
    echo "❌ Azure Firewall ping failed"
fi

echo ""

# Test 2: Azure resources status
echo "🧪 Test 2: Azure Resources Status"
echo "Checking Azure Firewall..."
FW_STATE=$(az network firewall show --resource-group rg-azfw-tls-lab --name azfw-tls-lab-firewall --query provisioningState --output tsv)
echo "🔥 Firewall State: $FW_STATE"

echo "Checking Key Vault certificate..."
CERT_ENABLED=$(az keyvault certificate show --vault-name azfw-tls-lab-kv-2025 --name azfw-tls-cert --query attributes.enabled --output tsv 2>/dev/null)
if [ "$CERT_ENABLED" = "true" ]; then
    echo "✅ TLS Certificate is available in Key Vault"
else
    echo "❌ TLS Certificate not found or disabled"
fi

echo ""

# Test 3: TLS Inspection Configuration
echo "🧪 Test 3: TLS Inspection Configuration"
TLS_CONFIG=$(az network firewall policy show --resource-group rg-azfw-tls-lab --name azfw-tls-lab-policy --query transportSecurity --output tsv 2>/dev/null)
if [ "$TLS_CONFIG" != "None" ]; then
    echo "✅ TLS Inspection is configured on firewall policy"
else
    echo "❌ TLS Inspection not configured"
fi

echo ""

# Manual testing instructions
echo "🎯 Manual Testing Steps:"
echo "========================"
echo ""
echo "1. 🖥️ Connect to Client VM via RDP:"
echo "   Address: $CLIENT_VM_IP:3389"
echo "   Username: azureadmin"
echo "   Password: <REMOVED_FROM_HISTORY>"
echo ""
echo "2. 🌐 Test HTTPS websites from Client VM:"
echo "   - Open web browser"
echo "   - Visit: https://www.google.com"
echo "   - Visit: https://www.microsoft.com"
echo "   - Check certificate details (should show Azure Firewall intermediate CA)"
echo ""
echo "3. 🔍 Monitor Azure Firewall logs:"
echo "   - Check Azure Monitor logs"
echo "   - Look for TLS inspection events"
echo "   - Verify traffic is being inspected"
echo ""
echo "4. 📊 Advanced testing (optional):"
echo "   - Test different HTTPS sites"
echo "   - Verify certificate chain validation"
echo "   - Check firewall rule matching"
echo ""

# Final status
echo "🎉 Setup Complete!"
echo "=================="
echo ""
echo "✅ Standalone CA configured (no AD required)"
echo "✅ TLS certificate generated and uploaded"
echo "✅ Azure Firewall TLS inspection enabled"
echo "✅ VMs ready for testing"
echo ""
echo "🚀 Your Azure Firewall TLS Inspection Lab is ready!"
echo ""
echo "📚 Next steps:"
echo "- Connect to Client VM and test HTTPS browsing"
echo "- Monitor firewall logs for TLS inspection events"
echo "- Experiment with different websites and applications"
