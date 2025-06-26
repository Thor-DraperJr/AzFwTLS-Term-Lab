#!/bin/bash

# Quick TLS Inspection Verification Test
echo "🧪 Quick TLS Inspection Verification"
echo "===================================="
echo ""

# Test the key components that matter for TLS inspection
echo "1. 🔐 Testing Key Vault Certificate..."
CERT_STATUS=$(az keyvault certificate show --vault-name azfw-tls-lab-kv-2025 --name azfw-tls-cert --query 'attributes.enabled' --output tsv 2>/dev/null)
if [ "$CERT_STATUS" == "true" ]; then
    echo "✅ Certificate is available and enabled in Key Vault"
else
    echo "❌ Certificate not found or disabled in Key Vault"
fi

echo ""
echo "2. 🔥 Testing Azure Firewall Status..."
FW_STATUS=$(az network firewall show --resource-group rg-azfw-tls-lab --name azfw-tls-lab-firewall --query 'provisioningState' --output tsv 2>/dev/null)
FW_TIER=$(az network firewall show --resource-group rg-azfw-tls-lab --name azfw-tls-lab-firewall --query 'sku.tier' --output tsv 2>/dev/null)
echo "🔥 Firewall Status: $FW_STATUS"
echo "🔥 Firewall Tier: $FW_TIER"

if [ "$FW_STATUS" == "Succeeded" ] && [ "$FW_TIER" == "Premium" ]; then
    echo "✅ Azure Firewall Premium is ready"
else
    echo "❌ Azure Firewall issues detected"
fi

echo ""
echo "3. 🖥️ Testing VM Connectivity..."
# Test CA Server
CA_VM_STATUS=$(az vm run-command invoke \
    --resource-group rg-azfw-tls-lab-west \
    --name ca-server-vm \
    --command-id RunPowerShellScript \
    --scripts "Write-Output 'CA_VM_ONLINE'" \
    --query 'value[0].message' --output tsv 2>/dev/null)

if echo "$CA_VM_STATUS" | grep -q "CA_VM_ONLINE"; then
    echo "✅ CA Server VM is responsive"
else
    echo "❌ CA Server VM not responding"
fi

# Test Client VM with web request
CLIENT_WEB_TEST=$(az vm run-command invoke \
    --resource-group rg-azfw-tls-lab-west \
    --name client-vm \
    --command-id RunPowerShellScript \
    --scripts "
        try {
            \$Response = Invoke-WebRequest -Uri 'https://httpbin.org/get' -UseBasicParsing -TimeoutSec 15
            if (\$Response.StatusCode -eq 200) {
                Write-Output 'WEB_SUCCESS:' + \$Response.StatusCode
            }
        } catch {
            Write-Output 'WEB_ERROR:' + \$_.Exception.Message
        }
    " --query 'value[0].message' --output tsv 2>/dev/null)

if echo "$CLIENT_WEB_TEST" | grep -q "WEB_SUCCESS"; then
    echo "✅ Client VM can access HTTPS websites"
else
    echo "❌ Client VM web connectivity issues"
fi

echo ""
echo "4. 🎯 TLS Inspection Detailed Test..."
# Detailed TLS inspection test
TLS_TEST=$(az vm run-command invoke \
    --resource-group rg-azfw-tls-lab-west \
    --name client-vm \
    --command-id RunPowerShellScript \
    --scripts "
        try {
            # Test certificate chain inspection
            \$ServicePoint = [System.Net.ServicePointManager]::FindServicePoint('https://www.google.com')
            \$ServicePoint.ConnectionLimit = 1
            
            \$Request = [System.Net.WebRequest]::Create('https://www.google.com')
            \$Request.Timeout = 15000
            \$Response = \$Request.GetResponse()
            
            if (\$Request.ServicePoint.Certificate) {
                \$Issuer = \$Request.ServicePoint.Certificate.Issuer
                Write-Output 'CERT_ISSUER:' + \$Issuer
                
                # Check if it's being intercepted by firewall
                if (\$Issuer -like '*Azure*' -or \$Issuer -like '*AzFW*' -or \$Issuer -like '*Firewall*') {
                    Write-Output 'TLS_INSPECTION:ACTIVE'
                } else {
                    Write-Output 'TLS_INSPECTION:PASSTHROUGH'
                }
            }
            \$Response.Close()
            
        } catch {
            Write-Output 'TLS_TEST_ERROR:' + \$_.Exception.Message
        }
    " --query 'value[0].message' --output tsv 2>/dev/null)

echo "Certificate Details:"
echo "$TLS_TEST"

if echo "$TLS_TEST" | grep -q "TLS_INSPECTION:ACTIVE"; then
    echo "🎉 TLS Inspection is ACTIVE - Firewall is intercepting HTTPS traffic!"
elif echo "$TLS_TEST" | grep -q "TLS_INSPECTION:PASSTHROUGH"; then
    echo "⚠️  TLS Inspection is in PASSTHROUGH mode - Traffic is not being intercepted"
else
    echo "❓ TLS Inspection status unclear"
fi

echo ""
echo "📊 Quick Test Summary:"
echo "====================="
echo "✅ = Working correctly"
echo "⚠️  = Working but may need attention"  
echo "❌ = Needs configuration"
echo ""
echo "🔗 For detailed manual testing:"
echo "RDP to Client VM: 20.125.51.10:3389"
echo "Username: azureadmin"
echo "Password: <REMOVED_FROM_HISTORY>"
echo ""
echo "Then browse to HTTPS websites and check certificate details."
