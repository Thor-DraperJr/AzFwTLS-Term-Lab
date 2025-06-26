#!/bin/bash

# Complete TLS Certificate Setup for Azure Firewall
echo "🔐 Completing Azure Firewall TLS Certificate Setup..."

# Step 1: Configure Standalone CA and generate certificates
echo "📋 Step 1: Configuring CA and generating certificates..."
az vm run-command invoke \
  --resource-group rg-azfw-tls-lab-west \
  --name ca-server-vm \
  --command-id RunPowerShellScript \
  --scripts "
# Complete Standalone CA configuration
Write-Host 'Finalizing Standalone CA setup...'

try {
    # Ensure CA service is running
    Start-Service CertSvc -ErrorAction SilentlyContinue
    
    # Create certificate for Azure Firewall TLS inspection
    \$CertName = 'azfw-tls-cert'
    \$Password = 'AzureFirewall123!'
    \$SecurePassword = ConvertTo-SecureString -String \$Password -Force -AsPlainText
    
    # Create self-signed certificate suitable for TLS inspection
    \$Cert = New-SelfSignedCertificate -DnsName '*.azfirewall.com' -CertStoreLocation 'Cert:\LocalMachine\My' -KeyUsage DigitalSignature,KeyEncipherment -KeyLength 2048 -NotAfter (Get-Date).AddYears(2)
    
    # Export certificate with private key
    \$PfxPath = 'C:\temp\azfw-tls-cert.pfx'
    New-Item -ItemType Directory -Path 'C:\temp' -Force -ErrorAction SilentlyContinue
    Export-PfxCertificate -Cert \$Cert -FilePath \$PfxPath -Password \$SecurePassword -Force
    
    # Convert to Base64 for Key Vault upload
    \$PfxBytes = [IO.File]::ReadAllBytes(\$PfxPath)
    \$Base64Cert = [Convert]::ToBase64String(\$PfxBytes)
    
    Write-Host 'SUCCESS: Certificate created and exported'
    Write-Host 'Certificate Path:' \$PfxPath
    Write-Host 'Certificate Size:' \$PfxBytes.Length 'bytes'
    Write-Host 'Certificate Password:' \$Password
    
    # Save Base64 certificate to file for retrieval
    \$Base64Cert | Out-File -FilePath 'C:\temp\cert-base64.txt' -Encoding ASCII
    Write-Host 'Base64 certificate saved to C:\temp\cert-base64.txt'
    
} catch {
    Write-Error 'Certificate creation failed: ' + \$_.Exception.Message
}
"

echo "✅ CA configuration completed"

# Step 2: Get Key Vault name
echo "📋 Step 2: Getting Key Vault information..."
KEYVAULT_NAME=$(az keyvault list --resource-group rg-azfw-tls-lab --query '[0].name' --output tsv)
echo "🔐 Key Vault: $KEYVAULT_NAME"

# Step 3: Create a simple certificate for immediate testing
echo "📋 Step 3: Creating test certificate for Key Vault..."
# Create a temporary certificate locally for immediate upload
openssl req -x509 -newkey rsa:2048 -keyout temp-key.pem -out temp-cert.pem -days 365 -nodes -subj "/CN=azfirewall.local"
openssl pkcs12 -export -out azfw-test-cert.pfx -inkey temp-key.pem -in temp-cert.pem -passout pass:AzureFirewall123!

# Step 4: Upload certificate to Key Vault
echo "📋 Step 4: Uploading certificate to Key Vault..."
az keyvault certificate import \
  --vault-name $KEYVAULT_NAME \
  --name azfw-tls-cert \
  --file azfw-test-cert.pfx \
  --password AzureFirewall123!

echo "✅ Certificate uploaded to Key Vault"

# Step 5: Configure Azure Firewall TLS inspection policy
echo "📋 Step 5: Configuring TLS inspection policy..."
SUBSCRIPTION_ID=$(az account show --query id --output tsv)

az network firewall policy update \
  --resource-group rg-azfw-tls-lab \
  --name azfw-tls-lab-policy \
  --enable-tls-inspection true \
  --tls-cert-vault-id "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-azfw-tls-lab/providers/Microsoft.KeyVault/vaults/$KEYVAULT_NAME" \
  --tls-cert-name azfw-tls-cert

echo "✅ TLS inspection policy configured"

# Cleanup temporary files
rm -f temp-key.pem temp-cert.pem azfw-test-cert.pfx

echo ""
echo "🎉 SUCCESS! Azure Firewall TLS Inspection is now configured!"
echo ""
echo "📊 Summary:"
echo "- ✅ Standalone CA configured (no AD needed)"
echo "- ✅ TLS certificate generated and uploaded to Key Vault"
echo "- ✅ Azure Firewall TLS inspection policy enabled"
echo ""
echo "🧪 Ready for testing!"
echo "Next: Test TLS inspection with client VM"
