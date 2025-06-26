#!/bin/bash

# Azure Firewall TLS Inspection Lab - Quick Programmatic Setup
# Uses Azure VM extensions and custom script extensions for automation

set -e

echo "⚡ Azure Firewall TLS Inspection Lab - Quick Programmatic Setup"
echo "=============================================================="
echo ""

# Configuration
RG_PRIMARY="rg-azfw-tls-lab"
RG_WEST="rg-azfw-tls-lab-west"
KV_NAME="azfw-tls-lab-kv-2025"
FW_POLICY="azfw-tls-lab-policy"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Create PowerShell script for CA automation
create_ca_extension_script() {
    print_info "Creating CA automation script for VM extension..."
    
    cat > ca-quick-setup.ps1 << 'EOF'
# Quick CA Setup for Azure Firewall TLS Inspection
try {
    # Install AD CS
    Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
    
    # Configure CA
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "AzFirewall-TLS-Lab-CA" -CADistinguishedNameSuffix "DC=azfwlab,DC=local" -Force
    
    # Wait and create intermediate cert
    Start-Sleep 20
    
    # Generate certificate for Azure Firewall
    $req = @"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject="CN=Azure-Firewall-Intermediate-CA,O=AzFirewall-TLS-Lab,C=US"
KeyLength=2048
KeyAlgorithm=RSA
MachineKeySet=TRUE
RequestType=PKCS10
[Extensions]
2.5.29.19 = "{text}CA:TRUE&pathlength:0"
"@
    
    New-Item -Path "C:\cert" -Type Directory -Force
    $req | Out-File "C:\cert\req.inf" -Encoding ASCII
    
    certreq -new "C:\cert\req.inf" "C:\cert\req.req"
    certreq -submit -config ".\AzFirewall-TLS-Lab-CA" "C:\cert\req.req" "C:\cert\cert.cer"
    certreq -accept "C:\cert\cert.cer"
    
    # Export certificates
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Azure-Firewall-Intermediate-CA*"}
    $pwd = ConvertTo-SecureString "AzFirewall2025!" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "C:\cert\intermediate.pfx" -Password $pwd
    
    $root = Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*AzFirewall-TLS-Lab-CA*"}
    Export-Certificate -Cert $root -FilePath "C:\cert\root.cer"
    
    "SUCCESS" > "C:\cert\status.txt"
} catch {
    $_.Exception.Message > "C:\cert\error.txt"
    "FAILED" > "C:\cert\status.txt"
}
EOF
}

# Deploy CA using VM extension
deploy_ca_extension() {
    print_info "Deploying CA configuration via VM extension..."
    
    create_ca_extension_script
    
    # Create storage account for script
    STORAGE_ACCOUNT="azfwtlslab$(date +%s | tail -c 6)"
    
    az storage account create \
        --name $STORAGE_ACCOUNT \
        --resource-group $RG_WEST \
        --location westus2 \
        --sku Standard_LRS >/dev/null
    
    # Upload script to storage
    STORAGE_KEY=$(az storage account keys list --resource-group $RG_WEST --account-name $STORAGE_ACCOUNT --query "[0].value" -o tsv)
    
    az storage container create \
        --name scripts \
        --account-name $STORAGE_ACCOUNT \
        --account-key $STORAGE_KEY >/dev/null
    
    az storage blob upload \
        --file ca-quick-setup.ps1 \
        --container-name scripts \
        --name ca-setup.ps1 \
        --account-name $STORAGE_ACCOUNT \
        --account-key $STORAGE_KEY >/dev/null
    
    SCRIPT_URL=$(az storage blob url \
        --container-name scripts \
        --name ca-setup.ps1 \
        --account-name $STORAGE_ACCOUNT \
        --account-key $STORAGE_KEY -o tsv)
    
    # Deploy custom script extension
    az vm extension set \
        --resource-group $RG_WEST \
        --vm-name ca-server-vm \
        --name CustomScriptExtension \
        --publisher Microsoft.Compute \
        --version 1.10 \
        --settings "{\"fileUris\":[\"$SCRIPT_URL\"],\"commandToExecute\":\"powershell -ExecutionPolicy Unrestricted -File ca-setup.ps1\"}" \
        --no-wait
    
    print_success "CA configuration extension deployed"
}

# Quick certificate retrieval and upload
quick_cert_upload() {
    print_info "Waiting for CA setup and retrieving certificates..."
    
    # Wait for completion
    for i in {1..10}; do
        print_info "Checking CA status (attempt $i/10)..."
        
        result=$(az vm run-command invoke \
            --resource-group $RG_WEST \
            --name ca-server-vm \
            --command-id RunPowerShellScript \
            --scripts "Get-Content 'C:\cert\status.txt' -ErrorAction SilentlyContinue" \
            --query "value[0].message" -o tsv 2>/dev/null || echo "")
        
        if [[ "$result" == *"SUCCESS"* ]]; then
            print_success "CA setup completed!"
            break
        fi
        
        sleep 30
    done
    
    # Download certificates
    print_info "Downloading certificates..."
    mkdir -p ./certs
    
    # Get PFX
    az vm run-command invoke \
        --resource-group $RG_WEST \
        --name ca-server-vm \
        --command-id RunPowerShellScript \
        --scripts "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\cert\intermediate.pfx'))" \
        --query "value[0].message" -o tsv | base64 -d > ./certs/intermediate.pfx
    
    # Get root cert
    az vm run-command invoke \
        --resource-group $RG_WEST \
        --name ca-server-vm \
        --command-id RunPowerShellScript \
        --scripts "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\cert\root.cer'))" \
        --query "value[0].message" -o tsv | base64 -d > ./certs/root.cer
    
    print_success "Certificates downloaded"
}

# Upload to Key Vault and configure firewall
configure_firewall_quick() {
    print_info "Uploading certificates and configuring firewall..."
    
    # Upload to Key Vault
    az keyvault certificate import \
        --vault-name $KV_NAME \
        --name azfw-intermediate-ca \
        --file ./certs/intermediate.pfx \
        --password "AzFirewall2025!" >/dev/null
    
    # Get certificate ID and configure firewall
    CERT_ID=$(az keyvault certificate show \
        --vault-name $KV_NAME \
        --name azfw-intermediate-ca \
        --query "id" -o tsv)
    
    # Update firewall policy
    az network firewall policy update \
        --resource-group $RG_PRIMARY \
        --name $FW_POLICY \
        --enable-tls-inspection true \
        --certificate-authority "$CERT_ID" >/dev/null
    
    # Create rules
    az network firewall policy rule-collection-group create \
        --resource-group $RG_PRIMARY \
        --policy-name $FW_POLICY \
        --name "TLSRules" \
        --priority 1000 >/dev/null 2>&1 || true
    
    sleep 10
    
    az network firewall policy rule-collection-group collection add-filter-collection \
        --resource-group $RG_PRIMARY \
        --policy-name $FW_POLICY \
        --rule-collection-group-name "TLSRules" \
        --name "HTTPS-TLS-Inspection" \
        --collection-priority 1000 \
        --action Allow \
        --rule-name "Allow-HTTPS" \
        --rule-type ApplicationRule \
        --destination-addresses "*" \
        --source-addresses "10.1.0.0/16" \
        --protocols "Https=443" \
        --enable-tls-inspection true >/dev/null
    
    print_success "Firewall configured for TLS inspection"
}

# Quick test
run_quick_test() {
    print_info "Running quick connectivity test..."
    
    # Install root cert and test
    az vm run-command invoke \
        --resource-group $RG_WEST \
        --name client-vm \
        --command-id RunPowerShellScript \
        --scripts "
            try {
                # Test basic connectivity
                \$result = Invoke-WebRequest -Uri 'https://www.microsoft.com' -UseBasicParsing -TimeoutSec 10
                if (\$result.StatusCode -eq 200) {
                    'TEST_SUCCESS: HTTPS connectivity working'
                } else {
                    'TEST_PARTIAL: Response code ' + \$result.StatusCode
                }
            } catch {
                'TEST_FAILED: ' + \$_.Exception.Message
            }
        " \
        --query "value[0].message" -o tsv
}

# Show summary
show_summary() {
    echo ""
    print_success "🎉 Quick programmatic setup completed!"
    echo ""
    echo "📊 What was automated:"
    echo "  ✅ Certificate Authority installed and configured"
    echo "  ✅ Intermediate CA certificate generated"
    echo "  ✅ Certificates uploaded to Key Vault"
    echo "  ✅ Azure Firewall Policy configured for TLS inspection"
    echo "  ✅ Application rules created"
    echo "  ✅ Basic connectivity test performed"
    echo ""
    echo "🔍 Resources created:"
    echo "  📋 Key Vault certificates:"
    az keyvault certificate list --vault-name $KV_NAME --query "[].name" -o tsv | sed 's/^/    - /'
    echo ""
    echo "🧪 To run more comprehensive tests:"
    echo "  ./scripts/automate-tls-inspection.sh  # Full automation"
    echo "  ./scripts/start-testing.sh            # Manual testing guide"
    echo ""
    echo "🔗 VM Access (if needed):"
    echo "  CA Server: $(az network public-ip show --resource-group $RG_WEST --name ca-server-pip --query "ipAddress" -o tsv 2>/dev/null):3389"
    echo "  Client VM: $(az network public-ip show --resource-group $RG_WEST --name client-vm-pip --query "ipAddress" -o tsv 2>/dev/null):3389"
    echo "  Username: azureadmin | Password: SecureP@ssw0rd123!"
}

# Main execution
main() {
    print_info "Starting quick programmatic setup..."
    
    deploy_ca_extension
    quick_cert_upload
    configure_firewall_quick
    
    print_info "Running connectivity test..."
    TEST_RESULT=$(run_quick_test)
    echo "Test Result: $TEST_RESULT"
    
    show_summary
    
    # Cleanup
    rm -f ca-quick-setup.ps1
}

# Run main
main
