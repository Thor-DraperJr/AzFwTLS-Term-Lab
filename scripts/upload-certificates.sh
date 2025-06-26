#!/bin/bash

# Azure Firewall TLS Lab - Certificate Upload Helper
# Use this script after you've generated certificates on the CA server

set -e

echo "🔐 Azure Firewall TLS Lab - Certificate Upload Helper"
echo "===================================================="
echo ""

# Configuration
KV_NAME="azfw-tls-lab-kv-2025"
RG_PRIMARY="rg-azfw-tls-lab"
FW_POLICY="azfw-tls-lab-policy"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if certificates exist
check_certificates() {
    print_info "Checking for certificate files..."
    
    if [ ! -f "azfw-intermediate-ca.pfx" ]; then
        echo "❌ azfw-intermediate-ca.pfx not found"
        echo "📋 Please copy this file from the CA server (C:\\temp\\azfw-intermediate-ca.pfx)"
        return 1
    fi
    
    if [ ! -f "azfw-root-ca.cer" ]; then
        echo "❌ azfw-root-ca.cer not found"
        echo "📋 Please copy this file from the CA server (C:\\temp\\azfw-root-ca.cer)"
        return 1
    fi
    
    print_success "Certificate files found"
    return 0
}

# Upload certificates to Key Vault
upload_certificates() {
    print_info "Uploading certificates to Key Vault $KV_NAME..."
    
    # Upload intermediate CA certificate (PFX with private key)
    az keyvault certificate import \
        --vault-name $KV_NAME \
        --name azfw-intermediate-ca \
        --file azfw-intermediate-ca.pfx \
        --password "AzFirewall2025!"
    
    print_success "Intermediate CA certificate uploaded"
    
    # Upload root CA certificate
    az keyvault certificate import \
        --vault-name $KV_NAME \
        --name azfw-root-ca \
        --file azfw-root-ca.cer
    
    print_success "Root CA certificate uploaded"
}

# Configure Azure Firewall Policy
configure_firewall_policy() {
    print_info "Configuring Azure Firewall Policy for TLS inspection..."
    
    # Get the certificate ID
    CERT_ID=$(az keyvault certificate show \
        --vault-name $KV_NAME \
        --name azfw-intermediate-ca \
        --query "id" -o tsv)
    
    print_info "Certificate ID: $CERT_ID"
    
    # Update firewall policy to enable TLS inspection
    az network firewall policy update \
        --resource-group $RG_PRIMARY \
        --name $FW_POLICY \
        --enable-tls-inspection true \
        --certificate-authority "$CERT_ID"
    
    print_success "Firewall policy updated with TLS inspection"
}

# Create application rules with TLS inspection
create_application_rules() {
    print_info "Creating application rules with TLS inspection..."
    
    # Create rule collection group if it doesn't exist
    az network firewall policy rule-collection-group create \
        --resource-group $RG_PRIMARY \
        --policy-name $FW_POLICY \
        --name "TLSInspectionRules" \
        --priority 1000 \
        --no-wait || true
    
    # Wait for rule collection group to be created
    sleep 10
    
    # Add application rule collection with TLS inspection
    az network firewall policy rule-collection-group collection add-filter-collection \
        --resource-group $RG_PRIMARY \
        --policy-name $FW_POLICY \
        --rule-collection-group-name "TLSInspectionRules" \
        --name "AllowHTTPSWithInspection" \
        --collection-priority 1000 \
        --action Allow \
        --rule-name "Allow-HTTPS-TLS-Inspection" \
        --rule-type ApplicationRule \
        --description "Allow HTTPS traffic with TLS inspection" \
        --destination-addresses "*" \
        --source-addresses "10.1.0.0/16" \
        --protocols "Https=443" \
        --enable-tls-inspection true
    
    print_success "Application rules created with TLS inspection enabled"
}

# Show verification steps
show_verification() {
    echo ""
    echo "🧪 VERIFICATION STEPS:"
    echo "===================="
    echo "1. Connect to Client VM (20.125.51.10) via RDP"
    echo "2. Install root CA certificate in trusted store:"
    echo "   - Copy azfw-root-ca.cer to client VM"
    echo "   - Run: Import-Certificate -FilePath azfw-root-ca.cer -CertStoreLocation Cert:\\LocalMachine\\Root"
    echo "3. Test HTTPS browsing:"
    echo "   - Invoke-WebRequest -Uri 'https://www.microsoft.com' -UseBasicParsing"
    echo "   - Invoke-WebRequest -Uri 'https://www.google.com' -UseBasicParsing"
    echo "4. Check Azure Firewall logs for TLS inspection events"
    echo ""
    echo "📊 Key Vault certificates:"
    az keyvault certificate list --vault-name $KV_NAME --query "[].{Name:name, Enabled:attributes.enabled}" --output table
}

# Main execution
main() {
    if check_certificates; then
        upload_certificates
        configure_firewall_policy
        create_application_rules
        show_verification
    else
        echo ""
        print_warning "Please copy the certificate files from the CA server first:"
        echo "📁 From CA Server: C:\\temp\\azfw-intermediate-ca.pfx"
        echo "📁 From CA Server: C:\\temp\\azfw-root-ca.cer"
        echo "📁 To Local: $(pwd)/"
        echo ""
        echo "🔄 Then run this script again: ./scripts/upload-certificates.sh"
    fi
}

main
