#!/bin/bash

# Azure Firewall TLS Inspection Lab - Quick Start Testing Script
# This script helps you begin testing your TLS inspection setup

set -e  # Exit on any error

echo "🔥 Azure Firewall TLS Inspection Lab - Quick Start Testing"
echo "=========================================================="
echo ""

# Configuration
RG_PRIMARY="rg-azfw-tls-lab"
RG_WEST="rg-azfw-tls-lab-west"
KV_NAME="azfw-tls-lab-kv-2025"
FW_POLICY="azfw-tls-lab-policy"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if user is authenticated
check_auth() {
    print_status "Checking Azure authentication..."
    if az account show >/dev/null 2>&1; then
        SUBSCRIPTION=$(az account show --query "name" -o tsv)
        print_success "Authenticated to Azure subscription: $SUBSCRIPTION"
    else
        print_error "Not authenticated to Azure. Run 'az login' first."
        exit 1
    fi
}

# Function to check VM status
check_vm_status() {
    print_status "Checking VM deployment status..."
    
    CA_VM_STATUS=$(az vm get-instance-view --resource-group $RG_WEST --name ca-server-vm --query "instanceView.statuses[1].displayStatus" -o tsv 2>/dev/null || echo "Not Found")
    CLIENT_VM_STATUS=$(az vm get-instance-view --resource-group $RG_WEST --name client-vm --query "instanceView.statuses[1].displayStatus" -o tsv 2>/dev/null || echo "Not Found")
    
    echo "   📋 CA Server VM: $CA_VM_STATUS"
    echo "   📋 Client VM: $CLIENT_VM_STATUS"
    
    if [ "$CA_VM_STATUS" = "VM running" ] && [ "$CLIENT_VM_STATUS" = "VM running" ]; then
        print_success "Both VMs are running and ready for configuration"
        return 0
    else
        print_warning "VMs are not fully ready yet. Please wait a few minutes."
        return 1
    fi
}

# Function to get connection info
get_connection_info() {
    print_status "Getting VM connection information..."
    
    CA_IP=$(az network public-ip show --resource-group $RG_WEST --name ca-server-pip --query "ipAddress" -o tsv 2>/dev/null || echo "Not Available")
    CLIENT_IP=$(az network public-ip show --resource-group $RG_WEST --name client-vm-pip --query "ipAddress" -o tsv 2>/dev/null || echo "Not Available")
    
    echo ""
    echo "🔗 CONNECTION INFORMATION:"
    echo "=========================="
    echo "📊 CA Server VM:"
    echo "   🌐 Public IP: $CA_IP"
    echo "   🔌 RDP: $CA_IP:3389"
    echo "   👤 Username: azureadmin"
    echo "   🔑 Password: SecureP@ssw0rd123!"
    echo ""
    echo "📊 Client VM:"
    echo "   🌐 Public IP: $CLIENT_IP"
    echo "   🔌 RDP: $CLIENT_IP:3389"
    echo "   👤 Username: azureadmin"
    echo "   🔑 Password: SecureP@ssw0rd123!"
    echo ""
}

# Function to create PowerShell script for CA configuration
create_ca_config_script() {
    print_status "Creating PowerShell script for CA configuration..."
    
    cat > ca-setup.ps1 << 'EOF'
# Azure Firewall TLS Lab - CA Server Configuration Script
# Run this script on the CA Server VM after RDP connection

Write-Host "🔐 Azure Firewall TLS Lab - CA Server Setup" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Create temp directory
if (!(Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp"
    Write-Host "✅ Created C:\temp directory" -ForegroundColor Green
}

# Install AD CS Role
Write-Host "📦 Installing Active Directory Certificate Services..." -ForegroundColor Yellow
try {
    Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools -ErrorAction Stop
    Write-Host "✅ AD CS Role installed successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to install AD CS Role: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Configure Certificate Authority
Write-Host "🏗️ Configuring Certificate Authority..." -ForegroundColor Yellow
try {
    Install-AdcsCertificationAuthority `
        -CAType EnterpriseRootCA `
        -CACommonName "AzFirewall-TLS-Lab-CA" `
        -CADistinguishedNameSuffix "DC=azfwlab,DC=local" `
        -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
        -KeyLength 2048 `
        -HashAlgorithmName SHA256 `
        -ValidityPeriod Years `
        -ValidityPeriodUnits 10 `
        -Force `
        -ErrorAction Stop
    Write-Host "✅ Certificate Authority configured successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to configure CA: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Create certificate request file for Azure Firewall
Write-Host "📜 Creating certificate request for Azure Firewall..." -ForegroundColor Yellow

$certReq = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject="CN=Azure-Firewall-Intermediate-CA,O=AzFirewall-TLS-Lab,C=US"
KeyLength=2048
KeyAlgorithm=RSA
MachineKeySet=TRUE
RequestType=PKCS10
KeyUsage=0x86
KeyUsageProperty=0x80

[Extensions]
2.5.29.19 = "{text}CA:TRUE&pathlength:0"
2.5.29.37 = "{text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2"
2.5.29.15 = "{text}Digital Signature, Key Encipherment, Certificate Signing"

[RequestAttributes]
CertificateTemplate=SubCA
"@

try {
    $certReq | Out-File -FilePath "C:\temp\azfw-intermediate-ca.inf" -Encoding ASCII
    Write-Host "✅ Certificate request file created" -ForegroundColor Green
    
    # Create certificate request
    certreq -new "C:\temp\azfw-intermediate-ca.inf" "C:\temp\azfw-intermediate-ca.req"
    Write-Host "✅ Certificate request generated" -ForegroundColor Green
    
    # Submit to CA and retrieve certificate
    certreq -submit -config ".\AzFirewall-TLS-Lab-CA" "C:\temp\azfw-intermediate-ca.req" "C:\temp\azfw-intermediate-ca.cer"
    Write-Host "✅ Certificate issued by CA" -ForegroundColor Green
    
    # Install certificate
    certreq -accept "C:\temp\azfw-intermediate-ca.cer"
    Write-Host "✅ Certificate installed in local store" -ForegroundColor Green
    
} catch {
    Write-Host "❌ Certificate creation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Export certificates
Write-Host "📤 Exporting certificates..." -ForegroundColor Yellow

try {
    # Find and export the intermediate CA certificate
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Azure-Firewall-Intermediate-CA*"}
    if ($cert) {
        $pfxPassword = ConvertTo-SecureString -String "AzFirewall2025!" -Force -AsPlainText
        
        # Export PFX file
        Export-PfxCertificate -Cert $cert -FilePath "C:\temp\azfw-intermediate-ca.pfx" -Password $pfxPassword
        Write-Host "✅ Intermediate CA exported as PFX" -ForegroundColor Green
        
        # Export public certificate
        Export-Certificate -Cert $cert -FilePath "C:\temp\azfw-intermediate-ca.cer"
        Write-Host "✅ Intermediate CA exported as CER" -ForegroundColor Green
    }
    
    # Export root CA certificate
    $rootCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*AzFirewall-TLS-Lab-CA*"}
    if ($rootCert) {
        Export-Certificate -Cert $rootCert -FilePath "C:\temp\azfw-root-ca.cer"
        Write-Host "✅ Root CA exported as CER" -ForegroundColor Green
    }
    
} catch {
    Write-Host "❌ Certificate export failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎉 CA Server setup completed!" -ForegroundColor Green
Write-Host "📁 Certificates are available in C:\temp\" -ForegroundColor Cyan
Write-Host "📋 Next steps:" -ForegroundColor Cyan
Write-Host "   1. Copy certificates to your local machine" -ForegroundColor White
Write-Host "   2. Upload certificates to Azure Key Vault" -ForegroundColor White
Write-Host "   3. Configure Azure Firewall policy for TLS inspection" -ForegroundColor White
EOF

    print_success "CA configuration script created: ca-setup.ps1"
    echo "   📋 Copy this script to the CA server and run it in PowerShell as Administrator"
}

# Function to check Key Vault access
check_key_vault() {
    print_status "Checking Key Vault access..."
    
    if az keyvault show --name $KV_NAME >/dev/null 2>&1; then
        print_success "Key Vault $KV_NAME is accessible"
        
        # Check current certificates
        CERT_COUNT=$(az keyvault certificate list --vault-name $KV_NAME --query "length(@)" -o tsv 2>/dev/null || echo "0")
        echo "   📜 Current certificates in Key Vault: $CERT_COUNT"
    else
        print_error "Cannot access Key Vault $KV_NAME"
        return 1
    fi
}

# Function to check firewall status
check_firewall() {
    print_status "Checking Azure Firewall status..."
    
    FW_STATUS=$(az network firewall show --resource-group $RG_PRIMARY --name azfw-tls-lab-firewall --query "provisioningState" -o tsv 2>/dev/null || echo "Not Found")
    FW_SKU=$(az network firewall show --resource-group $RG_PRIMARY --name azfw-tls-lab-firewall --query "sku.tier" -o tsv 2>/dev/null || echo "Unknown")
    
    echo "   🔥 Firewall Status: $FW_STATUS"
    echo "   🏷️  Firewall SKU: $FW_SKU"
    
    if [ "$FW_STATUS" = "Succeeded" ] && [ "$FW_SKU" = "Premium" ]; then
        print_success "Azure Firewall Premium is ready for TLS inspection"
        return 0
    else
        print_warning "Azure Firewall may not be ready or not Premium tier"
        return 1
    fi
}

# Function to show next steps
show_next_steps() {
    echo ""
    echo "📋 NEXT STEPS - TLS INSPECTION SETUP:"
    echo "====================================="
    echo ""
    echo "1. 🖥️  Connect to CA Server via RDP:"
    echo "   - Host: $(az network public-ip show --resource-group $RG_WEST --name ca-server-pip --query "ipAddress" -o tsv 2>/dev/null)"
    echo "   - Username: azureadmin"
    echo "   - Password: SecureP@ssw0rd123!"
    echo ""
    echo "2. 📦 Run the CA setup script:"
    echo "   - Copy ca-setup.ps1 to the CA server"
    echo "   - Open PowerShell as Administrator"
    echo "   - Run: .\\ca-setup.ps1"
    echo ""
    echo "3. 📤 Download certificates from CA server:"
    echo "   - C:\\temp\\azfw-intermediate-ca.pfx"
    echo "   - C:\\temp\\azfw-root-ca.cer"
    echo ""
    echo "4. 🔐 Upload certificates to Key Vault:"
    echo "   - Run: az keyvault certificate import --vault-name $KV_NAME --name azfw-intermediate-ca --file azfw-intermediate-ca.pfx --password 'AzFirewall2025!'"
    echo ""
    echo "5. 🔥 Configure Azure Firewall for TLS inspection:"
    echo "   - Enable TLS inspection in firewall policy"
    echo "   - Create application rules with TLS inspection"
    echo ""
    echo "6. 🧪 Test TLS inspection:"
    echo "   - Connect to client VM"
    echo "   - Browse HTTPS sites"
    echo "   - Monitor firewall logs"
    echo ""
}

# Main execution
main() {
    check_auth
    echo ""
    
    if check_vm_status; then
        echo ""
        get_connection_info
        check_key_vault
        echo ""
        check_firewall
        echo ""
        create_ca_config_script
        show_next_steps
    else
        echo ""
        print_warning "VMs are still deploying. Please wait and run this script again."
        echo ""
        echo "🔄 You can monitor deployment status with:"
        echo "   ./scripts/monitor-deployment.sh"
    fi
}

# Run main function
main
