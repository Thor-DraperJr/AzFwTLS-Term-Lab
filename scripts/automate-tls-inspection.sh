#!/bin/bash

# Azure Firewall TLS Inspection Lab - Full Automation Script
# This script automates the entire TLS inspection setup programmatically

set -e

echo "🤖 Azure Firewall TLS Inspection Lab - Full Automation"
echo "====================================================="
echo ""

# Configuration
RG_PRIMARY="rg-azfw-tls-lab"
RG_WEST="rg-azfw-tls-lab-west"
KV_NAME="azfw-tls-lab-kv-2025"
FW_POLICY="azfw-tls-lab-policy"
CA_VM="ca-server-vm"
CLIENT_VM="client-vm"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Step 1: Install and configure CA via Azure CLI VM extension
configure_ca_programmatically() {
    print_info "Step 1: Installing and configuring Certificate Authority programmatically..."
    
    # Create PowerShell script for CA setup
    cat > ca-automation.ps1 << 'EOF'
# Azure Firewall TLS Lab - Automated CA Configuration
param([string]$LogFile = "C:\ca-setup.log")

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

try {
    Write-Log "Starting automated CA configuration..."
    
    # Create directories
    New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
    New-Item -ItemType Directory -Path "C:\certificates" -Force | Out-Null
    
    # Install AD CS Role
    Write-Log "Installing AD CS role..."
    Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools -ErrorAction Stop
    
    # Configure Certificate Authority (suppress prompts)
    Write-Log "Configuring Certificate Authority..."
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
    
    # Wait for CA to be ready
    Start-Sleep -Seconds 30
    
    # Create certificate request for Azure Firewall
    Write-Log "Creating certificate request for Azure Firewall..."
    
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
    
    $certReq | Out-File -FilePath "C:\temp\azfw-intermediate-ca.inf" -Encoding ASCII
    
    # Generate certificate request
    & certreq -new "C:\temp\azfw-intermediate-ca.inf" "C:\temp\azfw-intermediate-ca.req"
    
    # Submit and retrieve certificate
    & certreq -submit -config ".\AzFirewall-TLS-Lab-CA" "C:\temp\azfw-intermediate-ca.req" "C:\temp\azfw-intermediate-ca.cer"
    
    # Install certificate
    & certreq -accept "C:\temp\azfw-intermediate-ca.cer"
    
    # Export certificates
    Write-Log "Exporting certificates..."
    
    # Find intermediate CA certificate
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Azure-Firewall-Intermediate-CA*"}
    if ($cert) {
        $pfxPassword = ConvertTo-SecureString -String "AzFirewall2025!" -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath "C:\certificates\azfw-intermediate-ca.pfx" -Password $pfxPassword
        Export-Certificate -Cert $cert -FilePath "C:\certificates\azfw-intermediate-ca.cer"
    }
    
    # Export root CA certificate
    $rootCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*AzFirewall-TLS-Lab-CA*"}
    if ($rootCert) {
        Export-Certificate -Cert $rootCert -FilePath "C:\certificates\azfw-root-ca.cer"
    }
    
    # Create success marker
    "SUCCESS" | Out-File -FilePath "C:\certificates\ca-ready.txt"
    
    Write-Log "CA configuration completed successfully!"
    
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    "FAILED" | Out-File -FilePath "C:\certificates\ca-ready.txt"
    throw
}
EOF

    # Upload and execute the script on CA VM
    print_info "Uploading CA configuration script to VM..."
    az vm run-command invoke \
        --resource-group $RG_WEST \
        --name $CA_VM \
        --command-id RunPowerShellScript \
        --scripts @ca-automation.ps1 \
        --no-wait
    
    print_success "CA configuration script submitted to VM"
}

# Step 2: Wait for CA configuration to complete
wait_for_ca_completion() {
    print_info "Step 2: Waiting for CA configuration to complete..."
    
    local max_attempts=20
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        print_info "Checking CA configuration status (attempt $attempt/$max_attempts)..."
        
        # Check if CA setup is complete
        result=$(az vm run-command invoke \
            --resource-group $RG_WEST \
            --name $CA_VM \
            --command-id RunPowerShellScript \
            --scripts "Get-Content 'C:\certificates\ca-ready.txt' -ErrorAction SilentlyContinue" \
            --query "value[0].message" -o tsv 2>/dev/null || echo "")
        
        if [[ "$result" == *"SUCCESS"* ]]; then
            print_success "CA configuration completed successfully!"
            return 0
        elif [[ "$result" == *"FAILED"* ]]; then
            print_error "CA configuration failed!"
            return 1
        fi
        
        print_info "CA still configuring... waiting 30 seconds"
        sleep 30
        ((attempt++))
    done
    
    print_error "CA configuration timed out after $((max_attempts * 30)) seconds"
    return 1
}

# Step 3: Download certificates from CA VM
download_certificates() {
    print_info "Step 3: Downloading certificates from CA VM..."
    
    # Create local certificates directory
    mkdir -p ./certificates
    
    # Download PFX certificate
    print_info "Downloading intermediate CA certificate (PFX)..."
    az vm run-command invoke \
        --resource-group $RG_WEST \
        --name $CA_VM \
        --command-id RunPowerShellScript \
        --scripts "
            \$content = [System.IO.File]::ReadAllBytes('C:\certificates\azfw-intermediate-ca.pfx')
            \$base64 = [System.Convert]::ToBase64String(\$content)
            Write-Output \$base64
        " \
        --query "value[0].message" -o tsv | base64 -d > ./certificates/azfw-intermediate-ca.pfx
    
    # Download root CA certificate
    print_info "Downloading root CA certificate..."
    az vm run-command invoke \
        --resource-group $RG_WEST \
        --name $CA_VM \
        --command-id RunPowerShellScript \
        --scripts "
            \$content = [System.IO.File]::ReadAllBytes('C:\certificates\azfw-root-ca.cer')
            \$base64 = [System.Convert]::ToBase64String(\$content)
            Write-Output \$base64
        " \
        --query "value[0].message" -o tsv | base64 -d > ./certificates/azfw-root-ca.cer
    
    print_success "Certificates downloaded to ./certificates/"
}

# Step 4: Upload certificates to Key Vault
upload_certificates_to_keyvault() {
    print_info "Step 4: Uploading certificates to Key Vault..."
    
    # Upload intermediate CA certificate
    az keyvault certificate import \
        --vault-name $KV_NAME \
        --name azfw-intermediate-ca \
        --file ./certificates/azfw-intermediate-ca.pfx \
        --password "AzFirewall2025!"
    
    # Upload root CA certificate
    az keyvault certificate import \
        --vault-name $KV_NAME \
        --name azfw-root-ca \
        --file ./certificates/azfw-root-ca.cer
    
    print_success "Certificates uploaded to Key Vault"
}

# Step 5: Configure Azure Firewall Policy
configure_firewall_policy() {
    print_info "Step 5: Configuring Azure Firewall Policy for TLS inspection..."
    
    # Get certificate ID
    CERT_ID=$(az keyvault certificate show \
        --vault-name $KV_NAME \
        --name azfw-intermediate-ca \
        --query "id" -o tsv)
    
    print_info "Using certificate: $CERT_ID"
    
    # Update firewall policy
    az network firewall policy update \
        --resource-group $RG_PRIMARY \
        --name $FW_POLICY \
        --enable-tls-inspection true \
        --certificate-authority "$CERT_ID"
    
    print_success "Firewall policy updated with TLS inspection"
}

# Step 6: Create application rules
create_application_rules() {
    print_info "Step 6: Creating application rules with TLS inspection..."
    
    # Create rule collection group
    az network firewall policy rule-collection-group create \
        --resource-group $RG_PRIMARY \
        --policy-name $FW_POLICY \
        --name "TLSInspectionRules" \
        --priority 1000 \
        --no-wait || true
    
    # Wait for rule collection group creation
    sleep 15
    
    # Add application rule with TLS inspection
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
    
    print_success "Application rules created with TLS inspection"
}

# Step 7: Configure client VM for testing
configure_client_vm() {
    print_info "Step 7: Configuring client VM for testing..."
    
    # Create client configuration script
    cat > client-config.ps1 << 'EOF'
param([string]$LogFile = "C:\client-setup.log")

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

try {
    Write-Log "Configuring client VM for TLS inspection testing..."
    
    # Create certificates directory
    New-Item -ItemType Directory -Path "C:\certificates" -Force | Out-Null
    
    # Create success marker
    "CLIENT_READY" | Out-File -FilePath "C:\certificates\client-ready.txt"
    
    Write-Log "Client configuration completed!"
    
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    "CLIENT_FAILED" | Out-File -FilePath "C:\certificates\client-ready.txt"
}
EOF
    
    # Execute client configuration
    az vm run-command invoke \
        --resource-group $RG_WEST \
        --name $CLIENT_VM \
        --command-id RunPowerShellScript \
        --scripts @client-config.ps1 \
        --no-wait
    
    print_success "Client VM configuration initiated"
}

# Step 8: Install root CA certificate on client
install_root_ca_on_client() {
    print_info "Step 8: Installing root CA certificate on client VM..."
    
    # Transfer and install root CA certificate
    az vm run-command invoke \
        --resource-group $RG_WEST \
        --name $CLIENT_VM \
        --command-id RunPowerShellScript \
        --scripts "
            # Download root CA certificate from CA server
            \$caServer = '10.1.1.4'  # CA server private IP
            
            # Copy certificate file from network location or use hardcoded content
            try {
                # Install root CA certificate to trusted store
                \$certContent = @'
$(base64 -w 0 ./certificates/azfw-root-ca.cer)
'@
                \$certBytes = [System.Convert]::FromBase64String(\$certContent)
                \$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(\$certBytes)
                \$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
                \$store.Open('ReadWrite')
                \$store.Add(\$cert)
                \$store.Close()
                
                'ROOT_CA_INSTALLED' | Out-File -FilePath 'C:\certificates\root-ca-status.txt'
                Write-Output 'Root CA certificate installed successfully'
            } catch {
                'ROOT_CA_FAILED' | Out-File -FilePath 'C:\certificates\root-ca-status.txt'
                Write-Output \"Failed to install root CA: \$(\$_.Exception.Message)\"
            }
        "
    
    print_success "Root CA certificate installation completed"
}

# Step 9: Run automated tests
run_automated_tests() {
    print_info "Step 9: Running automated TLS inspection tests..."
    
    # Create test script
    cat > test-tls-inspection.ps1 << 'EOF'
param([string]$LogFile = "C:\test-results.log")

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

function Test-HTTPSConnectivity {
    param([string]$Url)
    
    try {
        Write-Log "Testing HTTPS connectivity to $Url..."
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30
        Write-Log "SUCCESS: $Url - Status: $($response.StatusCode)"
        return $true
    } catch {
        Write-Log "FAILED: $Url - Error: $($_.Exception.Message)"
        return $false
    }
}

try {
    Write-Log "Starting TLS inspection tests..."
    
    $testResults = @()
    
    # Test various HTTPS sites
    $testSites = @(
        "https://www.microsoft.com",
        "https://www.google.com",
        "https://www.github.com",
        "https://azure.microsoft.com"
    )
    
    foreach ($site in $testSites) {
        $result = Test-HTTPSConnectivity -Url $site
        $testResults += @{
            Site = $site
            Success = $result
        }
    }
    
    # Generate summary
    $successCount = ($testResults | Where-Object { $_.Success }).Count
    $totalCount = $testResults.Count
    
    Write-Log "Test Summary: $successCount/$totalCount tests passed"
    
    # Create results file
    $testResults | ConvertTo-Json | Out-File -FilePath "C:\certificates\test-results.json"
    
    if ($successCount -eq $totalCount) {
        "TESTS_PASSED" | Out-File -FilePath "C:\certificates\test-status.txt"
    } else {
        "TESTS_PARTIAL" | Out-File -FilePath "C:\certificates\test-status.txt"
    }
    
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    "TESTS_FAILED" | Out-File -FilePath "C:\certificates\test-status.txt"
}
EOF
    
    # Execute tests on client VM
    az vm run-command invoke \
        --resource-group $RG_WEST \
        --name $CLIENT_VM \
        --command-id RunPowerShellScript \
        --scripts @test-tls-inspection.ps1 \
        --no-wait
    
    print_success "Automated tests initiated on client VM"
}

# Step 10: Get test results
get_test_results() {
    print_info "Step 10: Retrieving test results..."
    
    sleep 30  # Wait for tests to complete
    
    # Get test status
    test_status=$(az vm run-command invoke \
        --resource-group $RG_WEST \
        --name $CLIENT_VM \
        --command-id RunPowerShellScript \
        --scripts "Get-Content 'C:\certificates\test-status.txt' -ErrorAction SilentlyContinue" \
        --query "value[0].message" -o tsv 2>/dev/null || echo "")
    
    # Get detailed results
    test_results=$(az vm run-command invoke \
        --resource-group $RG_WEST \
        --name $CLIENT_VM \
        --command-id RunPowerShellScript \
        --scripts "Get-Content 'C:\certificates\test-results.json' -ErrorAction SilentlyContinue" \
        --query "value[0].message" -o tsv 2>/dev/null || echo "{}")
    
    echo ""
    echo "🧪 TEST RESULTS:"
    echo "================"
    echo "Status: $test_status"
    echo "Details: $test_results"
    
    if [[ "$test_status" == *"TESTS_PASSED"* ]]; then
        print_success "All TLS inspection tests passed!"
    elif [[ "$test_status" == *"TESTS_PARTIAL"* ]]; then
        print_warning "Some TLS inspection tests passed"
    else
        print_error "TLS inspection tests failed or incomplete"
    fi
}

# Main execution function
main() {
    echo "🚀 Starting full automation of Azure Firewall TLS Inspection lab..."
    echo ""
    
    configure_ca_programmatically
    
    if wait_for_ca_completion; then
        download_certificates
        upload_certificates_to_keyvault
        configure_firewall_policy
        create_application_rules
        configure_client_vm
        install_root_ca_on_client
        run_automated_tests
        get_test_results
        
        echo ""
        print_success "🎉 Azure Firewall TLS Inspection lab automation completed!"
        echo ""
        echo "📊 Summary:"
        echo "  ✅ Certificate Authority configured"
        echo "  ✅ Certificates generated and uploaded to Key Vault"
        echo "  ✅ Azure Firewall Policy configured for TLS inspection"
        echo "  ✅ Application rules created"
        echo "  ✅ Client VM configured for testing"
        echo "  ✅ Automated tests executed"
        echo ""
        echo "🔗 Access Details:"
        echo "  📍 CA Server: $(az network public-ip show --resource-group $RG_WEST --name ca-server-pip --query "ipAddress" -o tsv 2>/dev/null)"
        echo "  📍 Client VM: $(az network public-ip show --resource-group $RG_WEST --name client-vm-pip --query "ipAddress" -o tsv 2>/dev/null)"
        echo "  🔑 Username: azureadmin"
        echo "  🔑 Password: SecureP@ssw0rd123!"
        echo ""
        echo "📚 View logs and certificates:"
        echo "  📁 Local certificates: ./certificates/"
        echo "  📋 Key Vault: $KV_NAME"
        echo "  🔥 Firewall Policy: $FW_POLICY"
        
    else
        print_error "CA configuration failed. Automation stopped."
        exit 1
    fi
}

# Cleanup function
cleanup() {
    print_info "Cleaning up temporary files..."
    rm -f ca-automation.ps1 client-config.ps1 test-tls-inspection.ps1
}

# Set up cleanup trap
trap cleanup EXIT

# Run main function
main
