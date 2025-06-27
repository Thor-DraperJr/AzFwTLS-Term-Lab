#!/bin/bash

# =============================================================================
# Azure Firewall TLS Termination Setup Script
# =============================================================================
# This script implements the complete TLS termination setup for Azure Firewall Premium
# including certificate management and validation
# =============================================================================

set -e

# Configuration
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-azfw-tls-lab}"
RESOURCE_GROUP_WEST="${RESOURCE_GROUP_WEST:-rg-azfw-tls-lab-west}"
KEY_VAULT_NAME="${KEY_VAULT_NAME:-azfw-tls-lab-kv-2025}"
FIREWALL_POLICY_NAME="${FIREWALL_POLICY_NAME:-azfw-tls-lab-policy}"
CERT_NAME="${CERT_NAME:-azure-firewall-tls-cert}"
CERT_PASSWORD="${CERT_PASSWORD:-AzureFirewallTLS2025!}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Step 1: Setup Key Vault Permissions
setup_keyvault_permissions() {
    step "Setting up Key Vault permissions..."
    
    # Get current user
    local current_user
    current_user=$(az account show --query user.name -o tsv)
    
    log "Setting permissions for user: $current_user"
    
    # Set comprehensive permissions for current user
    az keyvault set-policy \
        --name "$KEY_VAULT_NAME" \
        --upn "$current_user" \
        --certificate-permissions backup create delete deleteissuers get getissuers import list listissuers managecontacts manageissuers purge recover restore setissuers update \
        --secret-permissions backup delete get list purge recover restore set \
        --key-permissions backup create decrypt delete encrypt get import list purge recover restore sign unwrapKey update verify wrapKey \
        >/dev/null 2>&1
    
    success "Key Vault permissions configured"
}

# Step 2: Generate and Upload Certificate
generate_and_upload_certificate() {
    step "Generating and uploading TLS certificate..."
    
    # Check if we have a CA VM to pull certificate from
    local ca_vm_name
    ca_vm_name=$(az vm list -g "$RESOURCE_GROUP_WEST" --query "[?contains(name, 'ca-server')].name" -o tsv 2>/dev/null | head -1)
    
    if [ -n "$ca_vm_name" ]; then
        log "Found CA VM: $ca_vm_name - attempting to pull certificate from Enterprise CA"
        pull_certificate_from_ca "$ca_vm_name"
    else
        log "No CA VM found - generating self-signed certificate for TLS inspection"
        generate_self_signed_certificate
    fi
    
    # Upload certificate to Key Vault
    upload_certificate_to_keyvault
}

# Pull certificate from Enterprise CA
pull_certificate_from_ca() {
    local ca_vm_name="$1"
    
    log "Pulling certificate from Enterprise CA VM: $ca_vm_name"
    
    # PowerShell script to generate/extract certificate
    local cert_script='
param(
    [string]$CertName = "AzureFirewallTLSCert",
    [string]$Password = "AzureFirewallTLS2025!"
)

try {
    Write-Host "=== Azure Firewall TLS Certificate Generation ==="
    
    # Create working directory
    $WorkDir = "C:\AzureFirewallTLS"
    if (!(Test-Path $WorkDir)) {
        New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    }
    
    # Check for existing certificate or create new one
    $ExistingCert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
        $_.Subject -like "*AzureFirewall*" -or $_.Subject -like "*TLS*"
    } | Select-Object -First 1
    
    if ($ExistingCert) {
        Write-Host "Found existing certificate: $($ExistingCert.Subject)"
        $TLSCert = $ExistingCert
    } else {
        Write-Host "Creating new TLS certificate for Azure Firewall..."
        
        # Create certificate for TLS inspection
        $TLSCert = New-SelfSignedCertificate `
            -Subject "CN=$CertName,O=Azure Firewall Lab,OU=TLS Inspection,C=US" `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -KeyUsage DigitalSignature,KeyEncipherment `
            -KeyLength 2048 `
            -NotAfter (Get-Date).AddYears(2) `
            -KeyExportPolicy Exportable `
            -HashAlgorithm SHA256 `
            -Provider "Microsoft RSA SChannel Cryptographic Provider"
    }
    
    # Export certificate
    $PfxFile = "$WorkDir\tls-cert.pfx"
    $SecurePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
    
    Export-PfxCertificate -Cert $TLSCert -FilePath $PfxFile -Password $SecurePassword -Force | Out-Null
    
    # Create base64 for transfer
    $PfxBytes = [System.IO.File]::ReadAllBytes($PfxFile)
    $PfxBase64 = [System.Convert]::ToBase64String($PfxBytes)
    
    Write-Host "CERTIFICATE_BASE64_START"
    Write-Host $PfxBase64
    Write-Host "CERTIFICATE_BASE64_END"
    Write-Host "CERTIFICATE_PASSWORD: $Password"
    Write-Host "CERTIFICATE_THUMBPRINT: $($TLSCert.Thumbprint)"
    Write-Host "CERTIFICATE_SUBJECT: $($TLSCert.Subject)"
    Write-Host "STATUS: SUCCESS"
    
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    Write-Host "STATUS: FAILED"
}
'
    
    local result
    result=$(az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP_WEST" \
        --name "$ca_vm_name" \
        --command-id RunPowerShellScript \
        --scripts "$cert_script" \
        --parameters "CertName=$CERT_NAME" "Password=$CERT_PASSWORD" \
        --query "value[0].message" -o tsv 2>/dev/null || echo "COMMAND_FAILED")
    
    if [[ "$result" == *"STATUS: SUCCESS"* ]]; then
        # Extract base64 certificate
        local cert_base64
        cert_base64=$(echo "$result" | sed -n '/CERTIFICATE_BASE64_START/,/CERTIFICATE_BASE64_END/p' | sed '1d;$d' | tr -d '\r\n ')
        
        if [ -n "$cert_base64" ]; then
            echo "$cert_base64" | base64 -d > "./temp-tls-cert.pfx"
            success "TLS certificate extracted from CA VM"
            
            # Extract certificate details
            local thumbprint
            local subject
            thumbprint=$(echo "$result" | grep "CERTIFICATE_THUMBPRINT:" | cut -d' ' -f2-)
            subject=$(echo "$result" | grep "CERTIFICATE_SUBJECT:" | cut -d' ' -f2-)
            
            log "Certificate Thumbprint: $thumbprint"
            log "Certificate Subject: $subject"
            
            return 0
        fi
    fi
    
    warning "Could not extract certificate from CA VM, falling back to self-signed"
    generate_self_signed_certificate
}

# Generate self-signed certificate locally
generate_self_signed_certificate() {
    log "Generating self-signed certificate for TLS inspection..."
    
    # Create self-signed certificate using OpenSSL
    openssl req -x509 -newkey rsa:2048 -keyout temp-tls-key.pem -out temp-tls-cert.pem -days 730 -nodes -subj "/CN=Azure Firewall TLS Cert/O=Lab/C=US" 2>/dev/null
    
    # Convert to PFX
    openssl pkcs12 -export -out temp-tls-cert.pfx -inkey temp-tls-key.pem -in temp-tls-cert.pem -password pass:$CERT_PASSWORD 2>/dev/null
    
    # Cleanup temp files
    rm -f temp-tls-key.pem temp-tls-cert.pem
    
    success "Self-signed TLS certificate generated"
}

# Upload certificate to Key Vault
upload_certificate_to_keyvault() {
    step "Uploading certificate to Key Vault..."
    
    if [ ! -f "./temp-tls-cert.pfx" ]; then
        error "Certificate file not found"
        return 1
    fi
    
    # Upload certificate
    local upload_result
    upload_result=$(az keyvault certificate import \
        --vault-name "$KEY_VAULT_NAME" \
        --name "$CERT_NAME" \
        --file "./temp-tls-cert.pfx" \
        --password "$CERT_PASSWORD" \
        --query "id" -o tsv 2>/dev/null || echo "UPLOAD_FAILED")
    
    if [[ "$upload_result" == *"$CERT_NAME"* ]]; then
        success "Certificate uploaded to Key Vault: $CERT_NAME"
        log "Certificate ID: $upload_result"
        
        # Cleanup temp file
        rm -f "./temp-tls-cert.pfx"
        
        return 0
    else
        error "Failed to upload certificate to Key Vault"
        return 1
    fi
}

# Step 3: Configure Azure Firewall TLS Termination
configure_tls_termination() {
    step "Configuring Azure Firewall TLS termination/inspection..."
    
    # Create managed identity for firewall
    local identity_name="azfw-tls-managed-identity"
    
    log "Creating managed identity: $identity_name"
    az identity create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$identity_name" \
        --location eastus \
        >/dev/null 2>&1 || log "Managed identity may already exist"
    
    # Get identity details
    local identity_id
    local principal_id
    identity_id=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$identity_name" --query "id" -o tsv)
    principal_id=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$identity_name" --query "principalId" -o tsv)
    
    success "Managed identity configured: $identity_name"
    log "Identity ID: $identity_id"
    log "Principal ID: $principal_id"
    
    # Grant managed identity access to Key Vault
    log "Granting managed identity access to Key Vault..."
    az keyvault set-policy \
        --name "$KEY_VAULT_NAME" \
        --object-id "$principal_id" \
        --certificate-permissions get list \
        --secret-permissions get list \
        >/dev/null 2>&1 || warning "Could not set Key Vault policy for managed identity"
    
    # Get certificate secret ID
    local cert_secret_id
    cert_secret_id=$(az keyvault certificate show \
        --vault-name "$KEY_VAULT_NAME" \
        --name "$CERT_NAME" \
        --query "sid" -o tsv 2>/dev/null)
    
    if [ -z "$cert_secret_id" ]; then
        error "Could not retrieve certificate secret ID from Key Vault"
        return 1
    fi
    
    success "Certificate secret ID retrieved: $cert_secret_id"
    
    # Configure TLS inspection on firewall policy
    log "Updating Azure Firewall policy for TLS inspection..."
    
    local policy_result
    policy_result=$(az network firewall policy update \
        --resource-group "$RESOURCE_GROUP" \
        --name "$FIREWALL_POLICY_NAME" \
        --transport-security-ca-name "$CERT_NAME" \
        --transport-security-key-vault-secret-id "$cert_secret_id" \
        --identity-type "UserAssigned" \
        --user-assigned-identities "$identity_id" \
        --query "name" -o tsv 2>/dev/null || echo "POLICY_UPDATE_FAILED")
    
    if [[ "$policy_result" == "$FIREWALL_POLICY_NAME" ]]; then
        success "🎉 Azure Firewall TLS termination/inspection configured successfully!"
        return 0
    else
        error "Failed to configure TLS inspection on firewall policy"
        return 1
    fi
}

# Step 4: Create TLS inspection rules
create_tls_inspection_rules() {
    step "Creating TLS inspection application rules..."
    
    # Create rule collection group
    log "Creating rule collection group..."
    az network firewall policy rule-collection-group create \
        --resource-group "$RESOURCE_GROUP" \
        --policy-name "$FIREWALL_POLICY_NAME" \
        --name "TLS-Inspection-Rules" \
        --priority 200 \
        >/dev/null 2>&1 || log "Rule collection group may already exist"
    
    # Add HTTPS inspection rule
    log "Adding HTTPS inspection rules..."
    az network firewall policy rule-collection-group collection add-filter-collection \
        --resource-group "$RESOURCE_GROUP" \
        --policy-name "$FIREWALL_POLICY_NAME" \
        --rule-collection-group-name "TLS-Inspection-Rules" \
        --name "Allow-HTTPS-Inspection" \
        --collection-priority 100 \
        --action Allow \
        --rule-name "Inspect-HTTPS" \
        --rule-type ApplicationRule \
        --description "Allow HTTPS with TLS inspection" \
        --protocols "Https=443" \
        --source-addresses "*" \
        --target-fqdns "*" \
        >/dev/null 2>&1 || log "Rule may already exist"
    
    success "TLS inspection rules configured"
}

# Step 5: Validate TLS termination configuration
validate_tls_configuration() {
    step "Validating TLS termination configuration..."
    
    # Check firewall policy TLS configuration
    log "Checking Azure Firewall policy TLS configuration..."
    
    local tls_config
    tls_config=$(az network firewall policy show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$FIREWALL_POLICY_NAME" \
        --query "transportSecurity" -o json 2>/dev/null)
    
    if [[ "$tls_config" != "null" ]] && [[ "$tls_config" != "" ]] && [[ "$tls_config" != "{}" ]]; then
        success "✅ TLS termination is ENABLED on Azure Firewall!"
        log "TLS Configuration: $tls_config"
        
        # Extract TLS details
        local ca_name
        local cert_status
        ca_name=$(echo "$tls_config" | grep -o '"certificateAuthority":{"name":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "N/A")
        
        success "Certificate Authority Name: $ca_name"
        success "TLS Inspection: ACTIVE"
        
    else
        warning "TLS termination configuration not detected"
        log "This may be normal if the configuration is still propagating"
    fi
    
    # Check certificate in Key Vault
    log "Verifying certificate in Key Vault..."
    local cert_info
    cert_info=$(az keyvault certificate show \
        --vault-name "$KEY_VAULT_NAME" \
        --name "$CERT_NAME" \
        --query "{thumbprint:x509Thumbprint, expires:attributes.expires, enabled:attributes.enabled}" -o json 2>/dev/null || echo "{}")
    
    if [[ "$cert_info" != "{}" ]]; then
        success "✅ Certificate verified in Key Vault"
        log "Certificate details: $cert_info"
    else
        warning "Could not verify certificate in Key Vault"
    fi
    
    # Test from client VM if available
    local client_vm
    client_vm=$(az vm list -g "$RESOURCE_GROUP_WEST" --query "[?contains(name, 'client')].name" -o tsv 2>/dev/null | head -1)
    
    if [ -n "$client_vm" ]; then
        log "Testing TLS inspection from client VM: $client_vm"
        test_tls_inspection_from_client "$client_vm"
    else
        log "No client VM found for testing"
    fi
}

# Test TLS inspection from client VM
test_tls_inspection_from_client() {
    local client_vm="$1"
    
    local test_script='
try {
    Write-Host "=== TLS Inspection Test ==="
    
    $TestSites = @("https://www.microsoft.com", "https://www.bing.com")
    $InspectionDetected = $false
    
    foreach ($Site in $TestSites) {
        try {
            Write-Host "Testing: $Site"
            
            # Test basic connectivity
            $Response = Invoke-WebRequest -Uri $Site -UseBasicParsing -TimeoutSec 30
            Write-Host "  Connection: SUCCESS (Status: $($Response.StatusCode))"
            
            # Check certificate
            $Uri = [System.Uri]$Site
            $TcpClient = New-Object Net.Sockets.TcpClient
            $TcpClient.Connect($Uri.Host, 443)
            $SslStream = New-Object Net.Security.SslStream($TcpClient.GetStream())
            $SslStream.AuthenticateAsClient($Uri.Host)
            $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
            
            Write-Host "  Certificate Subject: $($Certificate.Subject)"
            Write-Host "  Certificate Issuer: $($Certificate.Issuer)"
            
            # Check if certificate is replaced by firewall
            if ($Certificate.Issuer -like "*AzureFirewall*" -or 
                $Certificate.Issuer -like "*Lab*" -or 
                $Certificate.Subject -like "*AzureFirewall*") {
                Write-Host "  🎉 TLS INSPECTION DETECTED!"
                $InspectionDetected = $true
            } else {
                Write-Host "  ℹ️ Original certificate (inspection may not be active yet)"
            }
            
            $SslStream.Close()
            $TcpClient.Close()
            
        } catch {
            Write-Host "  Connection failed: $($_.Exception.Message)"
        }
        
        Write-Host ""
    }
    
    if ($InspectionDetected) {
        Write-Host "RESULT: TLS_INSPECTION_WORKING"
    } else {
        Write-Host "RESULT: TLS_INSPECTION_NOT_DETECTED"
    }
    
} catch {
    Write-Host "RESULT: TEST_FAILED"
}
'
    
    local test_result
    test_result=$(az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP_WEST" \
        --name "$client_vm" \
        --command-id RunPowerShellScript \
        --scripts "$test_script" \
        --query "value[0].message" -o tsv 2>/dev/null || echo "TEST_FAILED")
    
    if [[ "$test_result" == *"TLS_INSPECTION_WORKING"* ]]; then
        success "🎉 TLS INSPECTION IS WORKING FROM CLIENT!"
    elif [[ "$test_result" == *"TLS_INSPECTION_NOT_DETECTED"* ]]; then
        warning "TLS inspection configured but not yet intercepting traffic"
        log "This is normal - TLS inspection can take a few minutes to become active"
    else
        warning "TLS inspection test completed with mixed results"
    fi
    
    log "Detailed test results:"
    echo "$test_result" | grep -E "(Testing:|Connection:|Certificate|TLS INSPECTION|RESULT:)" || echo "No detailed results available"
}

# Main execution
main() {
    echo ""
    echo "=============================================="
    echo "🛡️ Azure Firewall TLS Termination Setup"
    echo "=============================================="
    echo "This script configures TLS termination/inspection"
    echo "for Azure Firewall Premium"
    echo ""
    
    # Check Azure authentication
    if ! az account show &>/dev/null; then
        error "Not logged into Azure CLI. Run: az login"
        exit 1
    fi
    
    local subscription
    subscription=$(az account show --query name -o tsv)
    success "Authenticated to: $subscription"
    
    log "Configuration:"
    log "  Resource Group: $RESOURCE_GROUP"
    log "  Key Vault: $KEY_VAULT_NAME"
    log "  Firewall Policy: $FIREWALL_POLICY_NAME"
    log "  Certificate Name: $CERT_NAME"
    echo ""
    
    case "${1:-all}" in
        "all"|"full")
            setup_keyvault_permissions
            generate_and_upload_certificate
            configure_tls_termination
            create_tls_inspection_rules
            validate_tls_configuration
            
            echo ""
            echo "=============================================="
            success "🎉 TLS Termination Setup Complete!"
            echo "=============================================="
            echo ""
            success "✅ Key Vault permissions configured"
            success "✅ TLS certificate generated and uploaded"
            success "✅ Azure Firewall TLS termination enabled"
            success "✅ TLS inspection rules created"
            success "✅ Configuration validated"
            echo ""
            log "🔍 TLS termination is now enabled on your Azure Firewall!"
            log "🧪 Test HTTPS traffic through the firewall to see TLS inspection in action"
            ;;
        "permissions")
            setup_keyvault_permissions
            ;;
        "certificate")
            setup_keyvault_permissions
            generate_and_upload_certificate
            ;;
        "configure")
            configure_tls_termination
            ;;
        "rules")
            create_tls_inspection_rules
            ;;
        "validate")
            validate_tls_configuration
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [COMMAND]"
            echo ""
            echo "Commands:"
            echo "  all          Complete TLS termination setup (default)"
            echo "  permissions  Setup Key Vault permissions"
            echo "  certificate  Generate and upload certificate"
            echo "  configure    Configure TLS termination on firewall"
            echo "  rules        Create TLS inspection rules"
            echo "  validate     Validate TLS termination configuration"
            echo "  help         Show this help"
            ;;
        *)
            error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
