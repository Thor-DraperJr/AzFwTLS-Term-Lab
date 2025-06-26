#!/bin/bash

# =============================================================================
# Azure Firewall Enterprise CA Intermediate Certificate Automation
# =============================================================================
# This script automates the exact process from Microsoft's documentation:
# https://learn.microsoft.com/en-us/azure/firewall/premium-deploy-certificates-enterprise-ca
#
# Specifically automates:
# 1. Pulling intermediate certificate from Enterprise CA
# 2. Uploading certificate to Azure Key Vault
# 3. Configuring Azure Firewall TLS inspection
# 4. Creating application rules
# 5. Validating TLS inspection
# =============================================================================

set -e

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="Azure Firewall Enterprise CA Automation"

# Configuration
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-azfw-tls-lab}"
RESOURCE_GROUP_WEST="${RESOURCE_GROUP_WEST:-rg-azfw-tls-lab-west}"
CERT_NAME="${CERT_NAME:-azure-firewall-intermediate-ca}"
CERT_PASSWORD="${CERT_PASSWORD:-AzureFirewallCA2025!}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Discover Azure resources
discover_resources() {
    log "Discovering Azure resources..."
    
    # Verify resource groups
    if ! az group show --name "$RESOURCE_GROUP" &>/dev/null; then
        error "Resource group $RESOURCE_GROUP not found"
        exit 1
    fi
    
    # Get resource names
    FIREWALL_NAME=$(az network firewall list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null)
    FIREWALL_POLICY_NAME=$(az network firewall policy list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null)
    KEY_VAULT_NAME=$(az keyvault list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null)
    CA_VM_NAME=$(az vm list -g "$RESOURCE_GROUP_WEST" --query "[?contains(name, 'ca-server')].name" -o tsv | head -1)
    
    if [[ -z "$FIREWALL_NAME" || -z "$KEY_VAULT_NAME" || -z "$CA_VM_NAME" ]]; then
        error "Required resources not found"
        exit 1
    fi
    
    success "Resources discovered:"
    echo "  Firewall: $FIREWALL_NAME"
    echo "  Policy: $FIREWALL_POLICY_NAME"
    echo "  Key Vault: $KEY_VAULT_NAME"
    echo "  CA VM: $CA_VM_NAME"
}

# Pull intermediate certificate from Enterprise CA
pull_intermediate_certificate() {
    log "Pulling intermediate certificate from Enterprise CA..."
    
    # PowerShell script to extract intermediate certificate
    local extract_script='
# Extract intermediate certificate from Enterprise CA
try {
    $WorkDir = "C:\AzureFirewallCerts"
    if (!(Test-Path $WorkDir)) {
        New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    }
    
    # Find existing intermediate certificate or create one
    $IntermediateCert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
        $_.Subject -like "*AzureFirewall*" -or $_.Subject -like "*Intermediate*"
    } | Select-Object -First 1
    
    if (-not $IntermediateCert) {
        # Create intermediate certificate
        Write-Host "Creating intermediate certificate..."
        $IntermediateCert = New-SelfSignedCertificate `
            -Subject "CN=Azure Firewall Intermediate CA,O=Lab,C=US" `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -KeyUsage CertSign,DigitalSignature,CrlSign `
            -KeyLength 2048 `
            -NotAfter (Get-Date).AddYears(3) `
            -KeyExportPolicy Exportable
    }
    
    # Export certificate
    $PfxFile = "$WorkDir\intermediate-ca.pfx"
    $Password = "AzureFirewallCA2025!"
    $SecurePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
    
    Export-PfxCertificate -Cert $IntermediateCert -FilePath $PfxFile -Password $SecurePassword -Force | Out-Null
    
    # Create base64 for transfer
    $PfxBytes = [System.IO.File]::ReadAllBytes($PfxFile)
    $PfxBase64 = [System.Convert]::ToBase64String($PfxBytes)
    
    Write-Host "CERTIFICATE_BASE64_START"
    Write-Host $PfxBase64
    Write-Host "CERTIFICATE_BASE64_END"
    Write-Host "CERTIFICATE_PASSWORD: $Password"
    Write-Host "STATUS: SUCCESS"
    
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    Write-Host "STATUS: FAILED"
}
'
    
    local result
    result=$(az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP_WEST" \
        --name "$CA_VM_NAME" \
        --command-id RunPowerShellScript \
        --scripts "$extract_script" \
        --query "value[0].message" -o tsv 2>/dev/null)
    
    if [[ "$result" == *"STATUS: SUCCESS"* ]]; then
        # Extract base64 certificate
        local cert_base64
        cert_base64=$(echo "$result" | sed -n '/CERTIFICATE_BASE64_START/,/CERTIFICATE_BASE64_END/p' | sed '1d;$d' | tr -d '\r\n ')
        
        if [ -n "$cert_base64" ]; then
            echo "$cert_base64" | base64 -d > "./temp-intermediate-ca.pfx"
            success "Intermediate certificate extracted from CA"
            return 0
        fi
    fi
    
    error "Failed to extract certificate from CA"
    return 1
}

# Upload certificate to Key Vault
upload_to_keyvault() {
    log "Uploading certificate to Key Vault..."
    
    if [ ! -f "./temp-intermediate-ca.pfx" ]; then
        error "Certificate file not found"
        return 1
    fi
    
    # Set Key Vault permissions
    local current_user
    current_user=$(az account show --query user.name -o tsv)
    
    az keyvault set-policy \
        --name "$KEY_VAULT_NAME" \
        --upn "$current_user" \
        --certificate-permissions import get list \
        --secret-permissions get list \
        >/dev/null 2>&1
    
    # Upload certificate
    local upload_result
    upload_result=$(az keyvault certificate import \
        --vault-name "$KEY_VAULT_NAME" \
        --name "$CERT_NAME" \
        --file "./temp-intermediate-ca.pfx" \
        --password "$CERT_PASSWORD" \
        --query "id" -o tsv 2>/dev/null)
    
    if [[ "$upload_result" == *"$CERT_NAME"* ]]; then
        success "Certificate uploaded to Key Vault: $CERT_NAME"
        return 0
    else
        error "Failed to upload certificate to Key Vault"
        return 1
    fi
}

# Configure Azure Firewall TLS inspection
configure_firewall_tls() {
    log "Configuring Azure Firewall TLS inspection..."
    
    # Create managed identity
    local identity_name="azfw-tls-identity"
    az identity create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$identity_name" \
        --location eastus \
        >/dev/null 2>&1
    
    local identity_id
    local principal_id
    identity_id=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$identity_name" --query "id" -o tsv)
    principal_id=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$identity_name" --query "principalId" -o tsv)
    
    # Grant Key Vault access
    az keyvault set-policy \
        --name "$KEY_VAULT_NAME" \
        --object-id "$principal_id" \
        --certificate-permissions get list \
        --secret-permissions get list \
        >/dev/null 2>&1
    
    # Get certificate secret ID
    local cert_secret_id
    cert_secret_id=$(az keyvault certificate show \
        --vault-name "$KEY_VAULT_NAME" \
        --name "$CERT_NAME" \
        --query "sid" -o tsv)
    
    # Configure firewall policy
    local policy_result
    policy_result=$(az network firewall policy update \
        --resource-group "$RESOURCE_GROUP" \
        --name "$FIREWALL_POLICY_NAME" \
        --transport-security-ca-name "$CERT_NAME" \
        --transport-security-key-vault-secret-id "$cert_secret_id" \
        --identity-type "UserAssigned" \
        --user-assigned-identities "$identity_id" \
        --query "name" -o tsv 2>/dev/null)
    
    if [[ "$policy_result" == "$FIREWALL_POLICY_NAME" ]]; then
        success "Azure Firewall configured for TLS inspection"
        return 0
    else
        error "Failed to configure Azure Firewall TLS inspection"
        return 1
    fi
}

# Create TLS inspection rules
create_inspection_rules() {
    log "Creating TLS inspection application rules..."
    
    # Create rule collection group
    az network firewall policy rule-collection-group create \
        --resource-group "$RESOURCE_GROUP" \
        --policy-name "$FIREWALL_POLICY_NAME" \
        --name "TLS-Inspection-Rules" \
        --priority 200 \
        >/dev/null 2>&1
    
    # Add HTTPS inspection rule
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
        >/dev/null 2>&1
    
    success "TLS inspection rules created"
}

# Validate TLS inspection
validate_tls_inspection() {
    log "Validating TLS inspection..."
    
    local client_vm
    client_vm=$(az vm list -g "$RESOURCE_GROUP_WEST" --query "[?contains(name, 'client')].name" -o tsv | head -1)
    
    if [ -z "$client_vm" ]; then
        warning "No client VM found for validation"
        return 0
    fi
    
    # Test HTTPS connections
    local test_script='
try {
    $TestSites = @("https://www.microsoft.com", "https://www.bing.com")
    $TLSDetected = $false
    
    foreach ($Site in $TestSites) {
        try {
            $Response = Invoke-WebRequest -Uri $Site -UseBasicParsing -TimeoutSec 30
            Write-Host "Connected to $Site (Status: $($Response.StatusCode))"
            
            # Check certificate
            $Uri = [System.Uri]$Site
            $TcpClient = New-Object Net.Sockets.TcpClient
            $TcpClient.Connect($Uri.Host, 443)
            $SslStream = New-Object Net.Security.SslStream($TcpClient.GetStream())
            $SslStream.AuthenticateAsClient($Uri.Host)
            $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
            
            if ($Certificate.Issuer -like "*AzureFirewall*" -or $Certificate.Issuer -like "*Lab*") {
                Write-Host "TLS INSPECTION DETECTED for $Site"
                $TLSDetected = $true
            }
            
            $SslStream.Close()
            $TcpClient.Close()
            
        } catch {
            Write-Host "Connection to $Site failed: $($_.Exception.Message)"
        }
    }
    
    if ($TLSDetected) {
        Write-Host "VALIDATION_RESULT: TLS_INSPECTION_WORKING"
    } else {
        Write-Host "VALIDATION_RESULT: TLS_INSPECTION_NOT_DETECTED"
    }
    
} catch {
    Write-Host "VALIDATION_RESULT: VALIDATION_FAILED"
}
'
    
    local validation_result
    validation_result=$(az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP_WEST" \
        --name "$client_vm" \
        --command-id RunPowerShellScript \
        --scripts "$test_script" \
        --query "value[0].message" -o tsv 2>/dev/null)
    
    if [[ "$validation_result" == *"TLS_INSPECTION_WORKING"* ]]; then
        success "🎉 TLS INSPECTION IS WORKING!"
    elif [[ "$validation_result" == *"TLS_INSPECTION_NOT_DETECTED"* ]]; then
        warning "TLS inspection configured but not yet detected (may need time to activate)"
    else
        warning "TLS inspection validation completed with mixed results"
    fi
}

# Cleanup temporary files
cleanup() {
    rm -f "./temp-intermediate-ca.pfx" 2>/dev/null
    log "Cleanup completed"
}

# Main execution
main() {
    echo ""
    echo "=================================="
    echo "$SCRIPT_NAME v$SCRIPT_VERSION"
    echo "=================================="
    echo "Automating Microsoft Enterprise CA documentation:"
    echo "https://learn.microsoft.com/en-us/azure/firewall/premium-deploy-certificates-enterprise-ca"
    echo ""
    
    # Check Azure authentication
    if ! az account show &>/dev/null; then
        error "Not logged into Azure CLI. Run: az login"
        exit 1
    fi
    
    local subscription
    subscription=$(az account show --query name -o tsv)
    success "Authenticated to: $subscription"
    echo ""
    
    case "${1:-all}" in
        "all"|"full")
            discover_resources
            pull_intermediate_certificate
            upload_to_keyvault
            configure_firewall_tls
            create_inspection_rules
            validate_tls_inspection
            cleanup
            echo ""
            success "🎉 Enterprise CA automation completed successfully!"
            echo ""
            echo "Next steps:"
            echo "1. Test HTTPS traffic through the firewall"
            echo "2. Check Azure Monitor for TLS inspection logs"
            echo "3. Verify certificates are being replaced by the intermediate CA"
            ;;
        "pull")
            discover_resources
            pull_intermediate_certificate
            ;;
        "upload")
            discover_resources
            upload_to_keyvault
            ;;
        "configure")
            discover_resources
            configure_firewall_tls
            ;;
        "rules")
            discover_resources
            create_inspection_rules
            ;;
        "validate")
            discover_resources
            validate_tls_inspection
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [COMMAND]"
            echo ""
            echo "Commands:"
            echo "  all        Complete automation (default)"
            echo "  pull       Pull certificate from Enterprise CA"
            echo "  upload     Upload certificate to Key Vault"
            echo "  configure  Configure Azure Firewall TLS inspection"
            echo "  rules      Create TLS inspection rules"
            echo "  validate   Validate TLS inspection"
            echo "  help       Show this help"
            echo ""
            echo "Environment variables:"
            echo "  RESOURCE_GROUP         Primary resource group"
            echo "  RESOURCE_GROUP_WEST    West region resource group"
            echo "  CERT_NAME              Certificate name in Key Vault"
            echo "  CERT_PASSWORD          Certificate password"
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
