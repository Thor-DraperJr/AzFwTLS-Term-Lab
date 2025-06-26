#!/bin/bash

# Azure Key Vault Certificate Upload Script
# This script uploads the intermediate CA certificate to Azure Key Vault for Azure Firewall TLS inspection

set -e

# Configuration
RESOURCE_GROUP_NAME="rg-azfw-tls-lab"
KEY_VAULT_NAME=""  # Will be retrieved from deployment
CERTIFICATE_NAME="azfw-tls-intermediate-ca"
CERTIFICATE_PATH=""  # Path to the PFX file

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Function to get Key Vault name from deployment
get_keyvault_name() {
    print_status "Retrieving Key Vault name from deployment..."
    
    DEPLOYMENT_NAME=$(az deployment group list \
        --resource-group $RESOURCE_GROUP_NAME \
        --query "[?contains(name, 'azfw-tls-lab')].name" \
        --output tsv | head -1)
    
    if [ -z "$DEPLOYMENT_NAME" ]; then
        print_error "No deployment found in resource group $RESOURCE_GROUP_NAME"
        exit 1
    fi
    
    KEY_VAULT_NAME=$(az deployment group show \
        --resource-group $RESOURCE_GROUP_NAME \
        --name $DEPLOYMENT_NAME \
        --query 'properties.outputs.keyVaultName.value' \
        --output tsv)
    
    if [ -z "$KEY_VAULT_NAME" ]; then
        print_error "Could not retrieve Key Vault name from deployment"
        exit 1
    fi
    
    print_success "Found Key Vault: $KEY_VAULT_NAME"
}

# Function to check if certificate file exists
check_certificate_file() {
    if [ -z "$CERTIFICATE_PATH" ]; then
        print_error "Certificate path not specified. Use -f option to specify the PFX file path."
        show_usage
        exit 1
    fi
    
    if [ ! -f "$CERTIFICATE_PATH" ]; then
        print_error "Certificate file not found: $CERTIFICATE_PATH"
        exit 1
    fi
    
    print_success "Certificate file found: $CERTIFICATE_PATH"
}

# Function to upload certificate to Key Vault
upload_certificate() {
    print_status "Uploading certificate to Key Vault..."
    
    # Check if certificate already exists
    if az keyvault certificate show --vault-name $KEY_VAULT_NAME --name $CERTIFICATE_NAME &> /dev/null; then
        print_warning "Certificate '$CERTIFICATE_NAME' already exists in Key Vault."
        read -p "Do you want to update it? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Upload cancelled."
            exit 0
        fi
    fi
    
    # Upload the certificate
    az keyvault certificate import \
        --vault-name $KEY_VAULT_NAME \
        --name $CERTIFICATE_NAME \
        --file "$CERTIFICATE_PATH" \
        --password ""
    
    print_success "Certificate uploaded successfully!"
    
    # Get certificate details
    CERT_ID=$(az keyvault certificate show \
        --vault-name $KEY_VAULT_NAME \
        --name $CERTIFICATE_NAME \
        --query 'id' \
        --output tsv)
    
    SECRET_ID=$(az keyvault certificate show \
        --vault-name $KEY_VAULT_NAME \
        --name $CERTIFICATE_NAME \
        --query 'sid' \
        --output tsv)
    
    print_success "Certificate Details:"
    echo "  Certificate ID: $CERT_ID"
    echo "  Secret ID: $SECRET_ID"
}

# Function to configure Azure Firewall policy
configure_firewall_policy() {
    print_status "Configuring Azure Firewall policy for TLS inspection..."
    
    # Get firewall policy name
    FIREWALL_POLICY_NAME=$(az deployment group show \
        --resource-group $RESOURCE_GROUP_NAME \
        --name $DEPLOYMENT_NAME \
        --query 'properties.outputs.firewallPolicyName.value' \
        --output tsv)
    
    if [ -z "$FIREWALL_POLICY_NAME" ]; then
        print_error "Could not retrieve Firewall Policy name"
        exit 1
    fi
    
    # Get the secret ID for the certificate
    SECRET_ID=$(az keyvault certificate show \
        --vault-name $KEY_VAULT_NAME \
        --name $CERTIFICATE_NAME \
        --query 'sid' \
        --output tsv)
    
    # Update firewall policy with TLS inspection certificate
    az network firewall policy update \
        --resource-group $RESOURCE_GROUP_NAME \
        --name $FIREWALL_POLICY_NAME \
        --cert-name "TLSInspectionCA" \
        --key-vault-secret-id "$SECRET_ID"
    
    print_success "Firewall policy updated with TLS inspection certificate!"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 -f <certificate_path> [options]"
    echo ""
    echo "Options:"
    echo "  -f <path>    Path to the intermediate CA certificate PFX file (required)"
    echo "  -g <name>    Resource group name (default: $RESOURCE_GROUP_NAME)"
    echo "  -n <name>    Certificate name in Key Vault (default: $CERTIFICATE_NAME)"
    echo "  -h           Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 -f /path/to/IntermediateCA-AzureFirewall.pfx"
}

# Function to show next steps
show_next_steps() {
    echo ""
    echo "=== NEXT STEPS ==="
    echo "1. Enable TLS inspection on specific application rules in the firewall policy"
    echo "2. Deploy the root CA certificate to client machines"
    echo "3. Test TLS inspection by browsing to HTTPS sites from the client VM"
    echo "4. Monitor firewall logs to verify TLS inspection is working"
    echo ""
    echo "To enable TLS inspection on application rules, use:"
    echo "az network firewall policy rule-collection-group collection rule update \\"
    echo "  --resource-group $RESOURCE_GROUP_NAME \\"
    echo "  --policy-name $FIREWALL_POLICY_NAME \\"
    echo "  --rule-collection-group-name 'DefaultApplicationRuleCollectionGroup' \\"
    echo "  --collection-name 'ApplicationRuleCollection' \\"
    echo "  --name 'AllowWeb' \\"
    echo "  --terminate-tls true"
    echo ""
}

# Parse command line arguments
while getopts "f:g:n:h" opt; do
    case $opt in
        f)
            CERTIFICATE_PATH="$OPTARG"
            ;;
        g)
            RESOURCE_GROUP_NAME="$OPTARG"
            ;;
        n)
            CERTIFICATE_NAME="$OPTARG"
            ;;
        h)
            show_usage
            exit 0
            ;;
        \?)
            print_error "Invalid option: -$OPTARG"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    echo ""
    echo "=================================="
    echo "Azure Key Vault Certificate Upload"
    echo "for Azure Firewall TLS Inspection"
    echo "=================================="
    echo ""
    
    # Validate inputs
    check_certificate_file
    
    # Get Azure resources
    get_keyvault_name
    
    # Upload certificate
    upload_certificate
    
    # Configure firewall policy
    configure_firewall_policy
    
    # Show next steps
    show_next_steps
    
    print_success "Certificate upload and configuration completed!"
}

# Check if required parameters are provided
if [ $# -eq 0 ]; then
    print_error "No arguments provided."
    show_usage
    exit 1
fi

# Run main function
main
