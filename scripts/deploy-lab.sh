#!/bin/bash

# Azure Firewall TLS Inspection Lab Deployment Script
# This script deploys the complete lab infrastructure using Bicep templates

set -e  # Exit on any error

# Configuration
RESOURCE_GROUP_NAME="rg-azfw-tls-lab"
LOCATION="eastus"
DEPLOYMENT_NAME="azfw-tls-lab-$(date +%Y%m%d-%H%M%S)"
BICEP_TEMPLATE="./bicep/main.bicep"
PARAMETERS_FILE="./bicep/parameters/lab.parameters.json"

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

# Function to check if user is logged in to Azure
check_azure_login() {
    print_status "Checking Azure login status..."
    if ! az account show &> /dev/null; then
        print_error "Not logged in to Azure. Please run 'az login' first."
        exit 1
    fi
    
    CURRENT_SUBSCRIPTION=$(az account show --query name -o tsv)
    print_success "Logged in to Azure. Current subscription: $CURRENT_SUBSCRIPTION"
}

# Function to create resource group
create_resource_group() {
    print_status "Creating resource group '$RESOURCE_GROUP_NAME' in '$LOCATION'..."
    
    if az group show --name $RESOURCE_GROUP_NAME &> /dev/null; then
        print_warning "Resource group '$RESOURCE_GROUP_NAME' already exists."
    else
        az group create --name $RESOURCE_GROUP_NAME --location $LOCATION
        print_success "Resource group '$RESOURCE_GROUP_NAME' created successfully."
    fi
}

# Function to validate Bicep template
validate_template() {
    print_status "Validating Bicep template..."
    
    az deployment group validate \
        --resource-group $RESOURCE_GROUP_NAME \
        --template-file $BICEP_TEMPLATE \
        --parameters @$PARAMETERS_FILE
        
    print_success "Bicep template validation passed."
}

# Function to deploy the template
deploy_template() {
    print_status "Deploying Azure Firewall TLS Lab infrastructure..."
    print_warning "This deployment may take 15-30 minutes to complete."
    
    az deployment group create \
        --resource-group $RESOURCE_GROUP_NAME \
        --name $DEPLOYMENT_NAME \
        --template-file $BICEP_TEMPLATE \
        --parameters @$PARAMETERS_FILE \
        --verbose
        
    print_success "Deployment completed successfully!"
}

# Function to show deployment outputs
show_outputs() {
    print_status "Retrieving deployment outputs..."
    
    echo ""
    echo "=== DEPLOYMENT OUTPUTS ==="
    az deployment group show \
        --resource-group $RESOURCE_GROUP_NAME \
        --name $DEPLOYMENT_NAME \
        --query 'properties.outputs' \
        --output table
    echo ""
}

# Function to show next steps
show_next_steps() {
    echo ""
    echo "=== NEXT STEPS ==="
    echo "1. Wait for VMs to finish provisioning (check in Azure Portal)"
    echo "2. Connect to the CA server VM to configure Active Directory and Certificate Services"
    echo "3. Generate the intermediate CA certificate for Azure Firewall"
    echo "4. Upload the certificate to Key Vault"
    echo "5. Configure TLS inspection on the Azure Firewall policy"
    echo "6. Test TLS inspection from the client VM"
    echo ""
    echo "For detailed instructions, see: docs/lab-setup-guide.md"
    echo ""
}

# Main execution
main() {
    echo ""
    echo "=================================="
    echo "Azure Firewall TLS Inspection Lab"
    echo "Infrastructure Deployment Script"
    echo "=================================="
    echo ""
    
    # Pre-flight checks
    check_azure_login
    
    # Deployment steps
    create_resource_group
    validate_template
    deploy_template
    show_outputs
    show_next_steps
    
    print_success "Lab infrastructure deployment completed!"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "validate")
        check_azure_login
        create_resource_group
        validate_template
        print_success "Template validation completed!"
        ;;
    "clean")
        print_warning "This will delete the entire resource group and all resources!"
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Deleting resource group '$RESOURCE_GROUP_NAME'..."
            az group delete --name $RESOURCE_GROUP_NAME --yes --no-wait
            print_success "Resource group deletion initiated."
        else
            print_status "Cleanup cancelled."
        fi
        ;;
    *)
        echo "Usage: $0 [deploy|validate|clean]"
        echo "  deploy   - Deploy the lab infrastructure (default)"
        echo "  validate - Validate the Bicep template only"
        echo "  clean    - Delete the resource group and all resources"
        exit 1
        ;;
esac
