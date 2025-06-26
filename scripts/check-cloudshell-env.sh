#!/bin/bash

# Azure Firewall TLS Inspection Lab - Cloud Shell Environment Checker
# Validates Cloud Shell environment and provides optimization tips

echo "☁️ Azure Cloud Shell Environment Check"
echo "======================================"
echo ""

# Colors for Cloud Shell
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✅${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ️${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠️${NC} $1"; }
print_error() { echo -e "${RED}❌${NC} $1"; }

# Detect Cloud Shell environment
check_cloudshell() {
    echo "🔍 Environment Detection:"
    echo "========================"
    
    if [[ -n "$AZURE_HTTP_USER_AGENT" ]] || [[ -n "$CLOUDSHELL" ]]; then
        print_success "Running in Azure Cloud Shell"
        echo "   🌐 User Agent: ${AZURE_HTTP_USER_AGENT:-'Cloud Shell'}"
        echo "   🖥️  Shell Type: $0"
        echo "   📁 Home Directory: $HOME"
        return 0
    else
        print_warning "Not running in Azure Cloud Shell"
        echo "   💻 Local environment detected"
        echo "   💡 For best experience, use Azure Cloud Shell"
        return 1
    fi
}

# Check Azure authentication
check_azure_auth() {
    echo ""
    echo "🔐 Azure Authentication:"
    echo "======================="
    
    if az account show >/dev/null 2>&1; then
        local sub_name=$(az account show --query "name" -o tsv)
        local sub_id=$(az account show --query "id" -o tsv)
        local tenant=$(az account show --query "tenantId" -o tsv)
        local user=$(az account show --query "user.name" -o tsv)
        
        print_success "Authenticated to Azure"
        echo "   👤 User: $user"
        echo "   📋 Subscription: $sub_name"
        echo "   🆔 Subscription ID: $sub_id"
        echo "   🏢 Tenant: $tenant"
    else
        print_error "Not authenticated to Azure"
        echo "   💡 In Cloud Shell, authentication should be automatic"
    fi
}

# Check available tools
check_tools() {
    echo ""
    echo "🛠️ Available Tools:"
    echo "=================="
    
    local tools=("az:Azure CLI" "git:Git" "curl:cURL" "jq:JSON processor" "base64:Base64 encoder")
    
    for tool_info in "${tools[@]}"; do
        local tool="${tool_info%%:*}"
        local desc="${tool_info##*:}"
        
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$(command -v "$tool" >/dev/null && eval "$tool --version 2>/dev/null | head -1" 2>/dev/null || echo "available")
            print_success "$desc: $version"
        else
            print_error "$desc: Not available"
        fi
    done
}

# Check Azure CLI configuration
check_azure_cli_config() {
    echo ""
    echo "⚙️ Azure CLI Configuration:"
    echo "=========================="
    
    local output_format=$(az config get core.output --only-show-errors 2>/dev/null | jq -r '.value // "json"')
    local error_mode=$(az config get core.only_show_errors --only-show-errors 2>/dev/null | jq -r '.value // "false"')
    
    echo "   📤 Output format: $output_format"
    echo "   🔇 Errors only: $error_mode"
    
    # Check for optimal settings
    if [[ "$output_format" == "json" ]]; then
        print_info "Output format is optimized for scripting"
    fi
    
    if [[ "$error_mode" == "true" ]]; then
        print_info "Error-only mode enabled for cleaner output"
    fi
}

# Check storage and persistence
check_storage() {
    echo ""
    echo "💾 Storage and Persistence:"
    echo "=========================="
    
    if [[ -d "$HOME/clouddrive" ]]; then
        print_success "Cloud Shell persistent storage mounted"
        echo "   📁 Mount point: $HOME/clouddrive"
        
        # Check available space
        local available=$(df -h "$HOME/clouddrive" 2>/dev/null | awk 'NR==2 {print $4}' || echo "Unknown")
        echo "   💿 Available space: $available"
        
        # Check lab directories
        if [[ -d "$HOME/clouddrive/azfw-tls-lab" ]]; then
            print_success "Lab persistent directory exists"
            echo "   📂 Lab storage: $HOME/clouddrive/azfw-tls-lab"
            
            # List contents
            if [[ -d "$HOME/clouddrive/azfw-tls-lab/certificates" ]]; then
                local cert_count=$(ls -1 "$HOME/clouddrive/azfw-tls-lab/certificates" 2>/dev/null | wc -l)
                echo "   📜 Certificates stored: $cert_count"
            fi
            
            if [[ -d "$HOME/clouddrive/azfw-tls-lab/logs" ]]; then
                local log_count=$(ls -1 "$HOME/clouddrive/azfw-tls-lab/logs" 2>/dev/null | wc -l)
                echo "   📝 Log files: $log_count"
            fi
        else
            print_info "Lab directories will be created on first run"
        fi
    else
        print_warning "Cloud Shell persistent storage not detected"
        echo "   💡 Storage may not persist between sessions"
    fi
    
    # Check current session storage
    echo "   🗂️ Current session temp: $HOME ($(df -h "$HOME" 2>/dev/null | awk 'NR==2 {print $4}' || echo "Unknown") available)"
}

# Check network connectivity
check_connectivity() {
    echo ""
    echo "🌐 Network Connectivity:"
    echo "======================="
    
    # Test Azure connectivity
    if curl -s --max-time 5 https://management.azure.com >/dev/null; then
        print_success "Azure Management API reachable"
    else
        print_warning "Azure Management API connection issues"
    fi
    
    # Test general internet
    if curl -s --max-time 5 https://www.microsoft.com >/dev/null; then
        print_success "Internet connectivity working"
    else
        print_warning "Internet connectivity issues"
    fi
}

# Check lab infrastructure
check_lab_infrastructure() {
    echo ""
    echo "🏗️ Lab Infrastructure Status:"
    echo "============================="
    
    # Check resource groups
    local rg_primary=$(az group show --name "rg-azfw-tls-lab" --query "properties.provisioningState" -o tsv 2>/dev/null || echo "NotFound")
    local rg_west=$(az group show --name "rg-azfw-tls-lab-west" --query "properties.provisioningState" -o tsv 2>/dev/null || echo "NotFound")
    
    echo "📊 Resource Groups:"
    if [[ "$rg_primary" == "Succeeded" ]]; then
        print_success "Primary RG (East US): $rg_primary"
    else
        print_error "Primary RG (East US): $rg_primary"
    fi
    
    if [[ "$rg_west" == "Succeeded" ]]; then
        print_success "Backup RG (West US 2): $rg_west"
    else
        print_error "Backup RG (West US 2): $rg_west"
    fi
    
    # Check key resources if RGs exist
    if [[ "$rg_primary" == "Succeeded" ]]; then
        local fw_status=$(az network firewall show --resource-group "rg-azfw-tls-lab" --name "azfw-tls-lab-firewall" --query "provisioningState" -o tsv 2>/dev/null || echo "NotFound")
        local kv_status=$(az keyvault show --name "azfw-tls-lab-kv-2025" --query "properties.provisioningState" -o tsv 2>/dev/null || echo "NotFound")
        
        echo "🔥 Azure Firewall: $fw_status"
        echo "🔐 Key Vault: $kv_status"
    fi
    
    if [[ "$rg_west" == "Succeeded" ]]; then
        local ca_vm=$(az vm show --resource-group "rg-azfw-tls-lab-west" --name "ca-server-vm" --query "provisioningState" -o tsv 2>/dev/null || echo "NotFound")
        local client_vm=$(az vm show --resource-group "rg-azfw-tls-lab-west" --name "client-vm" --query "provisioningState" -o tsv 2>/dev/null || echo "NotFound")
        
        echo "🖥️ CA Server VM: $ca_vm"
        echo "💻 Client VM: $client_vm"
    fi
}

# Show optimization recommendations
show_recommendations() {
    echo ""
    echo "🚀 Cloud Shell Optimization Tips:"
    echo "================================="
    
    echo "📈 Performance:"
    echo "   • Use 'az config set core.only_show_errors=true' for cleaner output"
    echo "   • Set 'az config set core.output=table' for readable results"
    echo "   • Use --no-wait flag for long-running operations"
    
    echo ""
    echo "💾 Storage:"
    echo "   • Store important files in ~/clouddrive/ for persistence"
    echo "   • Use symbolic links to access persistent storage easily"
    echo "   • Clean up temp files regularly"
    
    echo ""
    echo "⚡ Lab Specific:"
    echo "   • Use ./scripts/cloudshell-quick-setup.sh for fastest setup"
    echo "   • Monitor progress with ./scripts/monitor-deployment.sh"
    echo "   • Keep certificates in ~/clouddrive/azfw-tls-lab/certificates"
    
    echo ""
    echo "🔧 Troubleshooting:"
    echo "   • Refresh browser if session becomes unresponsive"
    echo "   • Use 'az account show' to verify authentication"
    echo "   • Check ~/clouddrive mount if files are missing"
}

# Main function
main() {
    check_cloudshell
    check_azure_auth
    check_tools
    check_azure_cli_config
    check_storage
    check_connectivity
    check_lab_infrastructure
    show_recommendations
    
    echo ""
    echo "✨ Cloud Shell environment check completed!"
    echo ""
    echo "🚀 Ready to run Azure Firewall TLS Inspection Lab:"
    echo "   ./scripts/cloudshell-quick-setup.sh"
}

# Run the checks
main
