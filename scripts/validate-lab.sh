#!/bin/bash

# Azure Firewall TLS Inspection Lab Validation Script
# This script validates that the lab environment is configured correctly

set -e

# Configuration
RESOURCE_GROUP_NAME="rg-azfw-tls-lab"
EXPECTED_RESOURCES=(
    "azfw-tls-lab-vnet:Microsoft.Network/virtualNetworks"
    "azfw-tls-lab-firewall:Microsoft.Network/azureFirewalls"
    "azfw-tls-lab-policy:Microsoft.Network/firewallPolicies"
    "azfw-tls-lab-ca-vm:Microsoft.Compute/virtualMachines"
    "azfw-tls-lab-client-vm:Microsoft.Compute/virtualMachines"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNING=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    local success_message="$3"
    local failure_message="$4"
    
    print_status "Testing: $test_name"
    
    if eval "$test_command" &> /dev/null; then
        print_success "$success_message"
        ((TESTS_PASSED++))
        return 0
    else
        print_error "$failure_message"
        ((TESTS_FAILED++))
        return 1
    fi
}

run_warning_test() {
    local test_name="$1"
    local test_command="$2"
    local success_message="$3"
    local warning_message="$4"
    
    print_status "Testing: $test_name"
    
    if eval "$test_command" &> /dev/null; then
        print_success "$success_message"
        ((TESTS_PASSED++))
        return 0
    else
        print_warning "$warning_message"
        ((TESTS_WARNING++))
        return 1
    fi
}

# Test 1: Azure Login
test_azure_login() {
    run_test \
        "Azure CLI Authentication" \
        "az account show" \
        "Azure CLI is authenticated" \
        "Azure CLI not authenticated - run 'az login'"
}

# Test 2: Resource Group Exists
test_resource_group() {
    run_test \
        "Resource Group Existence" \
        "az group show --name $RESOURCE_GROUP_NAME" \
        "Resource group '$RESOURCE_GROUP_NAME' exists" \
        "Resource group '$RESOURCE_GROUP_NAME' not found"
}

# Test 3: Required Resources
test_required_resources() {
    print_status "Checking required resources..."
    
    for resource in "${EXPECTED_RESOURCES[@]}"; do
        IFS=':' read -r name type <<< "$resource"
        
        if az resource show --resource-group $RESOURCE_GROUP_NAME --name "$name" --resource-type "$type" &> /dev/null; then
            print_success "$name ($type) exists"
            ((TESTS_PASSED++))
        else
            print_error "$name ($type) not found"
            ((TESTS_FAILED++))
        fi
    done
}

# Test 4: Network Configuration
test_network_configuration() {
    print_status "Validating network configuration..."
    
    # Check VNet subnets
    SUBNETS=$(az network vnet subnet list --resource-group $RESOURCE_GROUP_NAME --vnet-name azfw-tls-lab-vnet --query '[].name' -o tsv)
    
    for required_subnet in "AzureFirewallSubnet" "ServerSubnet"; do
        if echo "$SUBNETS" | grep -q "$required_subnet"; then
            print_success "Subnet '$required_subnet' exists"
            ((TESTS_PASSED++))
        else
            print_error "Subnet '$required_subnet' not found"
            ((TESTS_FAILED++))
        fi
    done
    
    # Check route table association
    run_test \
        "Route Table Association" \
        "az network vnet subnet show --resource-group $RESOURCE_GROUP_NAME --vnet-name azfw-tls-lab-vnet --name ServerSubnet --query 'routeTable.id'" \
        "Route table is associated with ServerSubnet" \
        "Route table not associated with ServerSubnet"
}

# Test 5: Azure Firewall Configuration
test_firewall_configuration() {
    print_status "Validating Azure Firewall configuration..."
    
    # Check firewall SKU
    FW_SKU=$(az network firewall show --resource-group $RESOURCE_GROUP_NAME --name azfw-tls-lab-firewall --query 'sku.tier' -o tsv)
    if [ "$FW_SKU" = "Premium" ]; then
        print_success "Azure Firewall is Premium tier"
        ((TESTS_PASSED++))
    else
        print_error "Azure Firewall is not Premium tier (current: $FW_SKU)"
        ((TESTS_FAILED++))
    fi
    
    # Check firewall policy
    run_test \
        "Firewall Policy Association" \
        "az network firewall show --resource-group $RESOURCE_GROUP_NAME --name azfw-tls-lab-firewall --query 'firewallPolicy.id'" \
        "Firewall policy is associated" \
        "Firewall policy is not associated"
    
    # Check managed identity
    run_test \
        "Firewall Managed Identity" \
        "az network firewall show --resource-group $RESOURCE_GROUP_NAME --name azfw-tls-lab-firewall --query 'identity.type'" \
        "Firewall has managed identity" \
        "Firewall managed identity not configured"
}

# Test 6: Key Vault Configuration
test_keyvault_configuration() {
    print_status "Validating Key Vault configuration..."
    
    # Get Key Vault name
    KV_NAME=$(az keyvault list --resource-group $RESOURCE_GROUP_NAME --query '[0].name' -o tsv)
    
    if [ -n "$KV_NAME" ]; then
        print_success "Key Vault found: $KV_NAME"
        ((TESTS_PASSED++))
        
        # Check access policies
        FW_PRINCIPAL_ID=$(az network firewall show --resource-group $RESOURCE_GROUP_NAME --name azfw-tls-lab-firewall --query 'identity.principalId' -o tsv)
        
        if [ -n "$FW_PRINCIPAL_ID" ]; then
            ACCESS_POLICY=$(az keyvault show --name "$KV_NAME" --query "properties.accessPolicies[?objectId=='$FW_PRINCIPAL_ID']" -o tsv)
            if [ -n "$ACCESS_POLICY" ]; then
                print_success "Firewall has access policy in Key Vault"
                ((TESTS_PASSED++))
            else
                print_warning "Firewall access policy not found in Key Vault"
                ((TESTS_WARNING++))
            fi
        fi
    else
        print_error "Key Vault not found"
        ((TESTS_FAILED++))
    fi
}

# Test 7: VM Status
test_vm_status() {
    print_status "Checking VM status..."
    
    for vm in "azfw-tls-lab-ca-vm" "azfw-tls-lab-client-vm"; do
        VM_STATUS=$(az vm get-instance-view --resource-group $RESOURCE_GROUP_NAME --name "$vm" --query 'instanceView.statuses[1].displayStatus' -o tsv)
        
        if [ "$VM_STATUS" = "VM running" ]; then
            print_success "$vm is running"
            ((TESTS_PASSED++))
        else
            print_warning "$vm status: $VM_STATUS"
            ((TESTS_WARNING++))
        fi
    done
}

# Test 8: Certificate Check (optional)
test_certificate() {
    print_status "Checking for TLS inspection certificate..."
    
    if [ -n "$KV_NAME" ]; then
        run_warning_test \
            "TLS Inspection Certificate" \
            "az keyvault certificate show --vault-name $KV_NAME --name azfw-tls-intermediate-ca" \
            "TLS inspection certificate found in Key Vault" \
            "TLS inspection certificate not found - upload required"
    else
        print_warning "Cannot check certificate - Key Vault not found"
        ((TESTS_WARNING++))
    fi
}

# Test 9: Firewall Rules
test_firewall_rules() {
    print_status "Checking firewall rules..."
    
    # Check application rules
    RULE_GROUPS=$(az network firewall policy rule-collection-group list --resource-group $RESOURCE_GROUP_NAME --policy-name azfw-tls-lab-policy --query '[].name' -o tsv)
    
    if echo "$RULE_GROUPS" | grep -q "DefaultApplicationRuleCollectionGroup"; then
        print_success "Application rule collection group exists"
        ((TESTS_PASSED++))
    else
        print_warning "Application rule collection group not found"
        ((TESTS_WARNING++))
    fi
    
    if echo "$RULE_GROUPS" | grep -q "DefaultNetworkRuleCollectionGroup"; then
        print_success "Network rule collection group exists"
        ((TESTS_PASSED++))
    else
        print_warning "Network rule collection group not found"
        ((TESTS_WARNING++))
    fi
}

# Test 10: Connectivity Test (if VMs are running)
test_connectivity() {
    print_status "Testing basic connectivity..."
    
    # This would require accessing the VMs, so we'll skip for now
    print_warning "Connectivity tests require VM access - run manually from client VM"
    ((TESTS_WARNING++))
}

# Show summary
show_summary() {
    echo ""
    echo "=========================="
    echo "VALIDATION SUMMARY"
    echo "=========================="
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    echo -e "Warnings: ${YELLOW}$TESTS_WARNING${NC}"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        if [ $TESTS_WARNING -eq 0 ]; then
            print_success "All tests passed! Lab environment is ready."
        else
            print_warning "Some optional components need attention, but core infrastructure is ready."
        fi
    else
        print_error "Some tests failed. Please review the issues above."
        echo ""
        echo "Common solutions:"
        echo "1. Ensure all resources are fully deployed"
        echo "2. Wait for VMs to finish provisioning"
        echo "3. Upload TLS inspection certificate to Key Vault"
        echo "4. Check Azure resource quotas and limits"
    fi
}

# Main execution
main() {
    echo ""
    echo "====================================="
    echo "Azure Firewall TLS Inspection Lab"
    echo "Environment Validation Script"
    echo "====================================="
    echo ""
    
    test_azure_login
    test_resource_group
    test_required_resources
    test_network_configuration
    test_firewall_configuration
    test_keyvault_configuration
    test_vm_status
    test_certificate
    test_firewall_rules
    test_connectivity
    
    show_summary
}

# Run validation
main
