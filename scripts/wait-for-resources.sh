#!/bin/bash

# Azure Firewall TLS Lab - Resource Monitoring Script
# This script monitors the provisioning status of Azure resources

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
RESOURCE_GROUP="rg-azfw-tls-lab"
SUBSCRIPTION_ID="e440a65b-7418-4865-9821-88e411ffdd5b"
WAIT_INTERVAL=30
MAX_WAIT_TIME=1800  # 30 minutes
CHECK_TYPE="all"

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
        "WAITING")
            echo -e "${YELLOW}⏳ $message${NC}"
            ;;
    esac
}

# Function to check resource status
check_resource_status() {
    local resource_type=$1
    local resource_name=$2
    local rg=$3
    
    print_status "INFO" "Checking $resource_type: $resource_name in $rg"
    
    # Get resource status and clean it up
    local status=$(az resource show \
        --resource-group "$rg" \
        --name "$resource_name" \
        --resource-type "$resource_type" \
        --query "properties.provisioningState" \
        --output tsv 2>/dev/null | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || echo "NotFound")
    
    case $status in
        "Succeeded")
            print_status "SUCCESS" "$resource_name is ready"
            return 0
            ;;
        "Failed")
            print_status "ERROR" "$resource_name deployment failed"
            return 1
            ;;
        "Creating"|"Updating"|"Running"|"Accepted")
            print_status "WAITING" "$resource_name is still provisioning (Status: $status)"
            return 2
            ;;
        "NotFound")
            print_status "ERROR" "$resource_name not found"
            return 1
            ;;
        *)
            print_status "WARNING" "$resource_name has unknown status: $status"
            return 2
            ;;
    esac
}

# Function to check VM status
check_vm_status() {
    local vm_name=$1
    local rg=$2
    
    print_status "INFO" "Checking VM: $vm_name in $rg"
    
    # Check if VM exists
    local vm_exists=$(az vm show --resource-group "$rg" --name "$vm_name" --query "name" --output tsv 2>/dev/null || echo "")
    
    if [ -z "$vm_exists" ]; then
        print_status "ERROR" "VM $vm_name not found in $rg"
        return 1
    fi
    
    # Get VM provisioning state
    local provisioning_state=$(az vm show \
        --resource-group "$rg" \
        --name "$vm_name" \
        --query "provisioningState" \
        --output tsv)
    
    # Get VM power state
    local power_state=$(az vm get-instance-view \
        --resource-group "$rg" \
        --name "$vm_name" \
        --query "instanceView.statuses[?code=='PowerState/running'].displayStatus" \
        --output tsv 2>/dev/null || echo "Unknown")
    
    print_status "INFO" "VM $vm_name - Provisioning: $provisioning_state, Power: $power_state"
    
    if [ "$provisioning_state" = "Succeeded" ] && [ "$power_state" = "VM running" ]; then
        print_status "SUCCESS" "VM $vm_name is ready and running"
        return 0
    elif [ "$provisioning_state" = "Failed" ]; then
        print_status "ERROR" "VM $vm_name provisioning failed"
        return 1
    else
        print_status "WAITING" "VM $vm_name is still provisioning or starting"
        return 2
    fi
}

# Function to check all core resources
check_core_resources() {
    local rg=$1
    local all_ready=true
    
    print_status "INFO" "Checking core infrastructure in $rg..."
    
    # Check Virtual Network
    if ! check_resource_status "Microsoft.Network/virtualNetworks" "azfw-tls-lab-vnet" "$rg"; then
        [ $? -eq 1 ] && all_ready=false
    fi
    
    # Check Public IP
    if ! check_resource_status "Microsoft.Network/publicIPAddresses" "azfw-tls-lab-fw-pip" "$rg"; then
        [ $? -eq 1 ] && all_ready=false
    fi
    
    # Check Firewall Policy
    if ! check_resource_status "Microsoft.Network/firewallPolicies" "azfw-tls-lab-policy" "$rg"; then
        [ $? -eq 1 ] && all_ready=false
    fi
    
    # Check Azure Firewall
    if ! check_resource_status "Microsoft.Network/azureFirewalls" "azfw-tls-lab-firewall" "$rg"; then
        [ $? -eq 1 ] && all_ready=false
    fi
    
    # Check Key Vault
    if ! check_resource_status "Microsoft.KeyVault/vaults" "azfw-tls-lab-kv-2025" "$rg"; then
        [ $? -eq 1 ] && all_ready=false
    fi
    
    if [ "$all_ready" = true ]; then
        print_status "SUCCESS" "All core resources are ready in $rg"
        return 0
    else
        print_status "WARNING" "Some core resources are not ready in $rg"
        return 2
    fi
}

# Function to check VMs
check_virtual_machines() {
    local rg=$1
    local all_ready=true
    
    print_status "INFO" "Checking virtual machines in $rg..."
    
    # List all VMs in the resource group
    local vms=$(az vm list --resource-group "$rg" --query "[].name" --output tsv 2>/dev/null || echo "")
    
    if [ -z "$vms" ]; then
        print_status "WARNING" "No VMs found in $rg"
        return 2
    fi
    
    while IFS= read -r vm_name; do
        if [ -n "$vm_name" ]; then
            if ! check_vm_status "$vm_name" "$rg"; then
                [ $? -eq 1 ] && all_ready=false
            fi
        fi
    done <<< "$vms"
    
    if [ "$all_ready" = true ]; then
        print_status "SUCCESS" "All VMs are ready in $rg"
        return 0
    else
        print_status "WARNING" "Some VMs are not ready in $rg"
        return 2
    fi
}

# Function to display resource overview
show_resource_overview() {
    local rg=$1
    
    print_status "INFO" "Resource overview for $rg:"
    echo ""
    
    # Show all resources in the resource group
    az resource list --resource-group "$rg" --output table 2>/dev/null || {
        print_status "ERROR" "Failed to list resources in $rg"
        return 1
    }
    
    echo ""
}

# Function to wait for resources
wait_for_resources() {
    local rg=$1
    local check_type=$2
    local start_time=$(date +%s)
    local all_ready=false
    
    print_status "INFO" "Starting resource monitoring for $rg (Type: $check_type)"
    print_status "INFO" "Check interval: ${WAIT_INTERVAL}s, Max wait time: ${MAX_WAIT_TIME}s"
    echo ""
    
    while [ "$all_ready" = false ]; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        if [ $elapsed -gt $MAX_WAIT_TIME ]; then
            print_status "ERROR" "Timeout reached (${MAX_WAIT_TIME}s). Some resources may still be provisioning."
            return 1
        fi
        
        print_status "INFO" "Check #$((elapsed / WAIT_INTERVAL + 1)) at $(date '+%Y-%m-%d %H:%M:%S')"
        
        case $check_type in
            "core")
                check_core_resources "$rg"
                local result=$?
                ;;
            "vms")
                check_virtual_machines "$rg"
                local result=$?
                ;;
            "all")
                check_core_resources "$rg"
                local core_result=$?
                check_virtual_machines "$rg"
                local vm_result=$?
                
                if [ $core_result -eq 0 ] && [ $vm_result -eq 0 ]; then
                    local result=0
                elif [ $core_result -eq 1 ] || [ $vm_result -eq 1 ]; then
                    local result=1
                else
                    local result=2
                fi
                ;;
        esac
        
        if [ $result -eq 0 ]; then
            all_ready=true
            print_status "SUCCESS" "All monitored resources are ready!"
            show_resource_overview "$rg"
            return 0
        elif [ $result -eq 1 ]; then
            print_status "ERROR" "Critical error detected. Stopping monitoring."
            return 1
        else
            print_status "WAITING" "Waiting ${WAIT_INTERVAL}s before next check..."
            sleep $WAIT_INTERVAL
        fi
        
        echo ""
    done
}

# Help function
show_help() {
    echo "Azure Firewall TLS Lab - Resource Monitoring Script"
    echo ""
    echo "Usage: $0 [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  wait            Wait for resources to be ready (default)"
    echo "  check           Check current status once"
    echo "  overview        Show resource overview"
    echo "  help            Show this help message"
    echo ""
    echo "Options:"
    echo "  -g, --resource-group NAME     Resource group name (default: $RESOURCE_GROUP)"
    echo "  -s, --subscription ID         Subscription ID (default: $SUBSCRIPTION_ID)"
    echo "  -t, --type TYPE              Check type: all, core, vms (default: $CHECK_TYPE)"
    echo "  -i, --interval SECONDS       Check interval in seconds (default: $WAIT_INTERVAL)"
    echo "  -m, --max-wait SECONDS       Maximum wait time in seconds (default: $MAX_WAIT_TIME)"
    echo ""
    echo "Examples:"
    echo "  $0 wait                                    # Wait for all resources"
    echo "  $0 check -t core                          # Check core infrastructure only"
    echo "  $0 wait -g rg-azfw-tls-lab-west -t vms   # Wait for VMs in West RG"
    echo "  $0 overview                               # Show resource overview"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -g|--resource-group)
            RESOURCE_GROUP="$2"
            shift 2
            ;;
        -s|--subscription)
            SUBSCRIPTION_ID="$2"
            shift 2
            ;;
        -t|--type)
            CHECK_TYPE="$2"
            shift 2
            ;;
        -i|--interval)
            WAIT_INTERVAL="$2"
            shift 2
            ;;
        -m|--max-wait)
            MAX_WAIT_TIME="$2"
            shift 2
            ;;
        wait|check|overview|help)
            COMMAND="$1"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Set default command if not specified
COMMAND=${COMMAND:-wait}

# Validate check type
if [[ ! "$CHECK_TYPE" =~ ^(all|core|vms)$ ]]; then
    print_status "ERROR" "Invalid check type: $CHECK_TYPE. Use: all, core, or vms"
    exit 1
fi

# Set Azure subscription
az account set --subscription "$SUBSCRIPTION_ID" || {
    print_status "ERROR" "Failed to set Azure subscription: $SUBSCRIPTION_ID"
    exit 1
}

print_status "INFO" "Using subscription: $SUBSCRIPTION_ID"
print_status "INFO" "Monitoring resource group: $RESOURCE_GROUP"

# Execute command
case $COMMAND in
    "wait")
        wait_for_resources "$RESOURCE_GROUP" "$CHECK_TYPE"
        ;;
    "check")
        case $CHECK_TYPE in
            "core")
                check_core_resources "$RESOURCE_GROUP"
                ;;
            "vms")
                check_virtual_machines "$RESOURCE_GROUP"
                ;;
            "all")
                check_core_resources "$RESOURCE_GROUP"
                echo ""
                check_virtual_machines "$RESOURCE_GROUP"
                ;;
        esac
        ;;
    "overview")
        show_resource_overview "$RESOURCE_GROUP"
        ;;
    "help")
        show_help
        ;;
    *)
        print_status "ERROR" "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
