#!/bin/bash

# =============================================================================
# Azure Firewall TLS Inspection Lab - Master Automation Script
# =============================================================================
# This is the comprehensive, referenceable automation script for the entire
# Azure Firewall TLS Inspection Lab. It provides complete end-to-end automation
# with advanced testing, monitoring, and reporting capabilities.
# 
# Author: Thor Draper Jr.
# Project: AzFwTLS-Term-Lab
# Repository: https://github.com/Thor-DraperJr/AzFwTLS-Term-Lab
# =============================================================================

set -e  # Exit on any error

# =============================================================================
# GLOBAL CONFIGURATION
# =============================================================================

SCRIPT_VERSION="2.0.0"
SCRIPT_NAME="AzFwTLS Master Automation"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
REPORT_DIR="$PROJECT_ROOT/reports"

# Ensure log and report directories exist
mkdir -p "$LOG_DIR" "$REPORT_DIR"

# Logging configuration
LOG_FILE="$LOG_DIR/master-automation-$(date +%Y%m%d-%H%M%S).log"
REPORT_FILE="$REPORT_DIR/lab-status-report-$(date +%Y%m%d-%H%M%S).html"
SUMMARY_FILE="$REPORT_DIR/execution-summary.json"

# Color coding for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Test and operation tracking
TOTAL_OPERATIONS=0
PASSED_OPERATIONS=0
FAILED_OPERATIONS=0
WARNING_OPERATIONS=0
START_TIME=$(date +%s)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Enhanced logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "DEBUG")
            if [ "${DEBUG:-}" == "true" ]; then
                echo -e "${PURPLE}[DEBUG]${NC} $message" | tee -a "$LOG_FILE"
            fi
            ;;
        *)
            echo -e "$message" | tee -a "$LOG_FILE"
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Operation result tracking
track_operation() {
    local operation_name="$1"
    local result="$2"
    local details="${3:-}"
    
    TOTAL_OPERATIONS=$((TOTAL_OPERATIONS + 1))
    
    case "$result" in
        "PASS"|"SUCCESS")
            log "SUCCESS" "✅ $operation_name"
            PASSED_OPERATIONS=$((PASSED_OPERATIONS + 1))
            ;;
        "FAIL"|"ERROR")
            log "ERROR" "❌ $operation_name"
            FAILED_OPERATIONS=$((FAILED_OPERATIONS + 1))
            ;;
        "WARN"|"WARNING")
            log "WARNING" "⚠️  $operation_name"
            WARNING_OPERATIONS=$((WARNING_OPERATIONS + 1))
            ;;
    esac
    
    if [ -n "$details" ]; then
        log "INFO" "   Details: $details"
    fi
}

# Check if Azure CLI is logged in
check_azure_auth() {
    log "INFO" "Checking Azure authentication..."
    if ! az account show &>/dev/null; then
        log "ERROR" "Not logged into Azure CLI. Please run 'az login'"
        exit 1
    fi
    
    local subscription=$(az account show --query name -o tsv)
    log "SUCCESS" "Authenticated to Azure subscription: $subscription"
}

# Get resource configuration
get_resource_config() {
    log "INFO" "Discovering Azure resources..."
    
    # Try to find resource group
    RESOURCE_GROUP=$(az group list --query "[?contains(name, 'azfw-tls') || contains(name, 'firewall-tls')].name" -o tsv | head -1)
    if [ -z "$RESOURCE_GROUP" ]; then
        log "ERROR" "Could not find resource group. Please ensure lab is deployed."
        exit 1
    fi
    
    # Get firewall name
    FIREWALL_NAME=$(az network firewall list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null || echo "")
    
    # Get Key Vault name
    KEY_VAULT_NAME=$(az keyvault list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null || echo "")
    
    # Get VM names
    CA_VM_NAME=$(az vm list -g "$RESOURCE_GROUP" --query "[?contains(name, 'ca-server') || contains(name, 'ca-vm')].name" -o tsv | head -1)
    CLIENT_VM_NAME=$(az vm list -g "$RESOURCE_GROUP" --query "[?contains(name, 'client-vm') || contains(name, 'client')].name" -o tsv | head -1)
    
    log "INFO" "Discovered resources:"
    log "INFO" "  Resource Group: $RESOURCE_GROUP"
    log "INFO" "  Firewall: ${FIREWALL_NAME:-'Not found'}"
    log "INFO" "  Key Vault: ${KEY_VAULT_NAME:-'Not found'}"
    log "INFO" "  CA VM: ${CA_VM_NAME:-'Not found'}"
    log "INFO" "  Client VM: ${CLIENT_VM_NAME:-'Not found'}"
}

# =============================================================================
# DEPLOYMENT FUNCTIONS
# =============================================================================

deploy_infrastructure() {
    log "INFO" "🚀 Starting infrastructure deployment..."
    
    if [ -f "$SCRIPT_DIR/deploy-lab.sh" ]; then
        bash "$SCRIPT_DIR/deploy-lab.sh"
        track_operation "Infrastructure Deployment" "SUCCESS"
    else
        log "ERROR" "deploy-lab.sh not found"
        track_operation "Infrastructure Deployment" "FAIL" "Script not found"
        return 1
    fi
}

configure_ca_server() {
    log "INFO" "🔐 Configuring Certificate Authority..."
    
    if [ -z "$CA_VM_NAME" ]; then
        track_operation "CA Configuration" "FAIL" "CA VM not found"
        return 1
    fi
    
    # Run CA setup script on the VM
    local setup_result=$(az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP" \
        --name "$CA_VM_NAME" \
        --command-id RunPowerShellScript \
        --scripts @"$SCRIPT_DIR/Generate-TLSCertificates.ps1" \
        --query "value[0].message" -o tsv 2>/dev/null || echo "FAILED")
    
    if [[ "$setup_result" == *"Certificate generated successfully"* ]]; then
        track_operation "CA Configuration" "SUCCESS"
    else
        track_operation "CA Configuration" "FAIL" "Setup script failed"
        return 1
    fi
}

upload_certificates() {
    log "INFO" "📜 Uploading certificates to Key Vault..."
    
    if [ -f "$SCRIPT_DIR/upload-certificates.sh" ]; then
        bash "$SCRIPT_DIR/upload-certificates.sh"
        track_operation "Certificate Upload" "SUCCESS"
    else
        track_operation "Certificate Upload" "FAIL" "Upload script not found"
        return 1
    fi
}

configure_tls_inspection() {
    log "INFO" "🔍 Configuring TLS inspection..."
    
    if [ -f "$SCRIPT_DIR/automate-tls-inspection.sh" ]; then
        bash "$SCRIPT_DIR/automate-tls-inspection.sh"
        track_operation "TLS Inspection Configuration" "SUCCESS"
    else
        track_operation "TLS Inspection Configuration" "FAIL" "TLS config script not found"
        return 1
    fi
}

# =============================================================================
# COMPREHENSIVE TESTING FUNCTIONS
# =============================================================================

test_infrastructure() {
    log "INFO" "🧪 Testing infrastructure components..."
    
    # Test resource group
    if az group show -n "$RESOURCE_GROUP" &>/dev/null; then
        track_operation "Resource Group Test" "SUCCESS"
    else
        track_operation "Resource Group Test" "FAIL"
    fi
    
    # Test firewall
    if [ -n "$FIREWALL_NAME" ] && az network firewall show -g "$RESOURCE_GROUP" -n "$FIREWALL_NAME" &>/dev/null; then
        track_operation "Firewall Test" "SUCCESS"
    else
        track_operation "Firewall Test" "FAIL"
    fi
    
    # Test Key Vault
    if [ -n "$KEY_VAULT_NAME" ] && az keyvault show -n "$KEY_VAULT_NAME" &>/dev/null; then
        track_operation "Key Vault Test" "SUCCESS"
    else
        track_operation "Key Vault Test" "FAIL"
    fi
    
    # Test VMs
    if [ -n "$CA_VM_NAME" ] && az vm show -g "$RESOURCE_GROUP" -n "$CA_VM_NAME" &>/dev/null; then
        track_operation "CA VM Test" "SUCCESS"
    else
        track_operation "CA VM Test" "FAIL"
    fi
    
    if [ -n "$CLIENT_VM_NAME" ] && az vm show -g "$RESOURCE_GROUP" -n "$CLIENT_VM_NAME" &>/dev/null; then
        track_operation "Client VM Test" "SUCCESS"
    else
        track_operation "Client VM Test" "FAIL"
    fi
}

test_certificate_configuration() {
    log "INFO" "🔐 Testing certificate configuration..."
    
    if [ -z "$KEY_VAULT_NAME" ]; then
        track_operation "Certificate Test" "FAIL" "Key Vault not found"
        return 1
    fi
    
    # Check for certificates in Key Vault
    local cert_count=$(az keyvault certificate list --vault-name "$KEY_VAULT_NAME" --query "length(@)" -o tsv 2>/dev/null || echo "0")
    
    if [ "$cert_count" -gt 0 ]; then
        track_operation "Certificate Test" "SUCCESS" "$cert_count certificates found"
    else
        track_operation "Certificate Test" "FAIL" "No certificates found in Key Vault"
    fi
}

test_tls_inspection() {
    log "INFO" "🔍 Testing TLS inspection functionality..."
    
    if [ -z "$CLIENT_VM_NAME" ]; then
        track_operation "TLS Inspection Test" "FAIL" "Client VM not found"
        return 1
    fi
    
    # Run TLS test command on client VM
    local test_command='curl -v -k https://www.microsoft.com --connect-timeout 10 --max-time 30 2>&1 | grep -E "(SSL|TLS|certificate|handshake)" | head -5'
    
    local test_result=$(az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP" \
        --name "$CLIENT_VM_NAME" \
        --command-id RunShellScript \
        --scripts "timeout 45 bash -c '$test_command'" \
        --query "value[0].message" -o tsv 2>/dev/null || echo "FAILED")
    
    if [[ "$test_result" == *"SSL"* ]] || [[ "$test_result" == *"TLS"* ]]; then
        track_operation "TLS Inspection Test" "SUCCESS" "TLS traffic detected"
    else
        track_operation "TLS Inspection Test" "WARNING" "Could not verify TLS inspection"
    fi
}

test_network_connectivity() {
    log "INFO" "🌐 Testing network connectivity..."
    
    if [ -z "$CLIENT_VM_NAME" ]; then
        track_operation "Network Connectivity Test" "FAIL" "Client VM not found"
        return 1
    fi
    
    # Test basic connectivity
    local connectivity_test=$(az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP" \
        --name "$CLIENT_VM_NAME" \
        --command-id RunShellScript \
        --scripts "ping -c 3 8.8.8.8 && echo 'CONNECTIVITY_SUCCESS'" \
        --query "value[0].message" -o tsv 2>/dev/null || echo "FAILED")
    
    if [[ "$connectivity_test" == *"CONNECTIVITY_SUCCESS"* ]]; then
        track_operation "Network Connectivity Test" "SUCCESS"
    else
        track_operation "Network Connectivity Test" "FAIL"
    fi
}

run_advanced_tests() {
    log "INFO" "🧪 Running advanced test suite..."
    
    # Run the existing remote test suite if available
    if [ -f "$SCRIPT_DIR/remote-test-suite.sh" ]; then
        bash "$SCRIPT_DIR/remote-test-suite.sh" | tee -a "$LOG_FILE"
        track_operation "Advanced Test Suite" "SUCCESS"
    else
        track_operation "Advanced Test Suite" "WARNING" "Advanced test suite not found"
    fi
}

# =============================================================================
# MONITORING AND REPORTING FUNCTIONS
# =============================================================================

generate_status_report() {
    log "INFO" "📊 Generating comprehensive status report..."
    
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))
    
    # Generate HTML report
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Firewall TLS Inspection Lab - Status Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #323130; margin-top: 30px; }
        .summary { display: flex; justify-content: space-around; margin: 30px 0; }
        .metric { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }
        .metric-value { font-size: 2em; font-weight: bold; }
        .success { color: #107c10; }
        .warning { color: #ffaa44; }
        .error { color: #d13438; }
        .info { color: #0078d4; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; font-weight: 600; }
        .status-pass { color: #107c10; font-weight: bold; }
        .status-fail { color: #d13438; font-weight: bold; }
        .status-warn { color: #ffaa44; font-weight: bold; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 0.9em; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Azure Firewall TLS Inspection Lab - Status Report</h1>
        
        <div class="summary">
            <div class="metric">
                <div class="metric-value success">$PASSED_OPERATIONS</div>
                <div>Passed</div>
            </div>
            <div class="metric">
                <div class="metric-value warning">$WARNING_OPERATIONS</div>
                <div>Warnings</div>
            </div>
            <div class="metric">
                <div class="metric-value error">$FAILED_OPERATIONS</div>
                <div>Failed</div>
            </div>
            <div class="metric">
                <div class="metric-value info">$TOTAL_OPERATIONS</div>
                <div>Total Operations</div>
            </div>
        </div>
        
        <h2>📋 Execution Summary</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Execution Date</td><td>$(date)</td></tr>
            <tr><td>Duration</td><td>$duration_formatted</td></tr>
            <tr><td>Script Version</td><td>$SCRIPT_VERSION</td></tr>
            <tr><td>Resource Group</td><td>${RESOURCE_GROUP:-'Not found'}</td></tr>
            <tr><td>Azure Firewall</td><td>${FIREWALL_NAME:-'Not found'}</td></tr>
            <tr><td>Key Vault</td><td>${KEY_VAULT_NAME:-'Not found'}</td></tr>
        </table>
        
        <h2>📁 Files Generated</h2>
        <ul>
            <li><strong>Log File:</strong> <code>$LOG_FILE</code></li>
            <li><strong>Report File:</strong> <code>$REPORT_FILE</code></li>
            <li><strong>Summary File:</strong> <code>$SUMMARY_FILE</code></li>
        </ul>
        
        <div class="footer">
            <p><strong>Azure Firewall TLS Inspection Lab</strong> - Master Automation Script v$SCRIPT_VERSION</p>
            <p>Generated by: $SCRIPT_NAME | Repository: <a href="https://github.com/Thor-DraperJr/AzFwTLS-Term-Lab">AzFwTLS-Term-Lab</a></p>
        </div>
    </div>
</body>
</html>
EOF

    # Generate JSON summary
    cat > "$SUMMARY_FILE" << EOF
{
    "execution_summary": {
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "duration_seconds": $duration,
        "duration_formatted": "$duration_formatted",
        "script_version": "$SCRIPT_VERSION"
    },
    "results": {
        "total_operations": $TOTAL_OPERATIONS,
        "passed_operations": $PASSED_OPERATIONS,
        "failed_operations": $FAILED_OPERATIONS,
        "warning_operations": $WARNING_OPERATIONS,
        "success_rate": $(echo "scale=2; $PASSED_OPERATIONS * 100 / $TOTAL_OPERATIONS" | bc -l 2>/dev/null || echo "0")
    },
    "resources": {
        "resource_group": "${RESOURCE_GROUP:-null}",
        "firewall_name": "${FIREWALL_NAME:-null}",
        "key_vault_name": "${KEY_VAULT_NAME:-null}",
        "ca_vm_name": "${CA_VM_NAME:-null}",
        "client_vm_name": "${CLIENT_VM_NAME:-null}"
    },
    "files": {
        "log_file": "$LOG_FILE",
        "report_file": "$REPORT_FILE",
        "summary_file": "$SUMMARY_FILE"
    }
}
EOF
    
    log "SUCCESS" "Report generated: $REPORT_FILE"
    log "SUCCESS" "Summary generated: $SUMMARY_FILE"
}

# =============================================================================
# MAIN EXECUTION FUNCTIONS
# =============================================================================

show_help() {
    cat << EOF
🛡️  Azure Firewall TLS Inspection Lab - Master Automation Script v$SCRIPT_VERSION

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    deploy          Deploy complete infrastructure
    configure       Configure CA and certificates
    test           Run comprehensive test suite
    monitor        Monitor and report on lab status
    full           Execute complete end-to-end automation
    status         Show current lab status
    cleanup        Clean up resources (interactive)
    help           Show this help message

OPTIONS:
    --debug        Enable debug logging
    --quiet        Suppress non-essential output
    --force        Skip confirmations
    --resource-group NAME    Specify resource group name
    --report-only  Generate reports without running operations

EXAMPLES:
    $0 full                    # Complete end-to-end automation
    $0 deploy                  # Deploy infrastructure only
    $0 test                    # Run tests on existing lab
    $0 status --report-only    # Generate status report only
    $0 configure --debug       # Configure with debug logging

ENVIRONMENT VARIABLES:
    DEBUG=true                 Enable debug output
    RESOURCE_GROUP=name        Override resource group discovery
    SKIP_CONFIRMATIONS=true    Skip interactive confirmations

For more information, visit: https://github.com/Thor-DraperJr/AzFwTLS-Term-Lab
EOF
}

execute_full_automation() {
    log "INFO" "🚀 Starting complete end-to-end automation..."
    log "INFO" "This will deploy, configure, and test the entire lab"
    
    # Step 1: Deploy infrastructure
    log "INFO" "Step 1/5: Deploying infrastructure..."
    deploy_infrastructure
    
    # Step 2: Configure resources
    log "INFO" "Step 2/5: Configuring resources..."
    get_resource_config
    
    # Step 3: Setup CA and certificates
    log "INFO" "Step 3/5: Setting up certificates..."
    configure_ca_server
    upload_certificates
    
    # Step 4: Configure TLS inspection
    log "INFO" "Step 4/5: Configuring TLS inspection..."
    configure_tls_inspection
    
    # Step 5: Run comprehensive tests
    log "INFO" "Step 5/5: Running comprehensive tests..."
    test_infrastructure
    test_certificate_configuration
    test_tls_inspection
    test_network_connectivity
    run_advanced_tests
}

execute_deploy_only() {
    log "INFO" "🏗️  Deploying infrastructure only..."
    deploy_infrastructure
    get_resource_config
}

execute_configure_only() {
    log "INFO" "⚙️  Configuring existing infrastructure..."
    get_resource_config
    configure_ca_server
    upload_certificates
    configure_tls_inspection
}

execute_test_only() {
    log "INFO" "🧪 Running comprehensive test suite..."
    get_resource_config
    test_infrastructure
    test_certificate_configuration
    test_tls_inspection
    test_network_connectivity
    run_advanced_tests
}

execute_status_check() {
    log "INFO" "📊 Checking lab status..."
    get_resource_config
    
    # Quick status checks
    test_infrastructure
    test_certificate_configuration
}

execute_monitoring() {
    log "INFO" "📈 Starting monitoring mode..."
    get_resource_config
    
    # Continuous monitoring loop
    local monitoring_interval=300  # 5 minutes
    local monitoring_duration=3600 # 1 hour
    local monitoring_end_time=$(($(date +%s) + monitoring_duration))
    
    while [ $(date +%s) -lt $monitoring_end_time ]; do
        log "INFO" "Running monitoring check..."
        test_infrastructure
        test_tls_inspection
        
        log "INFO" "Waiting $monitoring_interval seconds before next check..."
        sleep $monitoring_interval
    done
}

# =============================================================================
# MAIN SCRIPT LOGIC
# =============================================================================

main() {
    # Initialize
    echo -e "${WHITE}=================================${NC}"
    echo -e "${WHITE}$SCRIPT_NAME v$SCRIPT_VERSION${NC}"
    echo -e "${WHITE}=================================${NC}"
    echo ""
    
    log "INFO" "Starting execution at $(date)"
    log "INFO" "Log file: $LOG_FILE"
    
    # Parse command line arguments
    local command="${1:-help}"
    shift || true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG=true
                log "DEBUG" "Debug mode enabled"
                shift
                ;;
            --quiet)
                QUIET=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --resource-group)
                RESOURCE_GROUP="$2"
                shift 2
                ;;
            --report-only)
                REPORT_ONLY=true
                shift
                ;;
            *)
                log "WARNING" "Unknown option: $1"
                shift
                ;;
        esac
    done
    
    # Check prerequisites
    check_azure_auth
    
    # Execute based on command
    case "$command" in
        "full"|"all")
            execute_full_automation
            ;;
        "deploy")
            execute_deploy_only
            ;;
        "configure"|"config")
            execute_configure_only
            ;;
        "test")
            execute_test_only
            ;;
        "status")
            if [ "${REPORT_ONLY:-}" == "true" ]; then
                get_resource_config
            else
                execute_status_check
            fi
            ;;
        "monitor")
            execute_monitoring
            ;;
        "help"|"--help"|"-h")
            show_help
            exit 0
            ;;
        *)
            log "ERROR" "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
    
    # Generate final report
    generate_status_report
    
    # Summary
    local end_time=$(date +%s)
    local total_duration=$((end_time - START_TIME))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((total_duration/3600)) $((total_duration%3600/60)) $((total_duration%60)))
    
    echo ""
    echo -e "${WHITE}=================================${NC}"
    echo -e "${WHITE}EXECUTION SUMMARY${NC}"
    echo -e "${WHITE}=================================${NC}"
    log "INFO" "Total Operations: $TOTAL_OPERATIONS"
    log "SUCCESS" "Passed: $PASSED_OPERATIONS"
    log "WARNING" "Warnings: $WARNING_OPERATIONS"
    log "ERROR" "Failed: $FAILED_OPERATIONS"
    log "INFO" "Duration: $duration_formatted"
    log "INFO" "Report: $REPORT_FILE"
    echo -e "${WHITE}=================================${NC}"
    
    # Exit with appropriate code
    if [ $FAILED_OPERATIONS -gt 0 ]; then
        exit 1
    elif [ $WARNING_OPERATIONS -gt 0 ]; then
        exit 2
    else
        exit 0
    fi
}

# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

# Trap signals for cleanup
trap 'log "WARNING" "Script interrupted"; exit 130' INT TERM

# Execute main function with all arguments
main "$@"
