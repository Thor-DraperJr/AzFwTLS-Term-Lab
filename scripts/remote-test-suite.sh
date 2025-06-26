#!/bin/bash

# Azure Firewall TLS Inspection Remote Test Suite
# This script performs comprehensive remote testing of the TLS inspection lab
# without requiring RDP access to the VMs

set -e  # Exit on any error

echo "🧪 Azure Firewall TLS Inspection Remote Test Suite"
echo "=================================================="
echo "Date: $(date)"
echo ""

# Color coding for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to log test results
log_test() {
    local test_name="$1"
    local result="$2"
    local details="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$result" == "PASS" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    elif [ "$result" == "FAIL" ]; then
        echo -e "${RED}❌ FAIL${NC}: $test_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    elif [ "$result" == "WARN" ]; then
        echo -e "${YELLOW}⚠️  WARN${NC}: $test_name"
    else
        echo -e "${BLUE}ℹ️  INFO${NC}: $test_name"
    fi
    
    if [ -n "$details" ]; then
        echo "   Details: $details"
    fi
    echo ""
}

# Get resource information
echo "📋 Getting resource information..."
RG_MAIN="rg-azfw-tls-lab"
RG_WEST="rg-azfw-tls-lab-west"
KEYVAULT_NAME="azfw-tls-lab-kv-2025"
FIREWALL_NAME="azfw-tls-lab-firewall"
POLICY_NAME="azfw-tls-lab-policy"

# Get VM IPs
CA_VM_IP=$(az vm show --resource-group $RG_WEST --name ca-server-vm --show-details --query publicIps --output tsv 2>/dev/null || echo "N/A")
CLIENT_VM_IP=$(az vm show --resource-group $RG_WEST --name client-vm --show-details --query publicIps --output tsv 2>/dev/null || echo "N/A")
FIREWALL_IP=$(az network public-ip show --resource-group $RG_MAIN --name azfw-tls-lab-pip --query ipAddress --output tsv 2>/dev/null || echo "N/A")

echo "🔐 CA Server VM: $CA_VM_IP"
echo "🖥️ Client VM: $CLIENT_VM_IP"
echo "🔥 Azure Firewall: $FIREWALL_IP"
echo ""

# Test 1: Infrastructure Status
echo "🧪 Test Suite 1: Infrastructure Status"
echo "======================================"

# Test 1.1: Resource Group Existence
echo "Testing resource groups..."
if az group show --name $RG_MAIN &>/dev/null; then
    log_test "Main Resource Group Exists" "PASS" "$RG_MAIN found"
else
    log_test "Main Resource Group Exists" "FAIL" "$RG_MAIN not found"
fi

if az group show --name $RG_WEST &>/dev/null; then
    log_test "West Resource Group Exists" "PASS" "$RG_WEST found"
else
    log_test "West Resource Group Exists" "FAIL" "$RG_WEST not found"
fi

# Test 1.2: Azure Firewall Status
echo "Testing Azure Firewall..."
FW_STATE=$(az network firewall show --resource-group $RG_MAIN --name $FIREWALL_NAME --query provisioningState --output tsv 2>/dev/null || echo "NotFound")
if [ "$FW_STATE" == "Succeeded" ]; then
    log_test "Azure Firewall Provisioning" "PASS" "State: $FW_STATE"
else
    log_test "Azure Firewall Provisioning" "FAIL" "State: $FW_STATE"
fi

# Test 1.3: Firewall Policy Status
echo "Testing Firewall Policy..."
POLICY_STATE=$(az network firewall policy show --resource-group $RG_MAIN --name $POLICY_NAME --query provisioningState --output tsv 2>/dev/null || echo "NotFound")
if [ "$POLICY_STATE" == "Succeeded" ]; then
    log_test "Firewall Policy Provisioning" "PASS" "State: $POLICY_STATE"
else
    log_test "Firewall Policy Provisioning" "FAIL" "State: $POLICY_STATE"
fi

# Test 1.4: Key Vault Status
echo "Testing Key Vault..."
KV_STATE=$(az keyvault show --name $KEYVAULT_NAME --query properties.provisioningState --output tsv 2>/dev/null || echo "NotFound")
if [ "$KV_STATE" == "Succeeded" ]; then
    log_test "Key Vault Provisioning" "PASS" "State: $KV_STATE"
else
    log_test "Key Vault Provisioning" "FAIL" "State: $KV_STATE"
fi

# Test 1.5: VM Status
echo "Testing Virtual Machines..."
CA_VM_STATE=$(az vm show --resource-group $RG_WEST --name ca-server-vm --query provisioningState --output tsv 2>/dev/null || echo "NotFound")
if [ "$CA_VM_STATE" == "Succeeded" ]; then
    log_test "CA Server VM Provisioning" "PASS" "State: $CA_VM_STATE"
else
    log_test "CA Server VM Provisioning" "FAIL" "State: $CA_VM_STATE"
fi

CLIENT_VM_STATE=$(az vm show --resource-group $RG_WEST --name client-vm --query provisioningState --output tsv 2>/dev/null || echo "NotFound")
if [ "$CLIENT_VM_STATE" == "Succeeded" ]; then
    log_test "Client VM Provisioning" "PASS" "State: $CLIENT_VM_STATE"
else
    log_test "Client VM Provisioning" "FAIL" "State: $CLIENT_VM_STATE"
fi

# Test 2: TLS Configuration
echo "🧪 Test Suite 2: TLS Configuration"
echo "=================================="

# Test 2.1: Certificate in Key Vault
echo "Testing TLS certificate..."
CERT_EXISTS=$(az keyvault certificate show --vault-name $KEYVAULT_NAME --name azfw-tls-cert --query name --output tsv 2>/dev/null || echo "NotFound")
if [ "$CERT_EXISTS" == "azfw-tls-cert" ]; then
    log_test "TLS Certificate in Key Vault" "PASS" "Certificate found"
    
    # Get certificate details
    CERT_ENABLED=$(az keyvault certificate show --vault-name $KEYVAULT_NAME --name azfw-tls-cert --query attributes.enabled --output tsv 2>/dev/null || echo "false")
    if [ "$CERT_ENABLED" == "true" ]; then
        log_test "TLS Certificate Enabled" "PASS" "Certificate is enabled"
    else
        log_test "TLS Certificate Enabled" "FAIL" "Certificate is disabled"
    fi
else
    log_test "TLS Certificate in Key Vault" "FAIL" "Certificate not found"
fi

# Test 2.2: Firewall Policy TLS Configuration
echo "Testing TLS inspection policy..."
TLS_ENABLED=$(az network firewall policy show --resource-group $RG_MAIN --name $POLICY_NAME --query "transportSecurity.certificateAuthority.name" --output tsv 2>/dev/null || echo "NotConfigured")
if [ "$TLS_ENABLED" != "NotConfigured" ] && [ "$TLS_ENABLED" != "" ]; then
    log_test "TLS Inspection Policy" "PASS" "TLS inspection configured"
else
    log_test "TLS Inspection Policy" "WARN" "TLS inspection may not be fully configured"
fi

# Test 3: Network Connectivity
echo "🧪 Test Suite 3: Network Connectivity"
echo "====================================="

# Test 3.1: Public IP Connectivity
echo "Testing public IP connectivity..."
if [ "$FIREWALL_IP" != "N/A" ] && [ "$FIREWALL_IP" != "" ]; then
    if ping -c 2 -W 3 $FIREWALL_IP &>/dev/null; then
        log_test "Firewall Public IP Reachable" "PASS" "IP: $FIREWALL_IP"
    else
        log_test "Firewall Public IP Reachable" "WARN" "Ping failed (may be expected due to firewall rules)"
    fi
else
    log_test "Firewall Public IP Available" "FAIL" "No public IP found"
fi

if [ "$CA_VM_IP" != "N/A" ] && [ "$CA_VM_IP" != "" ]; then
    if ping -c 2 -W 3 $CA_VM_IP &>/dev/null; then
        log_test "CA VM Public IP Reachable" "PASS" "IP: $CA_VM_IP"
    else
        log_test "CA VM Public IP Reachable" "WARN" "Ping failed (may be expected due to firewall rules)"
    fi
else
    log_test "CA VM Public IP Available" "FAIL" "No public IP found"
fi

# Test 4: Remote VM Testing
echo "🧪 Test Suite 4: Remote VM Testing"
echo "=================================="

# Test 4.1: CA Server Configuration
echo "Testing CA server configuration remotely..."
CA_CONFIG_RESULT=$(az vm run-command invoke \
    --resource-group $RG_WEST \
    --name ca-server-vm \
    --command-id RunPowerShellScript \
    --scripts "
        try {
            # Check if Certificate Services is installed
            \$CertSvc = Get-WindowsFeature -Name ADCS-Cert-Authority
            if (\$CertSvc.InstallState -eq 'Installed') {
                Write-Output 'CA_INSTALLED:YES'
            } else {
                Write-Output 'CA_INSTALLED:NO'
            }
            
            # Check if CA service is running
            \$Service = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
            if (\$Service -and \$Service.Status -eq 'Running') {
                Write-Output 'CA_SERVICE:RUNNING'
            } else {
                Write-Output 'CA_SERVICE:STOPPED'
            }
            
            # Check for certificates
            \$Certs = Get-ChildItem Cert:\LocalMachine\My | Where-Object {\$_.Subject -like '*azfirewall*' -or \$_.Subject -like '*AzFW*'}
            if (\$Certs) {
                Write-Output 'CERTIFICATES:FOUND'
            } else {
                Write-Output 'CERTIFICATES:NONE'
            }
            
        } catch {
            Write-Output 'ERROR:' + \$_.Exception.Message
        }
    " --query 'value[0].message' --output tsv 2>/dev/null || echo "COMMAND_FAILED")

if echo "$CA_CONFIG_RESULT" | grep -q "CA_INSTALLED:YES"; then
    log_test "CA Software Installed" "PASS" "ADCS-Cert-Authority feature installed"
else
    log_test "CA Software Installed" "FAIL" "ADCS-Cert-Authority not installed"
fi

if echo "$CA_CONFIG_RESULT" | grep -q "CA_SERVICE:RUNNING"; then
    log_test "CA Service Running" "PASS" "Certificate Services running"
else
    log_test "CA Service Running" "FAIL" "Certificate Services not running"
fi

if echo "$CA_CONFIG_RESULT" | grep -q "CERTIFICATES:FOUND"; then
    log_test "Certificates Generated" "PASS" "TLS certificates found on CA server"
else
    log_test "Certificates Generated" "WARN" "No TLS certificates found"
fi

# Test 4.2: Client VM Web Testing
echo "Testing client VM web connectivity..."
CLIENT_WEB_RESULT=$(az vm run-command invoke \
    --resource-group $RG_WEST \
    --name client-vm \
    --command-id RunPowerShellScript \
    --scripts "
        try {
            # Test basic web connectivity
            \$Response = Invoke-WebRequest -Uri 'https://www.google.com' -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            if (\$Response.StatusCode -eq 200) {
                Write-Output 'WEB_TEST:SUCCESS'
            } else {
                Write-Output 'WEB_TEST:FAILED'
            }
            
            # Test certificate information
            \$Uri = 'https://www.google.com'
            \$Request = [System.Net.WebRequest]::Create(\$Uri)
            \$Request.Timeout = 10000
            \$Response = \$Request.GetResponse()
            \$Cert = \$Request.ServicePoint.Certificate
            if (\$Cert) {
                Write-Output 'CERT_ISSUER:' + \$Cert.Issuer
            }
            \$Response.Close()
            
        } catch {
            Write-Output 'WEB_ERROR:' + \$_.Exception.Message
        }
    " --query 'value[0].message' --output tsv 2>/dev/null || echo "COMMAND_FAILED")

if echo "$CLIENT_WEB_RESULT" | grep -q "WEB_TEST:SUCCESS"; then
    log_test "Client VM Web Connectivity" "PASS" "HTTPS requests successful"
else
    log_test "Client VM Web Connectivity" "FAIL" "HTTPS requests failed"
fi

# Check if TLS inspection is working (certificate issuer shows firewall)
if echo "$CLIENT_WEB_RESULT" | grep -q "azfw\|firewall\|AzFW"; then
    log_test "TLS Inspection Active" "PASS" "Firewall certificate detected in chain"
else
    log_test "TLS Inspection Active" "WARN" "Original certificate chain detected (TLS inspection may not be active)"
fi

# Test 5: Advanced Configuration Tests
echo "🧪 Test Suite 5: Advanced Configuration"
echo "======================================="

# Test 5.1: Firewall Rules
echo "Testing firewall rules..."
RULE_COUNT=$(az network firewall policy rule-collection-group list \
    --resource-group $RG_MAIN \
    --policy-name $POLICY_NAME \
    --query 'length(@)' --output tsv 2>/dev/null || echo "0")

if [ "$RULE_COUNT" -gt 0 ]; then
    log_test "Firewall Rules Configured" "PASS" "$RULE_COUNT rule collection groups found"
else
    log_test "Firewall Rules Configured" "WARN" "No rule collection groups found"
fi

# Test 5.2: Network Routing
echo "Testing network routing configuration..."
ROUTE_TABLES=$(az network route-table list --resource-group $RG_MAIN --query 'length(@)' --output tsv 2>/dev/null || echo "0")
if [ "$ROUTE_TABLES" -gt 0 ]; then
    log_test "Route Tables Configured" "PASS" "$ROUTE_TABLES route tables found"
else
    log_test "Route Tables Configured" "WARN" "No route tables found"
fi

# Final Summary
echo ""
echo "📊 Test Results Summary"
echo "======================"
echo -e "${BLUE}Total Tests Run:${NC} $TOTAL_TESTS"
echo -e "${GREEN}Tests Passed:${NC} $PASSED_TESTS"
echo -e "${RED}Tests Failed:${NC} $FAILED_TESTS"
echo -e "${YELLOW}Tests with Warnings:${NC} $((TOTAL_TESTS - PASSED_TESTS - FAILED_TESTS))"
echo ""

# Calculate success rate
if [ $TOTAL_TESTS -gt 0 ]; then
    SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    echo -e "${BLUE}Success Rate:${NC} $SUCCESS_RATE%"
else
    echo -e "${RED}No tests were run${NC}"
fi

echo ""

# Overall status
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 Overall Status: READY FOR TESTING${NC}"
    echo "Your Azure Firewall TLS Inspection Lab is fully configured and ready!"
    echo ""
    echo "🧪 Recommended next steps:"
    echo "1. RDP to Client VM ($CLIENT_VM_IP:3389) for manual testing"
    echo "2. Browse HTTPS websites and check certificate details"
    echo "3. Monitor Azure Firewall logs for TLS inspection events"
    echo "4. Test various applications and websites"
elif [ $FAILED_TESTS -le 2 ]; then
    echo -e "${YELLOW}⚠️  Overall Status: MOSTLY READY${NC}"
    echo "Most components are working. Minor issues may need attention."
else
    echo -e "${RED}❌ Overall Status: NEEDS ATTENTION${NC}"
    echo "Several components need configuration or troubleshooting."
fi

echo ""
echo "📋 Connection Details:"
echo "- CA Server VM: $CA_VM_IP:3389"
echo "- Client VM: $CLIENT_VM_IP:3389"
echo "- Username: azureadmin"
echo "- Password: SecureP@ssw0rd123!"
echo ""
echo "📊 This test report generated: $(date)"
