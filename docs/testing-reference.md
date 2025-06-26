# Azure Firewall TLS Inspection Testing Reference

This document provides a comprehensive reference for testing the Azure Firewall TLS Inspection Lab.

## 📋 Available Test Scripts

### 1. `remote-test-suite.sh` - Comprehensive Remote Testing
**Purpose**: Complete automated testing of all lab components
**Duration**: 2-3 minutes
**Tests Performed**:
- Infrastructure status (resource groups, firewall, VMs, Key Vault)
- TLS configuration (certificates, policies)
- Network connectivity
- Remote VM functionality
- Advanced configuration

**Usage**:
```bash
./scripts/remote-test-suite.sh
```

**Output**: Detailed test report with pass/fail status and recommendations

### 2. `quick-tls-test.sh` - Focused TLS Inspection Test
**Purpose**: Quick verification of TLS inspection functionality
**Duration**: 30-60 seconds
**Tests Performed**:
- Key Vault certificate status
- Azure Firewall Premium status
- VM connectivity and web access
- TLS inspection active/passive detection

**Usage**:
```bash
./scripts/quick-tls-test.sh
```

**Output**: Focused summary of TLS inspection status

### 3. `test-tls-inspection.sh` - Full Testing Guide
**Purpose**: Complete testing instructions and connectivity details
**Duration**: Manual execution
**Includes**:
- Connection details for all VMs
- Manual testing procedures
- Advanced testing scenarios

**Usage**:
```bash
./scripts/test-tls-inspection.sh
```

## 🧪 Testing Scenarios

### Scenario 1: Basic TLS Inspection Verification
**Objective**: Verify that HTTPS traffic is being inspected

**Remote Test**:
```bash
./scripts/quick-tls-test.sh
```

**Manual Test**:
1. RDP to Client VM (20.125.51.10:3389)
2. Open web browser
3. Navigate to https://www.google.com
4. Check certificate details (should show Azure Firewall in chain)

### Scenario 2: Certificate Chain Analysis
**Objective**: Analyze the complete certificate chain

**PowerShell on Client VM**:
```powershell
# Detailed certificate inspection
$Uri = "https://www.microsoft.com"
$Request = [System.Net.WebRequest]::Create($Uri)
$Response = $Request.GetResponse()
$Cert = $Request.ServicePoint.Certificate
Write-Host "Issuer: $($Cert.Issuer)"
Write-Host "Subject: $($Cert.Subject)"
$Response.Close()
```

### Scenario 3: Multiple Website Testing
**Objective**: Test TLS inspection across different websites

**Test Sites**:
- https://www.google.com
- https://www.microsoft.com
- https://httpbin.org/get
- https://www.github.com

### Scenario 4: Application Testing
**Objective**: Test TLS inspection with different applications

**Applications to Test**:
- Web browsers (Edge, Chrome if installed)
- PowerShell web requests
- Windows Update (background HTTPS traffic)
- Any custom applications

## 🔍 Troubleshooting Guide

### Common Issues and Solutions

#### Issue 1: TLS Inspection Not Active
**Symptoms**: Original website certificates shown instead of firewall certificates
**Possible Causes**:
- Certificate not properly uploaded to Key Vault
- Firewall policy not configured for TLS inspection
- Network routing not directing traffic through firewall

**Diagnostic Commands**:
```bash
# Check certificate in Key Vault
az keyvault certificate show --vault-name azfw-tls-lab-kv-2025 --name azfw-tls-cert

# Check firewall policy
az network firewall policy show --resource-group rg-azfw-tls-lab --name azfw-tls-lab-policy --query transportSecurity
```

#### Issue 2: VMs Not Accessible
**Symptoms**: Cannot RDP to VMs or run remote commands
**Possible Causes**:
- VMs are stopped/deallocated
- Network security group blocking access
- Public IP not assigned

**Diagnostic Commands**:
```bash
# Check VM status
az vm list --resource-group rg-azfw-tls-lab-west --query '[].{Name:name,PowerState:powerState}' --output table

# Start VMs if needed
az vm start --resource-group rg-azfw-tls-lab-west --name ca-server-vm
az vm start --resource-group rg-azfw-tls-lab-west --name client-vm
```

#### Issue 3: Certificate Issues
**Symptoms**: Certificate errors or TLS handshake failures
**Possible Causes**:
- Invalid certificate format
- Certificate expired
- Certificate not trusted

**Solutions**:
```bash
# Re-generate and upload certificate
./scripts/complete-tls-setup.sh
```

## 📊 Expected Test Results

### Successful TLS Inspection Setup
```
✅ Certificate is available and enabled in Key Vault
✅ Azure Firewall Premium is ready
✅ CA Server VM is responsive
✅ Client VM can access HTTPS websites
🎉 TLS Inspection is ACTIVE - Firewall is intercepting HTTPS traffic!
```

### Partial Setup (Needs Attention)
```
✅ Certificate is available and enabled in Key Vault
✅ Azure Firewall Premium is ready
✅ CA Server VM is responsive
✅ Client VM can access HTTPS websites
⚠️  TLS Inspection is in PASSTHROUGH mode - Traffic is not being intercepted
```

## 🔗 Connection Information

### VM Access Details
- **CA Server VM**: 172.171.124.184:3389
- **Client VM**: 20.125.51.10:3389
- **Username**: azureadmin
- **Password**: SecureP@ssw0rd123!

### Azure Resources
- **Resource Group (Main)**: rg-azfw-tls-lab
- **Resource Group (VMs)**: rg-azfw-tls-lab-west
- **Azure Firewall**: azfw-tls-lab-firewall
- **Key Vault**: azfw-tls-lab-kv-2025
- **Firewall Policy**: azfw-tls-lab-policy

## 🚀 Quick Start Testing

For immediate testing after setup:

```bash
# 1. Run comprehensive test
./scripts/remote-test-suite.sh

# 2. If issues found, run focused test
./scripts/quick-tls-test.sh

# 3. For manual testing, get connection details
./scripts/test-tls-inspection.sh
```

## 📝 Test Result Interpretation

### Test Status Indicators
- **✅ PASS**: Component working correctly
- **⚠️ WARN**: Component working but may need attention
- **❌ FAIL**: Component needs configuration or troubleshooting
- **ℹ️ INFO**: Informational message

### Success Criteria
- **Infrastructure**: All Azure resources provisioned successfully
- **TLS Configuration**: Certificate in Key Vault, firewall policy configured
- **Connectivity**: VMs accessible, web requests successful
- **TLS Inspection**: Firewall certificates visible in certificate chain

This reference document provides all the tools and knowledge needed to thoroughly test your Azure Firewall TLS Inspection Lab!
