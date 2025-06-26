# Azure Firewall Enterprise CA Certificate Automation - Complete Solution

## Overview

This document provides a comprehensive automation solution for implementing the Microsoft Azure Firewall Premium Enterprise CA certificate deployment process. The automation follows the exact steps outlined in Microsoft's official documentation: [Deploy certificates from an enterprise CA for Azure Firewall Premium](https://learn.microsoft.com/en-us/azure/firewall/premium-deploy-certificates-enterprise-ca).

## What We've Automated

### 🎯 **Core Process Automation**

Our automation scripts handle the complete enterprise CA certificate deployment process:

1. **Certificate Generation on Enterprise CA**
   - Automated PowerShell scripts on the CA VM
   - Creates subordinate/intermediate certificates for Azure Firewall
   - Exports certificates in PFX format with private keys
   - Generates base64-encoded versions for secure transfer

2. **Certificate Extraction and Transfer**
   - Automated extraction of certificates from CA VM
   - Secure base64 transfer to avoid file system dependencies
   - Support for both enterprise CA-issued and self-signed certificates for lab scenarios

3. **Azure Key Vault Upload**
   - Automated certificate import to Azure Key Vault
   - Proper permissions management for certificate access
   - Support for managed identity integration

4. **Azure Firewall TLS Inspection Configuration**
   - Automated firewall policy updates for TLS inspection
   - Managed identity creation and Key Vault access configuration
   - Transport security settings configuration

5. **Application Rules Creation**
   - Automated creation of TLS inspection rules
   - Comprehensive HTTPS traffic inspection policies
   - Support for wildcard and specific domain rules

6. **End-to-End Validation**
   - Automated testing from client VMs
   - Certificate chain validation
   - TLS inspection detection and verification

## Available Scripts

### 1. **Original Enterprise CA Automation** ✅ **WORKING**
```bash
./scripts/enterprise-ca-automation.sh
```

**Features:**
- ✅ Complete resource discovery
- ✅ Certificate generation on CA VM
- ✅ Certificate extraction and transfer
- ✅ Key Vault upload with proper permissions
- ✅ Azure Firewall TLS configuration
- ✅ Application rules creation
- ✅ Comprehensive validation testing
- ✅ Professional HTML reporting

**Usage:**
```bash
# Complete automation
./scripts/enterprise-ca-automation.sh all

# Individual steps
./scripts/enterprise-ca-automation.sh template    # Create certificate template
./scripts/enterprise-ca-automation.sh extract    # Extract certificate
./scripts/enterprise-ca-automation.sh upload     # Upload to Key Vault
./scripts/enterprise-ca-automation.sh configure  # Configure firewall
./scripts/enterprise-ca-automation.sh validate   # Test TLS inspection
```

### 2. **Microsoft Documentation Automation** ✅ **SIMPLIFIED**
```bash
./scripts/microsoft-enterprise-ca-automation.sh
```

**Features:**
- 🎯 Focused on exact Microsoft documentation steps
- 🔄 Streamlined certificate pulling from Enterprise CA
- ⚡ Fast upload to Azure Firewall via Key Vault
- 🧪 Automated validation testing
- 📋 Simplified command structure

**Usage:**
```bash
# Complete process
./scripts/microsoft-enterprise-ca-automation.sh all

# Individual steps
./scripts/microsoft-enterprise-ca-automation.sh pull       # Pull cert from CA
./scripts/microsoft-enterprise-ca-automation.sh upload     # Upload to Key Vault
./scripts/microsoft-enterprise-ca-automation.sh configure  # Configure firewall
./scripts/microsoft-enterprise-ca-automation.sh validate   # Test TLS inspection
```

### 3. **Enhanced Enterprise CA Automation** 🚀 **COMPREHENSIVE**
```bash
./scripts/enhanced-enterprise-ca-automation.sh
```

**Features:**
- 🏆 Most comprehensive automation solution
- 📊 Professional HTML reports with detailed metrics
- 🔍 Advanced certificate chain validation
- 🛡️ Enterprise-grade error handling and recovery
- 📝 Extensive logging and troubleshooting support
- 🎨 Beautiful visual reports and dashboards

## Current Lab Status

### ✅ **Infrastructure Deployed**
- **Azure Firewall Premium**: `azfw-tls-lab-firewall` (East US)
- **Firewall Policy**: `azfw-tls-lab-policy` (Premium tier)
- **Key Vault**: `azfw-tls-lab-kv-2025` (Certificate storage)
- **CA Server VM**: `ca-server-vm` (West US 2)
- **Client VM**: `client-vm` (West US 2)

### ✅ **Automation Scripts Ready**
- All three automation scripts are executable and tested
- Resource discovery working correctly
- Azure authentication validated
- Certificate generation capabilities confirmed

## Quick Start - Recommended Approach

### **Option 1: Original Enterprise CA Script** (⭐ **RECOMMENDED FOR FIRST RUN**)

```bash
# Run complete automation with professional reporting
cd /home/thor-ubuntu/AzFwTLS-Term-Lab
./scripts/enterprise-ca-automation.sh all
```

This will:
1. ✅ Discover all Azure resources automatically
2. 🏗️ Create subordinate certificate template on CA
3. 📤 Extract certificate from CA VM
4. 🔐 Upload certificate to Key Vault
5. 🔧 Configure Azure Firewall TLS inspection
6. 📋 Create application rules for HTTPS inspection
7. 🧪 Validate TLS inspection functionality
8. 📊 Generate comprehensive HTML report

### **Option 2: Simplified Microsoft Documentation Process**

```bash
# Run simplified automation focused on Microsoft docs
cd /home/thor-ubuntu/AzFwTLS-Term-Lab
./scripts/microsoft-enterprise-ca-automation.sh all
```

## Key Technical Achievements

### 🎯 **Automated Certificate Extraction**
Our PowerShell automation running on the CA VM:
- Creates enterprise-grade intermediate certificates
- Handles both enterprise CA-issued and self-signed scenarios
- Exports certificates with proper key usage extensions
- Generates base64-encoded versions for secure transfer

### 🔐 **Secure Key Vault Integration**
- Automated permissions management
- Proper certificate import with metadata
- Managed identity configuration for Azure Firewall access
- Support for certificate rotation and lifecycle management

### 🛡️ **Azure Firewall TLS Configuration**
- Transport security settings automation
- Certificate association with firewall policy
- Managed identity integration for Key Vault access
- Application rule creation for HTTPS inspection

### 🧪 **Comprehensive Validation**
- Automated testing from client VMs
- Certificate chain inspection
- TLS inspection detection
- Connection testing to multiple sites

## Environment Variables

All scripts support these environment variables for customization:

```bash
export RESOURCE_GROUP="rg-azfw-tls-lab"
export RESOURCE_GROUP_WEST="rg-azfw-tls-lab-west"
export CERTIFICATE_NAME="azure-firewall-intermediate-ca"
export CERTIFICATE_PASSWORD="<REMOVED_FROM_HISTORY>"
export MANAGED_IDENTITY_NAME="azfw-tls-managed-identity"
```

## Expected Results

### After Running Any Automation Script:

1. **Certificate Created**: Intermediate CA certificate generated on Enterprise CA
2. **Key Vault Updated**: Certificate stored securely in Azure Key Vault
3. **Firewall Configured**: Azure Firewall Premium configured for TLS inspection
4. **Rules Applied**: HTTPS traffic inspection rules active
5. **Validation Passed**: TLS inspection verified and working

### Visual Confirmation:
- **Azure Portal**: Firewall policy shows TLS inspection configuration
- **Key Vault**: Contains intermediate CA certificate
- **Client Testing**: HTTPS traffic shows replaced certificates
- **Logs**: Detailed execution logs and professional reports

## Troubleshooting

### Common Issues:
1. **Resource Not Found**: Scripts include resource discovery and validation
2. **Permission Issues**: Automated Key Vault permission management
3. **Certificate Generation**: Fallback to self-signed for lab scenarios
4. **TLS Inspection Delay**: May take a few minutes to become active

### Debug Mode:
```bash
# Enable debug logging
export DEBUG=true
./scripts/enterprise-ca-automation.sh all
```

## Integration with Existing Lab

These automation scripts work seamlessly with your existing lab infrastructure:
- ✅ Multi-region setup (East US firewall, West US VMs)
- ✅ Existing resource groups and naming conventions
- ✅ Current Azure authentication and permissions
- ✅ Integration with other lab automation scripts

## Next Steps

1. **Run Automation**: Choose one of the three scripts and execute complete automation
2. **Validate Results**: Check Azure Portal for TLS inspection configuration
3. **Test Traffic**: Use client VM to test HTTPS traffic through firewall
4. **Review Reports**: Check generated HTML reports for detailed results
5. **Production Adaptation**: Use scripts as templates for production deployments

## Documentation Reference

This automation implements the complete process from:
- [Microsoft: Deploy certificates from an enterprise CA for Azure Firewall Premium](https://learn.microsoft.com/en-us/azure/firewall/premium-deploy-certificates-enterprise-ca)
- [Azure Firewall Premium certificates](https://learn.microsoft.com/en-us/azure/firewall/premium-certificates)
- [Azure Firewall Premium features](https://learn.microsoft.com/en-us/azure/firewall/premium-features)

---

**Ready to run?** Choose your preferred automation script and execute the complete process! 🚀
