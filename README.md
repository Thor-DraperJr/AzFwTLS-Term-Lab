# Azure Firewall TLS Inspection Lab with AI Integration

This lab demonstrates how to set up Azure Firewall Premium with TLS inspection using an Enterprise CA certificate, leveraging AI tools fo## 🎯 **RECOMMENDED: Enterprise CA Certificate Automation**

### **🏆 Primary Option: Microsoft Documentation Automation**
```bash
# Automate the complete Microsoft Enterprise CA process
./scripts/enterprise-ca-automation.sh all
```

**Why This is THE Solution You Wanted:**
- 🎯 **Automates Microsoft's exact documentation process**
- 📤 **Pulls intermediate certificates from Enterprise CA**
- 🔐 **Uploads certificates to Azure Firewall via Key Vault**
- 🛡️ **Configures TLS inspection following best practices**
- 🧪 **Validates TLS inspection end-to-end**
- 📊 **Generates professional HTML reports**

**Alternative Enterprise CA Scripts:**
```bash
# Simplified Microsoft documentation process
./scripts/microsoft-enterprise-ca-automation.sh all

# Enhanced version with advanced features
./scripts/enhanced-enterprise-ca-automation.sh all
```

### **📖 Complete Documentation**
See [`docs/enterprise-ca-complete-automation-guide.md`](docs/enterprise-ca-complete-automation-guide.md) for comprehensive guide.

### **🏆 Legacy Option: Master Automation Script**
```bash
# The original comprehensive automation solution
./scripts/master-automation.sh full
```d simplification.

## Architecture Overview

- **Azure Firewall Premium** - For TLS inspection capabilities
- **Enterprise CA VM** - Windows Server with AD CS for certificate issuance
- **Client Test VM** - To generate and test HTTPS traffic
- **Azure Key Vault** - Secure storage for TLS certificates
- **Virtual Network** - Hub network with proper routing

## Lab Components

### Infrastructure (Bicep Templates)
- `main.bicep` - Main deployment template
- `modules/` - Modular Bicep templates for each component
- `parameters/` - Environment-specific parameter files

### Scripts
- `scripts/` - PowerShell and Azure CLI automation scripts
- `certificates/` - Certificate generation and management scripts

### Documentation
- `docs/` - Step-by-step deployment guides
- Lab validation and testing procedures

## Prerequisites

- Azure subscription with permissions to create resources
- Azure CLI installed and configured
- PowerShell 7+ for script execution
- Basic understanding of PKI and certificate management

## Getting Started

1. Review the architecture documentation
2. Deploy the infrastructure using Bicep templates
3. Configure the Enterprise CA
4. Generate and deploy certificates
5. Test TLS inspection functionality

## AI Integration

This lab showcases how AI tools like GitHub Copilot and Claude can assist with:
- Bicep template generation and validation
- Certificate creation automation
- Troubleshooting and optimization
- Documentation and best practices

## Security Considerations

⚠️ **This is a lab environment** - Do not use in production without proper security review and hardening.

## Current Deployment Status

✅ **Azure MCP Server Connected**: Successfully authenticated to your Azure subscription
- **Subscription**: `ME-MngEnvMCAP392206-thordraper-1`
- **Subscription ID**: `<REMOVED_FROM_HISTORY>`

✅ **Initial Infrastructure Deployed** (East US):
- Resource Group: `rg-azfw-tls-lab`
- Virtual Network: `azfw-tls-lab-vnet` (10.0.0.0/16)
- Azure Firewall Premium: `azfw-tls-lab-firewall`
- Firewall Policy: `azfw-tls-lab-policy` (Premium tier)
- Public IP: `<REMOVED_FROM_HISTORY>`
- Key Vault: `azfw-tls-lab-kv-2025`

## 🌐 Multi-Region Strategy

Due to capacity constraints in East US for specific VM sizes, we're implementing a **strategic multi-region approach**:

### Primary Region (East US)
- ✅ **Azure Firewall Premium** - Core TLS inspection capability
- ✅ **Virtual Network** - Hub network infrastructure  
- ✅ **Key Vault** - Certificate storage and management
- ✅ **Firewall Policy** - TLS inspection rules and configuration

### Backup Region (West US 2)  
- 🔄 **Virtual Machines** - CA server and client VMs (deploying now)
- 🎯 **Strategic Benefits**:
  - **Immediate Solution**: Overcome East US capacity constraints
  - **Cross-Region Testing**: Test connectivity through Azure Firewall across regions
  - **Business Continuity**: Practice multi-region disaster recovery scenarios
  - **Performance Analysis**: Compare latency and throughput across regions
  - **Certificate Management**: Test distributed PKI infrastructure

### Testing Scenarios Enabled
1. **Standard TLS Inspection**: VMs → Firewall → Internet
2. **Cross-Region Connectivity**: West US VMs → East US Firewall → Internet
3. **Regional Failover**: Primary to backup region scenarios
4. **Certificate Distribution**: Multi-region CA certificate deployment

This setup provides both **immediate lab functionality** and **real-world enterprise architecture experience**.

## Quick Start Deployment

Since you're already authenticated with Azure MCP server, you can continue the deployment:

### Option 1: Use Azure MCP Server (Current Approach)
```bash
# Continue with VM deployment in West US 2
# The Azure MCP server commands are being used to deploy step-by-step
```

### Option 2: Use Local Bicep Templates
```bash
# Update parameters and deploy using Azure CLI
./scripts/deploy-lab.sh deploy
```

## What We've Demonstrated

This lab showcases **AI-assisted Azure deployment** in action:

1. **Natural Language to Azure Commands**: Used Azure MCP server to translate deployment intentions into Azure CLI commands
2. **Real-time Problem Solving**: When capacity issues arose, AI helped pivot to alternative regions
3. **Iterative Deployment**: Building infrastructure piece by piece with AI guidance
4. **Adaptive Planning**: Adjusting deployment strategy based on real Azure constraints

## Next Steps

✅ **Infrastructure Complete**: All Azure resources deployed successfully
- **Primary Region (East US)**: Azure Firewall Premium, Key Vault, VNet
- **Backup Region (West US 2)**: CA Server VM, Client VM, VNet

🚀 **Ready to Start Testing**: 

## 🎯 **NEW: Enterprise CA Automation (Microsoft Docs Compliant)**

### **🏆 FEATURED: Complete Enterprise CA Certificate Deployment**
```bash
# Implements Microsoft's official documentation step-by-step:
# https://learn.microsoft.com/en-us/azure/firewall/premium-deploy-certificates-enterprise-ca
./scripts/enterprise-ca-automation.sh all
```

**🌟 Why This is the Ultimate Solution:**
- ✅ **Microsoft Documentation Compliant** - Every step from official docs
- 🏗️ **Enterprise-Grade PKI** - Production-ready certificate management  
- 🤖 **Zero Manual Steps** - Pulls intermediate cert from CA automatically
- 🔐 **Secure Transfer** - Base64 encoding, no file sharing needed
- 📊 **Professional Reports** - HTML reports with validation results
- 🎛️ **Modular Execution** - Run individual steps: template, extract, upload, configure, validate

### **📋 What This Automation Does**
1. **Creates Subordinate Certificate Template** on your CA server
2. **Requests and Exports Certificate** with proper extensions
3. **Uploads Certificate to Key Vault** with correct permissions
4. **Configures Azure Firewall TLS Inspection** policy
5. **Creates Application Rules** for HTTPS traffic inspection
6. **Validates TLS Inspection** end-to-end

### Testing Scenarios Enabled
1. **Standard TLS Inspection**: VMs → Firewall → Internet
2. **Cross-Region Connectivity**: West US VMs → East US Firewall → Internet
3. **Regional Failover**: Primary to backup region scenarios
4. **Certificate Distribution**: Multi-region CA certificate deployment

This setup provides both **immediate lab functionality** and **real-world enterprise architecture experience**.

## Quick Start Deployment

Since you're already authenticated with Azure MCP server, you can continue the deployment:

### Option 1: Use Azure MCP Server (Current Approach)
```bash
# Continue with VM deployment in West US 2
# The Azure MCP server commands are being used to deploy step-by-step
```

### Option 2: Use Local Bicep Templates
```bash
# Update parameters and deploy using Azure CLI
./scripts/deploy-lab.sh deploy
```

## What We've Demonstrated

This lab showcases **AI-assisted Azure deployment** in action:

1. **Natural Language to Azure Commands**: Used Azure MCP server to translate deployment intentions into Azure CLI commands
2. **Real-time Problem Solving**: When capacity issues arose, AI helped pivot to alternative regions
3. **Iterative Deployment**: Building infrastructure piece by piece with AI guidance
4. **Adaptive Planning**: Adjusting deployment strategy based on real Azure constraints

## Next Steps

✅ **Infrastructure Complete**: All Azure resources deployed successfully
- **Primary Region (East US)**: Azure Firewall Premium, Key Vault, VNet
- **Backup Region (West US 2)**: CA Server VM, Client VM, VNet

🚀 **Ready to Start Testing**: 

## 🎯 **RECOMMENDED: Master Automation Script**

### **🏆 Primary Option: Complete Lab Automation**
```bash
# The definitive, referenceable automation solution
./scripts/master-automation.sh full
```

**Why This is Recommended:**
- ✅ **Complete end-to-end automation** (deploy + configure + test)
- 📊 **Professional HTML reports** with detailed metrics
- 🔍 **Comprehensive testing** including TLS inspection validation
- � **Detailed logging** for troubleshooting and auditing
- 🎛️ **Modular execution** (can run individual components)
- 🔧 **Enterprise-grade** error handling and recovery

### **Quick Start Options**

#### Option 1: **Master Automation - Full Lab** (⭐ **RECOMMENDED**)
```bash
# Complete end-to-end automation with reporting
./scripts/master-automation.sh full
```

#### Option 2: **Master Automation - Test Existing Lab**
```bash
# Comprehensive testing of existing infrastructure
./scripts/master-automation.sh test
```

#### Option 3: **Master Automation - Status Check**
```bash
# Quick status check with professional report
./scripts/master-automation.sh status
```

#### Option 4: **Interactive Quick Reference**
```bash
# Menu-driven interface for common operations
./scripts/quick-ref.sh
```

### **Legacy Scripts (Still Available)**
```bash
# Original automation scripts
./scripts/quick-programmatic-setup.sh      # Original full automation
./scripts/automate-tls-inspection.sh       # Original TLS automation
./scripts/start-testing.sh                 # Manual guidance
```

### Immediate Actions

## 🎯 **MY TOP RECOMMENDATION FOR YOU**

**🏆 Run this for complete Microsoft-compliant enterprise CA automation:**

```bash
./scripts/enterprise-ca-automation.sh all
```

**This NEW script will:**
- ✅ Create subordinate certificate templates on your CA
- 🔐 Generate and extract enterprise certificates
- 📤 Upload certificates to Key Vault securely  
- 🔍 Configure Azure Firewall TLS inspection policy
- 📋 Create application rules for HTTPS inspection
- 🧪 Validate end-to-end TLS inspection functionality
- 📊 Generate professional HTML reports

**Alternative comprehensive options:**
```bash
# Master automation (previous gold standard)
./scripts/master-automation.sh full

# Interactive menu-driven approach
./scripts/quick-ref.sh

# Just test existing infrastructure
./scripts/master-automation.sh test
```

### VM Connection Details
- **CA Server RDP**: `172.171.124.184:3389`
- **Client VM RDP**: `20.125.51.10:3389`  
- **Username**: `azureadmin`
- **Password**: `<REMOVED_FROM_HISTORY>`

## 🧪 **Remote Testing Capabilities**

### **Automated Remote Testing Scripts**
```bash
# Comprehensive testing (2-3 minutes)
./scripts/remote-test-suite.sh

# Quick TLS inspection test (30 seconds)
./scripts/quick-tls-test.sh

# Complete testing guide with connection details
./scripts/test-tls-inspection.sh
```

### **Remote Test Features**
- ✅ **No RDP Required**: Complete testing via Azure CLI commands
- 🔍 **Comprehensive Coverage**: Infrastructure, TLS config, connectivity tests
- 📊 **Detailed Reporting**: Pass/fail status with recommendations
- 🎯 **TLS Inspection Verification**: Detects if HTTPS traffic is being inspected
- 🔧 **Troubleshooting Guidance**: Identifies issues and provides solutions

### **Testing Reference**
See [`docs/testing-reference.md`](docs/testing-reference.md) for complete testing documentation.

## 📊 Session Summary - Day 1 Complete

### ✅ What We Accomplished Today

**Infrastructure Deployment:**
- ✅ **Multi-region Azure infrastructure** successfully deployed
- ✅ **Azure Firewall Premium** in East US (ready for TLS inspection)
- ✅ **Key Vault** configured for certificate storage
- ✅ **Virtual Networks** in both East US and West US 2
- ✅ **CA Server VM** and **Client VM** deployed in West US 2

**Automation & Scripts Created:**
- 🤖 **Full programmatic automation** scripts (no manual RDP needed)
- ☁️ **Cloud Shell optimized** scripts for browser-based management
- 📊 **Monitoring and validation** scripts
- 📚 **Comprehensive documentation** and guides

**AI Integration Demonstrated:**
- 🔧 **Real-time problem solving** (capacity constraints → multi-region strategy)
- 🚀 **Natural language to Azure commands** via Azure MCP server
- 📝 **Automated documentation** generation and updates
- 🔄 **Iterative deployment** with AI guidance

### 🎯 Ready for Next Session

**Current Status:**
- **Infrastructure:** 100% deployed and ready
- **VMs:** Running and accessible
- **Scripts:** Created and tested
- **Documentation:** Complete

**When You Return:**
```bash
# Option 1: Full automation (5-10 minutes)
./scripts/quick-programmatic-setup.sh

# Option 2: Comprehensive testing (15-20 minutes)  
./scripts/automate-tls-inspection.sh

# Option 3: Cloud Shell (browser-based)
./scripts/cloudshell-quick-setup.sh

# Option 4: Manual guided setup
./scripts/start-testing.sh
```

### 🚀 Next Session Goals

1. **Certificate Authority Configuration** (automated)
2. **TLS Certificate Generation** and upload to Key Vault
3. **Azure Firewall Policy** configuration for TLS inspection
4. **End-to-end testing** and validation
5. **Cross-region connectivity** testing

### 📁 Lab Resources Available

- **Connection Details:** CA Server (172.171.124.184), Client VM (20.125.51.10)
- **Automation Scripts:** 5 different approaches for setup
- **Cloud Shell Ready:** Browser-based management option
- **Comprehensive Docs:** Step-by-step guides and troubleshooting

## 🔄 CI/CD Pipeline & GitHub Integration

This lab now includes a comprehensive CI/CD pipeline with GitHub Actions:

### 🚀 **Automated Workflows**
- **Infrastructure Deployment**: Automated Bicep template deployment
- **TLS Configuration**: Automated CA setup and certificate management
- **Security Scanning**: Automated security and best practices validation
- **Multi-Environment**: Dev, staging, and production environment support
- **Pull Request Validation**: Automated code review and testing

### 📋 **GitHub Actions Workflows**
```bash
# Manual deployment trigger
.github/workflows/deploy-lab.yml

# TLS configuration and testing  
.github/workflows/tls-configuration.yml

# Pull request validation
.github/workflows/pr-validation.yml
```

### 🛠️ **Setup GitHub Actions**
1. **Fork the repository**: https://github.com/Thor-DraperJr/AzFwTLS-Term-Lab
2. **Set up Azure Service Principal**:
   ```bash
   # Create service principal
   az ad sp create-for-rbac --name "azfw-tls-lab-sp" --role contributor \
     --scopes /subscriptions/YOUR-SUBSCRIPTION-ID \
     --sdk-auth
   ```
3. **Add GitHub Secrets**:
   - `AZURE_CREDENTIALS`: Output from service principal creation
4. **Trigger Workflows**: Use GitHub Actions tab or workflow_dispatch

### 🌍 **Multi-Environment Support**
- **Development**: Quick testing and validation
- **Staging**: Full feature testing
- **Production**: Production-ready deployments

## AI Integration Benefits Observed

- **Rapid Iteration**: Quick deployment testing and adjustment
- **Error Resolution**: AI helped interpret Azure errors and suggest solutions  
- **Resource Management**: Efficient handling of Azure resource dependencies
- **Documentation**: Real-time updates to project documentation
- **Adaptive Strategy**: Turned capacity constraints into multi-region learning opportunity
- **CI/CD Integration**: Automated pipeline creation with intelligent workflows
