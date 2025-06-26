# Azure Firewall TLS Inspection Lab with AI Integration

This lab demonstrates how to set up Azure Firewall Premium with TLS inspection using an Enterprise CA certificate, leveraging AI tools for automation and simplification.

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
- **Subscription ID**: `e440a65b-7418-4865-9821-88e411ffdd5b`

✅ **Initial Infrastructure Deployed** (East US):
- Resource Group: `rg-azfw-tls-lab`
- Virtual Network: `azfw-tls-lab-vnet` (10.0.0.0/16)
- Azure Firewall Premium: `azfw-tls-lab-firewall`
- Firewall Policy: `azfw-tls-lab-policy` (Premium tier)
- Public IP: `104.45.196.25`
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
1. **🤖 Programmatic Setup** (Recommended): `./scripts/quick-programmatic-setup.sh` - Full automation
2. **📋 Manual Setup**: `./scripts/start-testing.sh` - Step-by-step guidance  
3. **📖 Detailed Guide**: `docs/testing-guide.md` - Complete instructions

### Quick Start Options

#### Option A: Fully Automated (5-10 minutes)
```bash
# Complete automation - no RDP needed
./scripts/quick-programmatic-setup.sh
```

#### Option B: Full Automation with Detailed Logging (15-20 minutes)  
```bash
# Comprehensive automation with testing
./scripts/automate-tls-inspection.sh
```

#### Option C: Manual/Interactive Setup
```bash
# Get connection info and manual guidance
./scripts/start-testing.sh

# Monitor deployment status
./scripts/monitor-deployment.sh
```

### Immediate Actions
```bash
# Option 1: Full automation (Recommended)
./scripts/quick-programmatic-setup.sh

# Option 2: Comprehensive automation with testing  
./scripts/automate-tls-inspection.sh

# Option 3: Manual setup guidance
./scripts/start-testing.sh

# Monitor status
./scripts/monitor-deployment.sh
```

### VM Connection Details
- **CA Server RDP**: `172.171.124.184:3389`
- **Client VM RDP**: `20.125.51.10:3389`  
- **Username**: `azureadmin`
- **Password**: `SecureP@ssw0rd123!`

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
