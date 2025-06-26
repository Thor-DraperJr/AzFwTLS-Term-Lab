# Azure Firewall TLS Inspection Lab - Step-by-Step Deployment Guide

This guide walks you through the complete process of setting up and testing Azure Firewall Premium with TLS inspection using an Enterprise CA certificate.

## Prerequisites

Before starting, ensure you have:

- **Azure subscription** with permissions to create resources
- **Azure CLI** installed and configured (`az login`)
- **PowerShell 7+** for certificate generation scripts
- **Basic understanding** of PKI and certificate management
- **Estimated time**: 2-3 hours for complete setup and testing

## Phase 1: Infrastructure Deployment

### Step 1: Clone and Review the Lab

```bash
# Navigate to the lab directory
cd /home/thor-ubuntu/AzFwTLS-Term-Lab

# Review the architecture
cat README.md

# Review the Bicep templates
ls -la bicep/
ls -la bicep/modules/
```

### Step 2: Configure Parameters

Edit the parameter file for your environment:

```bash
# Edit the lab parameters
nano bicep/parameters/lab.parameters.json
```

**Important settings to review:**
- `adminPassword`: Change from default to a secure password
- `location`: Set to your preferred Azure region
- `deployBastion`: Set to `true` if you want secure access without public IPs

### Step 3: Deploy the Infrastructure

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Deploy the lab infrastructure
./scripts/deploy-lab.sh deploy
```

This deployment includes:
- Virtual network with proper subnets
- Azure Firewall Premium with policy
- Key Vault for certificate storage
- Windows Server VM (for CA)
- Windows Client VM (for testing)
- Routing configuration

**Expected deployment time**: 15-30 minutes

### Step 4: Verify Infrastructure

```bash
# Check deployment status
./scripts/deploy-lab.sh validate

# View deployment outputs
az deployment group show \
  --resource-group rg-azfw-tls-lab \
  --name azfw-tls-lab-* \
  --query 'properties.outputs'
```

## Phase 2: Certificate Authority Setup

### Step 5: Configure the CA Server

1. **Connect to the CA Server VM**:
   - Via Azure Portal (Bastion if deployed)
   - Or RDP using public IP: `az vm show --resource-group rg-azfw-tls-lab --name azfw-tls-lab-ca-vm --show-details --query publicIps`

2. **Complete Active Directory Setup**:
   ```powershell
   # Check if AD Domain Services is installed
   Get-WindowsFeature -Name AD-Domain-Services
   
   # If not installed, install and configure
   Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
   
   # Promote to Domain Controller
   Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns
   ```

3. **Install Certificate Services**:
   ```powershell
   # Install AD Certificate Services
   Install-WindowsFeature -Name ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools
   
   # Configure CA
   Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CACommonName "Lab Root CA" -Force
   Install-AdcsWebEnrollment -Force
   ```

### Step 6: Generate Certificates

Run the certificate generation script on the CA server:

```powershell
# Copy the script to the CA server and run
.\Generate-TLSCertificates.ps1 -OutputPath "C:\Certificates"
```

This script creates:
- **Root CA certificate** (for client trust)
- **Intermediate CA certificate** (for Azure Firewall)
- **Properly formatted PFX** file for Azure Firewall

### Step 7: Upload Certificate to Key Vault

From your local machine or Azure Cloud Shell:

```bash
# First, download the PFX file from the CA server to your local machine
# Then upload to Key Vault
./scripts/upload-certificate.sh -f /path/to/IntermediateCA-AzureFirewall.pfx
```

## Phase 3: TLS Inspection Configuration

### Step 8: Enable TLS Inspection

The upload script automatically configures the firewall policy, but you can also do it manually:

```bash
# Get the Key Vault secret ID
SECRET_ID=$(az keyvault certificate show \
  --vault-name azfw-tls-lab-kv-* \
  --name azfw-tls-intermediate-ca \
  --query 'sid' \
  --output tsv)

# Update firewall policy
az network firewall policy update \
  --resource-group rg-azfw-tls-lab \
  --name azfw-tls-lab-policy \
  --cert-name "TLSInspectionCA" \
  --key-vault-secret-id "$SECRET_ID"
```

### Step 9: Configure Application Rules with TLS Inspection

```bash
# Enable TLS inspection on web traffic rules
az network firewall policy rule-collection-group collection rule update \
  --resource-group rg-azfw-tls-lab \
  --policy-name azfw-tls-lab-policy \
  --rule-collection-group-name 'DefaultApplicationRuleCollectionGroup' \
  --collection-name 'ApplicationRuleCollection' \
  --name 'AllowWeb' \
  --terminate-tls true
```

## Phase 4: Client Configuration and Testing

### Step 10: Configure Client Trust

1. **Connect to the Client VM**
2. **Join to Domain** (if using AD):
   ```powershell
   # Join client to domain
   Add-Computer -DomainName "lab.local" -Credential (Get-Credential)
   ```

3. **Or manually install Root CA** (if not domain-joined):
   ```powershell
   # Import root CA certificate to trusted store
   Import-Certificate -FilePath "C:\RootCA.crt" -CertStoreLocation "Cert:\LocalMachine\Root"
   ```

### Step 11: Test TLS Inspection

1. **From Client VM, browse to HTTPS sites**:
   - https://www.bing.com
   - https://www.github.com
   - https://www.microsoft.com

2. **Verify certificate chain**:
   - Check that certificates are issued by "Azure Firewall Intermediate CA"
   - Verify no certificate warnings appear

3. **Monitor firewall logs**:
   ```bash
   # Check application rule logs
   az monitor log-analytics query \
     --workspace azfw-tls-lab-workspace \
     --analytics-query "AzureDiagnostics | where Category == 'AzureFirewallApplicationRule' | take 50"
   ```

## Phase 5: Validation and Testing

### Step 12: Validate TLS Inspection

**From Client VM**:

```powershell
# Test HTTPS connectivity
Invoke-WebRequest -Uri "https://www.bing.com" -UseBasicParsing

# Check certificate details
$cert = Get-WebCertificate -Url "https://www.bing.com"
$cert.Issuer  # Should show Azure Firewall Intermediate CA
```

**Expected Results**:
- ✅ HTTPS sites load without certificate errors
- ✅ Certificate issuer shows "Azure Firewall Intermediate CA"
- ✅ Firewall logs show application rule hits
- ✅ TLS inspection is actively decrypting and re-encrypting traffic

### Step 13: Troubleshooting

**Common Issues**:

1. **Certificate Errors on Client**:
   - Verify Root CA is in Trusted Root store
   - Check time synchronization between VMs

2. **TLS Inspection Not Working**:
   - Verify certificate uploaded to Key Vault correctly
   - Check firewall policy configuration
   - Ensure application rules have `terminateTLS: true`

3. **Connectivity Issues**:
   - Verify route table is associated with client subnet
   - Check NSG rules allow required traffic
   - Confirm firewall rules allow the destination

## Phase 6: AI Integration Testing

### Step 14: Test AI-Assisted Certificate Management

Use GitHub Copilot and Claude to:

1. **Generate additional certificates**:
   - Ask Copilot to modify the PowerShell script for different scenarios
   - Use Claude to explain certificate requirements and troubleshoot issues

2. **Automate additional tasks**:
   - Generate scripts for certificate rotation
   - Create monitoring and alerting configurations
   - Build automated testing scripts

3. **Optimize the deployment**:
   - Use AI to suggest Bicep template improvements
   - Generate documentation and runbooks
   - Create disaster recovery procedures

## Cleanup

When finished with the lab:

```bash
# Delete all resources
./scripts/deploy-lab.sh clean
```

## Security Considerations

⚠️ **Important**: This is a lab environment with several security considerations:

- **Default passwords**: Change all default passwords
- **Public IPs**: VMs have public IPs for easy access - not recommended for production
- **Firewall rules**: Permissive rules for testing - tighten for production
- **Certificate validity**: Short validity periods for testing - extend for production
- **Key management**: Simplified key management - use proper PKI hierarchy for production

## Next Steps

- **Production deployment**: Adapt templates for production use
- **Monitoring**: Implement comprehensive logging and monitoring
- **Automation**: Create CI/CD pipelines for certificate management
- **Integration**: Connect with existing PKI infrastructure
- **Scaling**: Design for multiple environments and certificate rotation

## Support and Resources

- **Azure Firewall Documentation**: https://docs.microsoft.com/en-us/azure/firewall/
- **Bicep Documentation**: https://docs.microsoft.com/en-us/azure/azure-resource-manager/bicep/
- **PKI Best Practices**: https://docs.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/server-certificate-deployment-overview
- **Lab GitHub Issues**: For questions and issues specific to this lab
