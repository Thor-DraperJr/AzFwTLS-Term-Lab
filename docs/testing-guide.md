# Azure Firewall TLS Inspection Testing Guide

## 🚀 Quick Start Testing

Now that your infrastructure is deployed, here's how to start testing TLS inspection:

### Current Status ✅
- **Azure Firewall Premium**: Deployed in East US
- **Key Vault**: Ready for certificate storage
- **CA Server VM**: Deployed in West US 2 (172.171.124.184)
- **Client VM**: Deployed in West US 2 (20.125.51.10)

## Step 1: Connect to CA Server and Install AD CS

### Connect via RDP
```bash
# Use RDP client to connect to CA Server
# Host: 172.171.124.184
# Port: 3389
# Username: azureadmin
# Password: SecureP@ssw0rd123!
```

### Install Active Directory Certificate Services
Once connected to the CA server, run these PowerShell commands:

```powershell
# Install AD CS Role
Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools

# Configure Certificate Authority
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "AzFirewall-TLS-Lab-CA" -CADistinguishedNameSuffix "DC=azfwlab,DC=local" -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 10

# Enable Certificate Templates
Add-WindowsFeature -Name ADCS-Web-Enrollment
Install-AdcsWebEnrollment
```

## Step 2: Generate Intermediate CA Certificate

### Create Certificate Template for Azure Firewall
```powershell
# Create certificate request for Azure Firewall intermediate CA
$certReq = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject="CN=Azure-Firewall-Intermediate-CA,O=AzFirewall-TLS-Lab,C=US"
KeyLength=2048
KeyAlgorithm=RSA
MachineKeySet=TRUE
RequestType=PKCS10
KeyUsage=0x86
KeyUsageProperty=0x80

[Extensions]
2.5.29.19 = "{text}CA:TRUE&pathlength:0"
2.5.29.37 = "{text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2"
2.5.29.15 = "{text}Digital Signature, Key Encipherment, Certificate Signing"

[RequestAttributes]
CertificateTemplate=SubCA
"@

# Save request file
$certReq | Out-File -FilePath "C:\temp\azfw-intermediate-ca.inf" -Encoding ASCII

# Create certificate request
certreq -new "C:\temp\azfw-intermediate-ca.inf" "C:\temp\azfw-intermediate-ca.req"

# Submit to CA and retrieve certificate
certreq -submit -config "ca-server\AzFirewall-TLS-Lab-CA" "C:\temp\azfw-intermediate-ca.req" "C:\temp\azfw-intermediate-ca.cer"

# Install certificate
certreq -accept "C:\temp\azfw-intermediate-ca.cer"
```

## Step 3: Export Certificate for Azure Firewall

### Export Certificate Chain
```powershell
# Export the intermediate CA certificate with private key
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Azure-Firewall-Intermediate-CA*"}
$pfxPassword = ConvertTo-SecureString -String "AzFirewall2025!" -Force -AsPlainText

# Export PFX file
Export-PfxCertificate -Cert $cert -FilePath "C:\temp\azfw-intermediate-ca.pfx" -Password $pfxPassword

# Export public certificate
Export-Certificate -Cert $cert -FilePath "C:\temp\azfw-intermediate-ca.cer"

# Also export the root CA certificate
$rootCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*AzFirewall-TLS-Lab-CA*"}
Export-Certificate -Cert $rootCert -FilePath "C:\temp\azfw-root-ca.cer"
```

## Step 4: Upload Certificates to Key Vault

### From your local machine (with Azure CLI)
```bash
# First, copy the certificates from the CA server to your local machine
# You can use SCP, RDP file transfer, or Azure Storage

# Upload root CA certificate to Key Vault
az keyvault certificate import \
  --vault-name azfw-tls-lab-kv-2025 \
  --name azfw-root-ca \
  --file azfw-root-ca.cer

# Upload intermediate CA certificate to Key Vault
az keyvault certificate import \
  --vault-name azfw-tls-lab-kv-2025 \
  --name azfw-intermediate-ca \
  --file azfw-intermediate-ca.pfx \
  --password "AzFirewall2025!"
```

## Step 5: Configure Azure Firewall Policy for TLS Inspection

### Enable TLS Inspection
```bash
# Get the certificate ID from Key Vault
CERT_ID=$(az keyvault certificate show \
  --vault-name azfw-tls-lab-kv-2025 \
  --name azfw-intermediate-ca \
  --query "id" -o tsv)

# Update firewall policy to enable TLS inspection
az network firewall policy update \
  --resource-group rg-azfw-tls-lab \
  --name azfw-tls-lab-policy \
  --enable-tls-inspection true \
  --certificate-authority $CERT_ID
```

### Create Application Rule with TLS Inspection
```bash
# Create rule collection for TLS inspection
az network firewall policy rule-collection-group collection add-filter-collection \
  --resource-group rg-azfw-tls-lab \
  --policy-name azfw-tls-lab-policy \
  --rule-collection-group-name DefaultApplicationRuleCollectionGroup \
  --name "TLS-Inspection-Rules" \
  --collection-priority 1000 \
  --action Allow \
  --rule-name "Allow-HTTPS-with-TLS-Inspection" \
  --rule-type ApplicationRule \
  --description "Allow HTTPS traffic with TLS inspection" \
  --destination-addresses "*" \
  --source-addresses "10.1.0.0/16" \
  --protocols "Https=443" \
  --enable-tls-inspection true
```

## Step 6: Configure Network Routing

### Create Route Table for West US 2 VMs
```bash
# Create route table
az network route-table create \
  --resource-group rg-azfw-tls-lab-west \
  --name azfw-tls-lab-west-rt \
  --location westus2

# Add route to send traffic through East US firewall
az network route-table route create \
  --resource-group rg-azfw-tls-lab-west \
  --route-table-name azfw-tls-lab-west-rt \
  --name "DefaultRoute" \
  --address-prefix 0.0.0.0/0 \
  --next-hop-type VirtualAppliance \
  --next-hop-ip-address 10.0.1.4

# Associate route table with subnets
az network vnet subnet update \
  --resource-group rg-azfw-tls-lab-west \
  --vnet-name azfw-tls-lab-west-vnet \
  --name ca-subnet \
  --route-table azfw-tls-lab-west-rt

az network vnet subnet update \
  --resource-group rg-azfw-tls-lab-west \
  --vnet-name azfw-tls-lab-west-vnet \
  --name client-subnet \
  --route-table azfw-tls-lab-west-rt
```

## Step 7: Test TLS Inspection

### From Client VM (20.125.51.10)
```powershell
# Test HTTPS connectivity
Invoke-WebRequest -Uri "https://www.microsoft.com" -UseBasicParsing

# Test with certificate validation
Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing

# Check certificate chain
$webRequest = [System.Net.WebRequest]::Create("https://www.github.com")
$webRequest.GetResponse()
```

### Monitor Firewall Logs
```bash
# Query firewall logs for TLS inspection events
az monitor log-analytics query \
  --workspace azfw-tls-lab-workspace \
  --analytics-query "
    AzureDiagnostics
    | where Category == 'AzureFirewallApplicationRule'
    | where TimeGenerated > ago(1h)
    | where msg_s contains 'TLS'
    | project TimeGenerated, msg_s, Protocol_s, SourceIP_s, TargetURL_s
    | order by TimeGenerated desc
  "
```

## Step 8: Validate TLS Inspection

### Check Certificate Installation on Client
```powershell
# Import root CA certificate to client machine trust store
Import-Certificate -FilePath "C:\temp\azfw-root-ca.cer" -CertStoreLocation Cert:\LocalMachine\Root

# Verify certificate chain
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*AzFirewall-TLS-Lab-CA*"}
```

### Test Different Scenarios
1. **HTTPS to major websites** (Google, Microsoft, GitHub)
2. **Self-signed certificate sites** (should be blocked/warned)
3. **Non-HTTPS traffic** (should pass through normally)
4. **Certificate validation errors** (should be detected)

## Troubleshooting

### Common Issues
1. **Certificate not trusted**: Ensure root CA is in client trust store
2. **Routing issues**: Verify route tables and firewall rules
3. **DNS resolution**: Check DNS settings on client VMs
4. **Firewall policy**: Verify TLS inspection is enabled

### Monitoring Commands
```bash
# Check firewall status
az network firewall show \
  --resource-group rg-azfw-tls-lab \
  --name azfw-tls-lab-firewall \
  --query "provisioningState"

# Check certificate in Key Vault
az keyvault certificate show \
  --vault-name azfw-tls-lab-kv-2025 \
  --name azfw-intermediate-ca
```

## Next Steps

1. **Configure Log Analytics** for detailed monitoring
2. **Set up additional test scenarios** (malicious sites, different protocols)
3. **Document performance metrics** (latency, throughput)
4. **Test failover scenarios** between regions

## 🎯 Success Criteria

- ✅ CA server configured with AD CS
- ✅ Intermediate CA certificate generated and uploaded
- ✅ Azure Firewall policy configured for TLS inspection
- ✅ Client VMs can browse HTTPS sites through firewall
- ✅ TLS inspection logs visible in Azure Monitor
- ✅ Certificate validation working correctly
