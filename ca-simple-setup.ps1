# Configure Enterprise CA - Simple PowerShell Script for Azure VM Extension
# This script installs and configures Active Directory Certificate Services

Write-Output "Starting Enterprise CA Configuration..."
Write-Output "Time: $(Get-Date)"

try {
    # Install AD Certificate Services role
    Write-Output "Installing AD Certificate Services role..."
    Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
    
    # Install CA role service
    Write-Output "Installing Certification Authority role service..."
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -CACommonName "AzFirewall-Lab-CA" -CADistinguishedNameSuffix "DC=azfirewall,DC=lab" -Force
    
    # Create certificate template for intermediate CA
    Write-Output "Configuring certificate templates..."
    
    # Generate intermediate CA certificate request
    Write-Output "Generating intermediate CA certificate..."
    $certRequest = @"
[NewRequest]
Subject = "CN=AzFirewall-Intermediate-CA,DC=azfirewall,DC=lab"
KeyLength = 2048
KeyAlgorithm = RSA
HashAlgorithm = SHA256
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1
"@

    $certRequest | Out-File -FilePath "C:\cert-request.inf" -Encoding ASCII
    
    # Create certificate request
    certreq -new "C:\cert-request.inf" "C:\cert-request.req"
    
    # Submit and approve the request
    $requestId = certreq -submit -config "localhost\AzFirewall-Lab-CA" "C:\cert-request.req" "C:\intermediate-ca.cer"
    
    # Extract certificate and private key for Azure Firewall
    Write-Output "Exporting certificate for Azure Firewall..."
    
    # Create PFX with private key
    $password = ConvertTo-SecureString -String "AzFirewall2025!" -Force -AsPlainText
    Export-PfxCertificate -Cert "Cert:\LocalMachine\My\*" -FilePath "C:\azfirewall-ca.pfx" -Password $password
    
    Write-Output "CA configuration completed successfully!"
    Write-Output "Certificate files created:"
    Write-Output "- C:\intermediate-ca.cer (public certificate)"
    Write-Output "- C:\azfirewall-ca.pfx (certificate with private key)"
    Write-Output "- Password: AzFirewall2025!"
    
} catch {
    Write-Error "CA configuration failed: $($_.Exception.Message)"
    exit 1
}

Write-Output "Enterprise CA setup completed at $(Get-Date)"
