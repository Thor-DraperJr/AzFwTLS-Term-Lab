# PowerShell script to generate certificates for Azure Firewall TLS Inspection
# This script creates a root CA and intermediate CA certificate suitable for Azure Firewall

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Certificates",
    
    [Parameter(Mandatory=$false)]
    [string]$RootCACommonName = "Lab Root CA",
    
    [Parameter(Mandatory=$false)]
    [string]$IntermediateCACommonName = "Azure Firewall Intermediate CA",
    
    [Parameter(Mandatory=$false)]
    [int]$ValidityYears = 5,
    
    [Parameter(Mandatory=$false)]
    [int]$IntermediateValidityYears = 2
)

# Ensure we're running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force
    Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
}

Write-Host "=== Azure Firewall TLS Inspection Certificate Generator ===" -ForegroundColor Cyan
Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow
Write-Host "Root CA: $RootCACommonName" -ForegroundColor Yellow
Write-Host "Intermediate CA: $IntermediateCACommonName" -ForegroundColor Yellow

# Step 1: Create Root CA Certificate
Write-Host "`n[1/4] Creating Root CA Certificate..." -ForegroundColor Green

$rootCertParams = @{
    Subject = "CN=$RootCACommonName"
    KeyLength = 4096
    KeyAlgorithm = "RSA"
    HashAlgorithm = "SHA256"
    KeyUsage = "CertSign", "CRLSign", "DigitalSignature"
    NotAfter = (Get-Date).AddYears($ValidityYears)
    CertStoreLocation = "Cert:\LocalMachine\My"
    KeyExportPolicy = "Exportable"
    TextExtension = @(
        "2.5.29.19={critical}{text}CA=true",  # Basic Constraints
        "2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2"  # Enhanced Key Usage
    )
}

try {
    $rootCert = New-SelfSignedCertificate @rootCertParams
    Write-Host "Root CA certificate created successfully." -ForegroundColor Green
    Write-Host "Thumbprint: $($rootCert.Thumbprint)" -ForegroundColor Yellow
} catch {
    Write-Error "Failed to create root CA certificate: $_"
    exit 1
}

# Step 2: Export Root CA Certificate (for client trust)
Write-Host "`n[2/4] Exporting Root CA Certificate..." -ForegroundColor Green

$rootCertPath = Join-Path $OutputPath "RootCA.crt"
try {
    Export-Certificate -Cert $rootCert -FilePath $rootCertPath -Type CERT
    Write-Host "Root CA certificate exported to: $rootCertPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to export root CA certificate: $_"
    exit 1
}

# Step 3: Create Intermediate CA Certificate
Write-Host "`n[3/4] Creating Intermediate CA Certificate..." -ForegroundColor Green

$intermediateCertParams = @{
    Subject = "CN=$IntermediateCACommonName"
    KeyLength = 4096
    KeyAlgorithm = "RSA"
    HashAlgorithm = "SHA256"
    KeyUsage = "CertSign", "CRLSign", "DigitalSignature"
    NotAfter = (Get-Date).AddYears($IntermediateValidityYears)
    CertStoreLocation = "Cert:\LocalMachine\My"
    KeyExportPolicy = "Exportable"
    Signer = $rootCert
    TextExtension = @(
        "2.5.29.19={critical}{text}CA=true&pathlength=1",  # Basic Constraints with path length
        "2.5.29.15={critical}{hex}0300"  # Key Usage: Digital Signature + Certificate Sign
    )
}

try {
    $intermediateCert = New-SelfSignedCertificate @intermediateCertParams
    Write-Host "Intermediate CA certificate created successfully." -ForegroundColor Green
    Write-Host "Thumbprint: $($intermediateCert.Thumbprint)" -ForegroundColor Yellow
} catch {
    Write-Error "Failed to create intermediate CA certificate: $_"
    exit 1
}

# Step 4: Export Intermediate CA Certificate for Azure Firewall
Write-Host "`n[4/4] Exporting Intermediate CA Certificate for Azure Firewall..." -ForegroundColor Green

# Export as PFX (PKCS#12) format without password for Azure Firewall
$intermediatePfxPath = Join-Path $OutputPath "IntermediateCA-AzureFirewall.pfx"
try {
    # Export without password as required by Azure Firewall
    Export-PfxCertificate -Cert $intermediateCert -FilePath $intermediatePfxPath -Password (New-Object System.Security.SecureString)
    Write-Host "Intermediate CA certificate (PFX) exported to: $intermediatePfxPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to export intermediate CA certificate: $_"
    exit 1
}

# Also export as CRT for reference
$intermediateCrtPath = Join-Path $OutputPath "IntermediateCA.crt"
try {
    Export-Certificate -Cert $intermediateCert -FilePath $intermediateCrtPath -Type CERT
    Write-Host "Intermediate CA certificate (CRT) exported to: $intermediateCrtPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to export intermediate CA certificate (CRT): $_"
}

# Display certificate information
Write-Host "`n=== Certificate Information ===" -ForegroundColor Cyan

Write-Host "`nRoot CA Certificate:" -ForegroundColor Yellow
Write-Host "  Subject: $($rootCert.Subject)"
Write-Host "  Thumbprint: $($rootCert.Thumbprint)"
Write-Host "  Valid From: $($rootCert.NotBefore)"
Write-Host "  Valid To: $($rootCert.NotAfter)"
Write-Host "  Key Length: 4096 bits"

Write-Host "`nIntermediate CA Certificate:" -ForegroundColor Yellow
Write-Host "  Subject: $($intermediateCert.Subject)"
Write-Host "  Thumbprint: $($intermediateCert.Thumbprint)"
Write-Host "  Valid From: $($intermediateCert.NotBefore)"
Write-Host "  Valid To: $($intermediateCert.NotAfter)"
Write-Host "  Key Length: 4096 bits"
Write-Host "  Issuer: $($intermediateCert.Issuer)"

Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
Write-Host "1. Upload '$intermediatePfxPath' to Azure Key Vault"
Write-Host "2. Configure Azure Firewall Policy to use the certificate for TLS inspection"
Write-Host "3. Deploy '$rootCertPath' to client machines' Trusted Root CA store"
Write-Host "4. Test TLS inspection functionality"

Write-Host "`n=== Files Created ===" -ForegroundColor Cyan
Write-Host "  Root CA Certificate: $rootCertPath"
Write-Host "  Intermediate CA Certificate: $intermediateCrtPath"
Write-Host "  Azure Firewall PFX: $intermediatePfxPath"

Write-Host "`nCertificate generation completed successfully!" -ForegroundColor Green
