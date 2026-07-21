param(
    [Parameter(Mandatory = $true)]
    [SecureString]$PfxPassword
)

$ErrorActionPreference = 'Stop'
Write-Output 'Starting Enterprise CA configuration.'

Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -CACommonName 'AzFirewall-Lab-CA' -CADistinguishedNameSuffix 'DC=azfirewall,DC=lab' -Force

$request = @"
[NewRequest]
Subject = "CN=AzFirewall-Intermediate-CA,DC=azfirewall,DC=lab"
KeyLength = 2048
KeyAlgorithm = RSA
HashAlgorithm = SHA256
MachineKeySet = TRUE
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1
"@

$request | Out-File 'C:\cert-request.inf' -Encoding ASCII
certreq -new 'C:\cert-request.inf' 'C:\cert-request.req'
certreq -submit -config 'localhost\AzFirewall-Lab-CA' 'C:\cert-request.req' 'C:\intermediate-ca.cer'

$certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object HasPrivateKey | Select-Object -First 1
Export-PfxCertificate -Cert $certificate -FilePath 'C:\azfirewall-ca.pfx' -Password $PfxPassword

Write-Output 'CA configuration completed. Store the PFX password outside the repository.'
