param(
    [Parameter(Mandatory = $true)]
    [SecureString]$PfxPassword
)

$ErrorActionPreference = 'Stop'

try {
    Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'AzFirewall-TLS-Lab-CA' -CADistinguishedNameSuffix 'DC=azfwlab,DC=local' -Force

    Start-Sleep -Seconds 20

    $request = @"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject="CN=Azure-Firewall-Intermediate-CA,O=AzFirewall-TLS-Lab,C=US"
KeyLength=2048
KeyAlgorithm=RSA
MachineKeySet=TRUE
RequestType=PKCS10
[Extensions]
2.5.29.19 = "{text}CA:TRUE&pathlength:0"
"@

    New-Item -Path 'C:\cert' -ItemType Directory -Force | Out-Null
    $request | Out-File 'C:\cert\req.inf' -Encoding ASCII

    certreq -new 'C:\cert\req.inf' 'C:\cert\req.req'
    certreq -submit -config '.\AzFirewall-TLS-Lab-CA' 'C:\cert\req.req' 'C:\cert\cert.cer'
    certreq -accept 'C:\cert\cert.cer'

    $certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*Azure-Firewall-Intermediate-CA*' } | Select-Object -First 1
    Export-PfxCertificate -Cert $certificate -FilePath 'C:\cert\intermediate.pfx' -Password $PfxPassword

    $rootCertificate = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*AzFirewall-TLS-Lab-CA*' } | Select-Object -First 1
    Export-Certificate -Cert $rootCertificate -FilePath 'C:\cert\root.cer'

    'SUCCESS' | Set-Content 'C:\cert\status.txt'
} catch {
    $_.Exception.Message | Set-Content 'C:\cert\error.txt'
    'FAILED' | Set-Content 'C:\cert\status.txt'
    throw
}
