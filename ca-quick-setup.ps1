# Quick CA Setup for Azure Firewall TLS Inspection
try {
    # Install AD CS
    Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
    
    # Configure CA
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "AzFirewall-TLS-Lab-CA" -CADistinguishedNameSuffix "DC=azfwlab,DC=local" -Force
    
    # Wait and create intermediate cert
    Start-Sleep 20
    
    # Generate certificate for Azure Firewall
    $req = @"
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
    
    New-Item -Path "C:\cert" -Type Directory -Force
    $req | Out-File "C:\cert\req.inf" -Encoding ASCII
    
    certreq -new "C:\cert\req.inf" "C:\cert\req.req"
    certreq -submit -config ".\AzFirewall-TLS-Lab-CA" "C:\cert\req.req" "C:\cert\cert.cer"
    certreq -accept "C:\cert\cert.cer"
    
    # Export certificates
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Azure-Firewall-Intermediate-CA*"}
    $pwd = ConvertTo-SecureString "AzFirewall2025!" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "C:\cert\intermediate.pfx" -Password $pwd
    
    $root = Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*AzFirewall-TLS-Lab-CA*"}
    Export-Certificate -Cert $root -FilePath "C:\cert\root.cer"
    
    "SUCCESS" > "C:\cert\status.txt"
} catch {
    $_.Exception.Message > "C:\cert\error.txt"
    "FAILED" > "C:\cert\status.txt"
}
