#!/bin/bash

# Azure Firewall TLS Inspection Lab - Cloud Shell Quick Setup
# Optimized for Azure Cloud Shell environment

set -e

echo "☁️ Azure Firewall TLS Inspection Lab - Cloud Shell Quick Setup"
echo "=============================================================="
echo ""

# Cloud Shell detection and setup
detect_cloudshell() {
    if [[ -n "$AZURE_HTTP_USER_AGENT" ]] || [[ -n "$CLOUDSHELL" ]]; then
        echo "✅ Running in Azure Cloud Shell"
        export RUNNING_IN_CLOUDSHELL=true
        
        # Use Cloud Shell storage
        export LAB_HOME="$HOME/AzFwTLS-Term-Lab"
        
        # Ensure we're in the right directory
        if [[ "$PWD" != "$LAB_HOME" ]]; then
            if [[ -d "$LAB_HOME" ]]; then
                cd "$LAB_HOME"
            else
                echo "📁 Lab directory not found. Creating in Cloud Shell storage..."
                mkdir -p "$LAB_HOME"
                cd "$LAB_HOME"
            fi
        fi
        
        # Create persistent directories in Cloud Shell storage
        mkdir -p "$HOME/clouddrive/azfw-tls-lab/certificates"
        mkdir -p "$HOME/clouddrive/azfw-tls-lab/logs"
        
        # Link to Cloud Shell persistent storage
        ln -sf "$HOME/clouddrive/azfw-tls-lab/certificates" ./certificates
        ln -sf "$HOME/clouddrive/azfw-tls-lab/logs" ./logs
        
    else
        echo "💻 Running in local environment"
        export RUNNING_IN_CLOUDSHELL=false
        export LAB_HOME="$PWD"
    fi
}

# Enhanced Cloud Shell authentication check
check_cloudshell_auth() {
    echo "🔐 Checking Azure authentication..."
    
    if az account show >/dev/null 2>&1; then
        SUBSCRIPTION_NAME=$(az account show --query "name" -o tsv)
        SUBSCRIPTION_ID=$(az account show --query "id" -o tsv)
        TENANT_ID=$(az account show --query "tenantId" -o tsv)
        
        echo "✅ Authenticated to Azure:"
        echo "   📋 Subscription: $SUBSCRIPTION_NAME"
        echo "   🆔 Subscription ID: $SUBSCRIPTION_ID"
        echo "   🏢 Tenant ID: $TENANT_ID"
        
        # Store auth info for other scripts
        cat > ./cloudshell-auth.env << EOF
SUBSCRIPTION_NAME="$SUBSCRIPTION_NAME"
SUBSCRIPTION_ID="$SUBSCRIPTION_ID" 
TENANT_ID="$TENANT_ID"
AUTHENTICATED=true
EOF
        
        return 0
    else
        echo "❌ Not authenticated to Azure"
        if [[ "$RUNNING_IN_CLOUDSHELL" == "true" ]]; then
            echo "🔄 In Cloud Shell, authentication should be automatic"
            echo "   Try refreshing your browser or restarting Cloud Shell"
        else
            echo "🔑 Run: az login"
        fi
        return 1
    fi
}

# Cloud Shell specific environment setup
setup_cloudshell_env() {
    echo "⚙️ Setting up Cloud Shell environment..."
    
    # Set Azure CLI defaults for faster execution
    az config set core.output=json >/dev/null 2>&1 || true
    az config set core.only_show_errors=true >/dev/null 2>&1 || true
    
    # Enable parallel operations where possible
    export AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=1
    
    # Cloud Shell specific configurations
    if [[ "$RUNNING_IN_CLOUDSHELL" == "true" ]]; then
        # Use Cloud Shell storage for temporary files
        export TMPDIR="$HOME/clouddrive/azfw-tls-lab/temp"
        mkdir -p "$TMPDIR"
        
        # Set up logging
        export LOG_FILE="$HOME/clouddrive/azfw-tls-lab/logs/cloudshell-setup-$(date +%Y%m%d-%H%M%S).log"
        
        echo "📁 Using Cloud Shell persistent storage:"
        echo "   📂 Certificates: $HOME/clouddrive/azfw-tls-lab/certificates"
        echo "   📝 Logs: $HOME/clouddrive/azfw-tls-lab/logs"
        echo "   🗂️ Temp: $TMPDIR"
    fi
    
    echo "✅ Cloud Shell environment configured"
}

# Enhanced progress tracking for Cloud Shell
show_progress() {
    local step=$1
    local total=$2
    local message=$3
    local percentage=$((step * 100 / total))
    
    # Cloud Shell friendly progress bar
    local filled=$((percentage / 5))
    local empty=$((20 - filled))
    
    printf "\r🔄 [%s%s] %d%% - %s" \
        "$(printf '%*s' "$filled" | tr ' ' '█')" \
        "$(printf '%*s' "$empty" | tr ' ' '░')" \
        "$percentage" \
        "$message"
    
    if [[ $step -eq $total ]]; then
        echo ""
    fi
}

# Quick infrastructure check
check_infrastructure() {
    echo ""
    echo "🏗️ Checking infrastructure status..."
    
    # Check resource groups
    local rg_primary_status=$(az group show --name "rg-azfw-tls-lab" --query "properties.provisioningState" -o tsv 2>/dev/null || echo "NotFound")
    local rg_west_status=$(az group show --name "rg-azfw-tls-lab-west" --query "properties.provisioningState" -o tsv 2>/dev/null || echo "NotFound")
    
    echo "📊 Resource Groups:"
    echo "   🌍 Primary (East US): $rg_primary_status"
    echo "   🌎 Backup (West US 2): $rg_west_status"
    
    if [[ "$rg_primary_status" == "Succeeded" ]] && [[ "$rg_west_status" == "Succeeded" ]]; then
        echo "✅ Infrastructure is ready for TLS inspection setup"
        return 0
    else
        echo "⚠️ Infrastructure may not be complete"
        echo "💡 Run the full deployment first if needed"
        return 1
    fi
}

# Cloud Shell optimized VM extension deployment
deploy_ca_with_cloudshell() {
    echo ""
    echo "🚀 Deploying Certificate Authority (Cloud Shell Optimized)..."
    
    # Create optimized PowerShell script for Cloud Shell
    cat > ca-cloudshell-setup.ps1 << 'EOF'
# CA Setup optimized for Cloud Shell execution
param([string]$LogPath = "C:\CloudShellCA")

try {
    # Create logging directory
    New-Item -Path $LogPath -Type Directory -Force | Out-Null
    Start-Transcript -Path "$LogPath\setup.log" -Append
    
    Write-Host "Starting Cloud Shell CA setup..." -ForegroundColor Cyan
    
    # Install AD CS with minimal prompts
    Write-Host "Installing AD CS role..." -ForegroundColor Yellow
    $feature = Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools -ErrorAction Stop
    Write-Host "AD CS installed: $($feature.Success)" -ForegroundColor Green
    
    # Configure CA with error handling
    Write-Host "Configuring Certificate Authority..." -ForegroundColor Yellow
    try {
        Install-AdcsCertificationAuthority `
            -CAType EnterpriseRootCA `
            -CACommonName "CloudShell-AzFirewall-CA" `
            -CADistinguishedNameSuffix "DC=cloudshell,DC=lab" `
            -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
            -KeyLength 2048 `
            -HashAlgorithmName SHA256 `
            -ValidityPeriod Years `
            -ValidityPeriodUnits 5 `
            -Force `
            -ErrorAction Stop
        
        Write-Host "CA configured successfully" -ForegroundColor Green
        
        # Wait for CA service to be ready
        Start-Sleep -Seconds 30
        
        # Generate intermediate certificate
        Write-Host "Generating intermediate certificate..." -ForegroundColor Yellow
        
        $reqContent = @"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject="CN=CloudShell-AzFirewall-Intermediate,O=CloudShell-Lab,C=US"
KeyLength=2048
KeyAlgorithm=RSA
MachineKeySet=TRUE
RequestType=PKCS10
[Extensions]
2.5.29.19 = "{text}CA:TRUE&pathlength:0"
"@
        
        New-Item -Path "$LogPath\req.inf" -Value $reqContent -Force
        
        # Generate request and certificate
        & certreq -new "$LogPath\req.inf" "$LogPath\req.req"
        & certreq -submit -config ".\CloudShell-AzFirewall-CA" "$LogPath\req.req" "$LogPath\cert.cer"
        & certreq -accept "$LogPath\cert.cer"
        
        # Export certificates
        Write-Host "Exporting certificates..." -ForegroundColor Yellow
        
        $intermediateCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*CloudShell-AzFirewall-Intermediate*"}
        if ($intermediateCert) {
            $pwd = ConvertTo-SecureString "CloudShell2025!" -AsPlainText -Force
            Export-PfxCertificate -Cert $intermediateCert -FilePath "$LogPath\intermediate.pfx" -Password $pwd
            Export-Certificate -Cert $intermediateCert -FilePath "$LogPath\intermediate.cer"
            Write-Host "Intermediate certificate exported" -ForegroundColor Green
        }
        
        $rootCert = Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*CloudShell-AzFirewall-CA*"}
        if ($rootCert) {
            Export-Certificate -Cert $rootCert -FilePath "$LogPath\root.cer"
            Write-Host "Root certificate exported" -ForegroundColor Green
        }
        
        # Create completion marker
        "CLOUDSHELL_SUCCESS" | Out-File "$LogPath\status.txt"
        
        Write-Host "CA setup completed successfully!" -ForegroundColor Green
        
    } catch {
        Write-Host "CA configuration failed: $($_.Exception.Message)" -ForegroundColor Red
        "CLOUDSHELL_FAILED" | Out-File "$LogPath\status.txt"
        throw
    }
    
    Stop-Transcript
    
} catch {
    Write-Host "Setup failed: $($_.Exception.Message)" -ForegroundColor Red
    "CLOUDSHELL_ERROR" | Out-File "$LogPath\status.txt"
    if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) {
        Stop-Transcript
    }
}
EOF

    # Deploy CA setup via Azure CLI from Cloud Shell
    echo "📤 Uploading CA setup script to VM..."
    
    az vm run-command invoke \
        --resource-group "rg-azfw-tls-lab-west" \
        --name "ca-server-vm" \
        --command-id RunPowerShellScript \
        --scripts @ca-cloudshell-setup.ps1 \
        --no-wait
    
    echo "✅ CA setup initiated from Cloud Shell"
    
    # Monitor progress with Cloud Shell friendly output
    echo "⏳ Monitoring CA setup progress..."
    local attempts=0
    local max_attempts=15
    
    while [[ $attempts -lt $max_attempts ]]; do
        show_progress $((attempts + 1)) $max_attempts "Configuring Certificate Authority..."
        
        local status=$(az vm run-command invoke \
            --resource-group "rg-azfw-tls-lab-west" \
            --name "ca-server-vm" \
            --command-id RunPowerShellScript \
            --scripts "Get-Content 'C:\CloudShellCA\status.txt' -ErrorAction SilentlyContinue" \
            --query "value[0].message" -o tsv 2>/dev/null || echo "")
        
        if [[ "$status" == *"CLOUDSHELL_SUCCESS"* ]]; then
            echo ""
            echo "✅ Certificate Authority setup completed successfully!"
            return 0
        elif [[ "$status" == *"CLOUDSHELL_FAILED"* ]] || [[ "$status" == *"CLOUDSHELL_ERROR"* ]]; then
            echo ""
            echo "❌ Certificate Authority setup failed"
            return 1
        fi
        
        sleep 60  # Check every minute
        ((attempts++))
    done
    
    echo ""
    echo "⏰ CA setup is taking longer than expected"
    echo "💡 Check the VM status in Azure Portal or continue monitoring"
    return 1
}

# Cloud Shell certificate download with persistent storage
download_certificates_cloudshell() {
    echo ""
    echo "📥 Downloading certificates to Cloud Shell persistent storage..."
    
    # Download to Cloud Shell persistent storage
    local cert_dir="$HOME/clouddrive/azfw-tls-lab/certificates"
    mkdir -p "$cert_dir"
    
    # Download PFX certificate
    echo "📜 Downloading intermediate certificate..."
    az vm run-command invoke \
        --resource-group "rg-azfw-tls-lab-west" \
        --name "ca-server-vm" \
        --command-id RunPowerShellScript \
        --scripts "
            try {
                \$bytes = [IO.File]::ReadAllBytes('C:\CloudShellCA\intermediate.pfx')
                [Convert]::ToBase64String(\$bytes)
            } catch {
                'ERROR: Could not read certificate file'
            }
        " \
        --query "value[0].message" -o tsv | base64 -d > "$cert_dir/intermediate.pfx"
    
    # Download root certificate
    echo "🏛️ Downloading root certificate..."
    az vm run-command invoke \
        --resource-group "rg-azfw-tls-lab-west" \
        --name "ca-server-vm" \
        --command-id RunPowerShellScript \
        --scripts "
            try {
                \$bytes = [IO.File]::ReadAllBytes('C:\CloudShellCA\root.cer')
                [Convert]::ToBase64String(\$bytes)
            } catch {
                'ERROR: Could not read root certificate file'
            }
        " \
        --query "value[0].message" -o tsv | base64 -d > "$cert_dir/root.cer"
    
    if [[ -f "$cert_dir/intermediate.pfx" ]] && [[ -f "$cert_dir/root.cer" ]]; then
        echo "✅ Certificates downloaded to Cloud Shell persistent storage"
        echo "   📁 Location: $cert_dir"
        return 0
    else
        echo "❌ Certificate download failed"
        return 1
    fi
}

# Cloud Shell main execution
main() {
    echo "🌟 Starting Azure Firewall TLS Inspection Lab in Cloud Shell"
    echo ""
    
    # Step 1: Cloud Shell setup
    detect_cloudshell
    setup_cloudshell_env
    
    # Step 2: Authentication check
    if ! check_cloudshell_auth; then
        echo "❌ Authentication required. Please check your Cloud Shell session."
        exit 1
    fi
    
    # Step 3: Infrastructure check
    if ! check_infrastructure; then
        echo "💡 You may need to deploy the infrastructure first"
        echo "   Run the deployment scripts or check existing resources"
        echo ""
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Step 4: CA deployment
    if deploy_ca_with_cloudshell; then
        # Step 5: Certificate download
        if download_certificates_cloudshell; then
            echo ""
            echo "🎉 Cloud Shell quick setup completed successfully!"
            echo ""
            echo "📋 Next steps:"
            echo "  1. Upload certificates to Key Vault"
            echo "  2. Configure Azure Firewall policy"
            echo "  3. Test TLS inspection"
            echo ""
            echo "🚀 Run the full automation script:"
            echo "   ./scripts/cloudshell-full-automation.sh"
            echo ""
            echo "📊 Files saved to Cloud Shell persistent storage:"
            echo "   📁 $HOME/clouddrive/azfw-tls-lab/"
        fi
    fi
    
    # Cleanup
    rm -f ca-cloudshell-setup.ps1
}

# Run main function
main "$@"
