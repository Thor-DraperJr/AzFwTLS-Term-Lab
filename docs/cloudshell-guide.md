# Azure Firewall TLS Inspection Lab - Cloud Shell Setup

## 🌐 Running from Azure Cloud Shell

This lab is **perfectly suited for Azure Cloud Shell** - no local setup required!

### ✅ Cloud Shell Advantages

- **🔐 Pre-authenticated**: Already connected to your Azure subscription
- **📦 Tools included**: Azure CLI, PowerShell, Git, and more pre-installed
- **🌍 Browser-based**: Access from anywhere with internet
- **🔄 Persistent storage**: Your files persist across sessions
- **🚀 No setup required**: Ready to run immediately

### 🚀 Quick Start in Cloud Shell

#### Step 1: Open Azure Cloud Shell
1. Go to [shell.azure.com](https://shell.azure.com) or click the Cloud Shell icon in Azure Portal
2. Choose **Bash** or **PowerShell** (Bash recommended for this lab)

#### Step 2: Clone the Lab Repository
```bash
# Clone the lab to Cloud Shell
git clone https://github.com/your-repo/AzFwTLS-Term-Lab.git
cd AzFwTLS-Term-Lab

# Or if you have the files locally, upload them to Cloud Shell
# Use the upload feature in Cloud Shell to transfer files
```

#### Step 3: Run Automated Setup
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Option 1: Quick automated setup (Recommended)
./scripts/cloudshell-quick-setup.sh

# Option 2: Full automation with detailed testing
./scripts/cloudshell-full-automation.sh

# Option 3: Manual guided setup
./scripts/start-testing.sh
```

## 🎯 Cloud Shell Specific Features

### Enhanced Automation
- **Persistent sessions**: Scripts can run for extended periods
- **File storage**: Certificates and logs persist in Cloud Shell storage
- **Direct Azure integration**: No authentication setup needed

### Monitoring and Management
```bash
# Monitor deployment status
./scripts/monitor-deployment.sh

# Check Cloud Shell environment
./scripts/check-cloudshell-env.sh

# View lab status dashboard
./scripts/lab-dashboard.sh
```

### Cloud Shell vs Local Setup

| Feature | Local Setup | Cloud Shell |
|---------|-------------|-------------|
| Azure CLI | Manual install | ✅ Pre-installed |
| Authentication | `az login` required | ✅ Auto-authenticated |
| PowerShell | Manual install | ✅ Available |
| File Persistence | Local only | ✅ Cloud storage |
| Access | Single machine | ✅ Any browser |
| Updates | Manual | ✅ Always current |

## 🔧 Cloud Shell Optimizations

The lab scripts are optimized for Cloud Shell with:
- **Automatic authentication detection**
- **Cloud storage integration**
- **Progress indicators for long-running operations**
- **Session persistence handling**
- **Browser-friendly output formatting**

## 🚀 Get Started Now

Open [Azure Cloud Shell](https://shell.azure.com) and run:

```bash
# Quick start - everything automated
curl -sSL https://raw.githubusercontent.com/your-repo/AzFwTLS-Term-Lab/main/scripts/cloudshell-bootstrap.sh | bash
```

This will download the lab, set permissions, and start the automated setup process!
