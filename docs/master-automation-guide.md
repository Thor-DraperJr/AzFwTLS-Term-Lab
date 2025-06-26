# Azure Firewall TLS Inspection Lab - Master Automation Reference Guide

## Overview

The **Master Automation Script** (`scripts/master-automation.sh`) is the definitive, comprehensive automation solution for the Azure Firewall TLS Inspection Lab. This script provides complete end-to-end automation with advanced testing, monitoring, and reporting capabilities.

## Key Features

### 🎯 **Complete Automation**
- **End-to-end deployment**: Infrastructure → Configuration → Testing
- **Modular execution**: Run specific components independently
- **Error handling**: Robust error detection and recovery
- **Progress tracking**: Real-time operation tracking and reporting

### 📊 **Advanced Reporting**
- **HTML Status Reports**: Professional, detailed HTML reports
- **JSON Summaries**: Machine-readable execution summaries
- **Comprehensive Logging**: Detailed logs with timestamps
- **Success Metrics**: Pass/fail rates and execution statistics

### 🧪 **Comprehensive Testing**
- **Infrastructure validation**: All Azure resources
- **Certificate verification**: Key Vault and certificate chain
- **TLS inspection testing**: End-to-end TLS interception
- **Network connectivity**: Comprehensive network testing
- **Advanced test suite**: Integration with existing test scripts

### 📈 **Monitoring & Maintenance**
- **Status monitoring**: Continuous lab health monitoring
- **Resource discovery**: Automatic Azure resource detection
- **Configuration validation**: Ongoing configuration verification
- **Performance tracking**: Execution time and efficiency metrics

## Quick Start

### 🚀 **Complete Lab Setup (Recommended)**
```bash
# Deploy, configure, and test everything in one command
./scripts/master-automation.sh full
```

### 🏗️ **Infrastructure Only**
```bash
# Deploy just the Azure infrastructure
./scripts/master-automation.sh deploy
```

### ⚙️ **Configuration Only**
```bash
# Configure existing infrastructure (CA, certificates, TLS inspection)
./scripts/master-automation.sh configure
```

### 🧪 **Testing Only**
```bash
# Run comprehensive tests on existing lab
./scripts/master-automation.sh test
```

### 📊 **Status Check**
```bash
# Check current lab status
./scripts/master-automation.sh status
```

## Detailed Command Reference

### Commands

| Command | Description | Use Case |
|---------|-------------|----------|
| `full` | Complete end-to-end automation | New lab setup |
| `deploy` | Deploy infrastructure only | Initial deployment |
| `configure` | Configure existing resources | Post-deployment setup |
| `test` | Run comprehensive test suite | Validation and troubleshooting |
| `status` | Check lab status | Health monitoring |
| `monitor` | Continuous monitoring mode | Ongoing monitoring |
| `help` | Show help information | Reference |

### Options

| Option | Description | Example |
|--------|-------------|---------|
| `--debug` | Enable debug logging | `./master-automation.sh test --debug` |
| `--quiet` | Suppress non-essential output | `./master-automation.sh status --quiet` |
| `--force` | Skip confirmations | `./master-automation.sh deploy --force` |
| `--resource-group NAME` | Specify resource group | `./master-automation.sh test --resource-group my-rg` |
| `--report-only` | Generate reports without operations | `./master-automation.sh status --report-only` |

## Advanced Usage Scenarios

### 🔄 **CI/CD Integration**
```bash
# Automated deployment in CI/CD pipeline
./scripts/master-automation.sh full --force --quiet > /dev/null 2>&1
echo "Exit code: $?"
```

### 🔍 **Debugging and Troubleshooting**
```bash
# Enable maximum verbosity for troubleshooting
DEBUG=true ./scripts/master-automation.sh test --debug
```

### 📊 **Monitoring and Reporting**
```bash
# Generate status report without running operations
./scripts/master-automation.sh status --report-only

# Continuous monitoring for 1 hour
./scripts/master-automation.sh monitor
```

### 🎛️ **Environment Variables**
```bash
# Override resource group discovery
RESOURCE_GROUP="my-custom-rg" ./scripts/master-automation.sh test

# Skip interactive confirmations
SKIP_CONFIRMATIONS=true ./scripts/master-automation.sh deploy

# Enable debug mode
DEBUG=true ./scripts/master-automation.sh full
```

## Output and Reporting

### 📁 **Generated Files**

The script generates comprehensive output files in organized directories:

```
project-root/
├── logs/
│   └── master-automation-YYYYMMDD-HHMMSS.log
├── reports/
│   ├── lab-status-report-YYYYMMDD-HHMMSS.html
│   └── execution-summary.json
```

### 📋 **Report Contents**

#### **HTML Status Report**
- Executive summary with pass/fail metrics
- Detailed operation results
- Resource configuration details
- Execution timeline and performance data
- Professional styling for presentations

#### **JSON Summary**
- Machine-readable execution results
- Performance metrics and timing data
- Resource inventory
- Success/failure rates
- Integration-friendly format

#### **Detailed Logs**
- Timestamped operation logs
- Debug information (when enabled)
- Error messages and stack traces
- Command outputs and results

## Integration Points

### 🔗 **GitHub Actions Integration**
The master script is designed to work seamlessly with the existing CI/CD pipeline:

```yaml
# Example GitHub Actions step
- name: Deploy and Test Lab
  run: |
    ./scripts/master-automation.sh full --force
    echo "Exit code: $?"
```

### 🛠️ **Existing Script Integration**
The master script leverages all existing automation scripts:
- `deploy-lab.sh` - Infrastructure deployment
- `automate-tls-inspection.sh` - TLS configuration
- `remote-test-suite.sh` - Comprehensive testing
- `upload-certificates.sh` - Certificate management

### 🔌 **API Integration**
JSON output format enables easy integration with monitoring systems:

```bash
# Extract success rate for monitoring
SUCCESS_RATE=$(jq -r '.results.success_rate' reports/execution-summary.json)
echo "Lab success rate: ${SUCCESS_RATE}%"
```

## Error Handling and Recovery

### 🚨 **Exit Codes**
- `0`: All operations successful
- `1`: One or more operations failed
- `2`: Warnings detected (operations succeeded with issues)
- `130`: Script interrupted (Ctrl+C)

### 🔧 **Troubleshooting**

#### **Authentication Issues**
```bash
# Verify Azure login
az account show

# Re-authenticate if needed
az login
```

#### **Resource Discovery Issues**
```bash
# Manually specify resource group
./scripts/master-automation.sh test --resource-group "azfw-tls-rg"
```

#### **Permission Issues**
```bash
# Check script permissions
ls -la scripts/master-automation.sh

# Fix permissions if needed
chmod +x scripts/master-automation.sh
```

## Best Practices

### 🎯 **Execution Strategies**

#### **Development Environment**
```bash
# Full development cycle with debug output
DEBUG=true ./scripts/master-automation.sh full --debug
```

#### **Production Environment**
```bash
# Production deployment with minimal output
./scripts/master-automation.sh full --quiet --force
```

#### **Continuous Integration**
```bash
# CI/CD pipeline execution
./scripts/master-automation.sh deploy --force
./scripts/master-automation.sh test --quiet
```

### 📊 **Monitoring Recommendations**

#### **Regular Health Checks**
```bash
# Daily status check (cron job friendly)
./scripts/master-automation.sh status --quiet
```

#### **Performance Monitoring**
```bash
# Extract performance metrics
jq -r '.execution_summary.duration_formatted' reports/execution-summary.json
```

### 🔒 **Security Considerations**

- Always verify Azure authentication before running
- Use resource group scoping to limit impact
- Review generated reports before sharing
- Protect Key Vault access and certificate data

## Support and Maintenance

### 📚 **Documentation References**
- [Lab Setup Guide](../docs/lab-setup-guide.md)
- [Testing Guide](../docs/testing-guide.md)
- [Deployment Guide](../docs/deployment-guide.md)
- [Multi-Region Strategy](../docs/multi-region-strategy.md)

### 🔄 **Regular Maintenance**
```bash
# Weekly comprehensive test
./scripts/master-automation.sh test --debug > weekly-test.log 2>&1

# Monthly full validation
./scripts/master-automation.sh full --report-only
```

### 🆘 **Getting Help**
- Review execution logs in `logs/` directory
- Check HTML reports for detailed analysis
- Enable debug mode for troubleshooting
- Consult existing documentation and guides

## Version Information

- **Script Version**: 2.0.0
- **Compatibility**: Azure CLI 2.x, Bash 4.x+
- **Last Updated**: December 2024
- **Repository**: [AzFwTLS-Term-Lab](https://github.com/Thor-DraperJr/AzFwTLS-Term-Lab)

---

**Note**: This master automation script represents the culmination of all lab automation capabilities. It provides enterprise-grade functionality with comprehensive testing, monitoring, and reporting suitable for both development and production environments.
