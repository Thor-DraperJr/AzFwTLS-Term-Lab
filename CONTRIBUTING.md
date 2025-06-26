# Azure Firewall TLS Inspection Lab Contributing Guide

Thank you for your interest in contributing to the Azure Firewall TLS Inspection Lab! This project demonstrates AI-assisted Azure infrastructure deployment with enterprise-grade TLS inspection capabilities.

## 🚀 Quick Start

1. **Fork the repository**
2. **Clone your fork**: `git clone https://github.com/YOUR-USERNAME/AzFwTLS-Term-Lab.git`
3. **Create a feature branch**: `git checkout -b feature/your-feature-name`
4. **Make your changes**
5. **Test your changes** using the CI/CD pipeline
6. **Submit a pull request**

## 📋 Development Guidelines

### Bicep Templates
- Follow [Azure Bicep best practices](https://docs.microsoft.com/en-us/azure/azure-resource-manager/bicep/best-practices)
- Use consistent naming conventions
- Include proper parameter validation
- Add comments for complex logic
- Test templates with `az bicep build`

### Scripts
- Use `#!/bin/bash` for shell scripts
- Include error handling with `set -e`
- Add descriptive comments
- Make scripts executable: `chmod +x script.sh`
- Test scripts locally before committing

### Documentation
- Update README.md for significant changes
- Add/update docs in the `docs/` directory
- Use clear, concise language
- Include examples and screenshots where helpful

## 🔧 Local Development

### Prerequisites
- Azure CLI installed and configured
- PowerShell 7+ (for Windows scripts)
- Bicep CLI extension
- Git

### Setting Up Development Environment
```bash
# Clone the repository
git clone https://github.com/Thor-DraperJr/AzFwTLS-Term-Lab.git
cd AzFwTLS-Term-Lab

# Make scripts executable
chmod +x scripts/*.sh

# Validate Bicep templates
az bicep build --file bicep/main.bicep

# Run validation scripts
./scripts/validate-lab.sh
```

## 🧪 Testing

### Automated Testing
The CI/CD pipeline automatically runs:
- Bicep template validation
- Script syntax checking
- Security scanning
- Infrastructure deployment (on main branch)

### Manual Testing
1. **Local Validation**:
   ```bash
   # Validate Bicep templates
   az deployment group validate \
     --resource-group your-rg \
     --template-file bicep/main.bicep \
     --parameters bicep/parameters/lab.parameters.json
   ```

2. **Script Testing**:
   ```bash
   # Test script syntax
   bash -n scripts/your-script.sh
   
   # Test script execution (dry run)
   ./scripts/your-script.sh --dry-run
   ```

## 📝 Pull Request Process

### Before Submitting
- [ ] Code follows project conventions
- [ ] Bicep templates are validated
- [ ] Scripts are tested and executable
- [ ] Documentation is updated
- [ ] Commit messages are descriptive

### PR Requirements
- Clear title and description
- Reference any related issues
- Include testing steps
- Wait for CI/CD checks to pass
- Address review feedback promptly

### Review Process
1. **Automated Checks**: CI/CD pipeline validates changes
2. **Code Review**: Maintainers review code quality and functionality
3. **Testing**: Manual testing if needed
4. **Approval**: PR approved and merged

## 🔒 Security Guidelines

### Secrets Management
- **NEVER** commit secrets, passwords, or keys
- Use Azure Key Vault for secret storage
- Use GitHub secrets for CI/CD credentials
- Use `@secure()` decorator in Bicep for sensitive parameters

### Best Practices
- Follow principle of least privilege
- Use managed identities when possible
- Enable audit logging
- Regularly review access permissions

## 🏷️ Issue Guidelines

### Bug Reports
Include:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (Azure region, subscription type, etc.)
- Error messages and logs

### Feature Requests
Include:
- Clear description of the feature
- Use case and business value
- Proposed implementation approach
- Breaking change considerations

## 📚 Resources

### Azure Documentation
- [Azure Firewall Premium](https://docs.microsoft.com/en-us/azure/firewall/premium-features)
- [Azure Bicep](https://docs.microsoft.com/en-us/azure/azure-resource-manager/bicep/)
- [Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/)

### Project Documentation
- [Lab Setup Guide](docs/lab-setup-guide.md)
- [Deployment Guide](docs/deployment-guide.md)
- [Testing Guide](docs/testing-guide.md)
- [AI Integration Overview](docs/ai-integration-overview.md)

## 🤝 Community

### Getting Help
- Check existing [issues](https://github.com/Thor-DraperJr/AzFwTLS-Term-Lab/issues)
- Review [documentation](docs/)
- Ask questions in issue discussions

### Code of Conduct
- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow GitHub community guidelines

## 🙏 Recognition

Contributors will be recognized in:
- Project README
- Release notes
- GitHub contributors list

Thank you for contributing to the Azure Firewall TLS Inspection Lab! 🚀
