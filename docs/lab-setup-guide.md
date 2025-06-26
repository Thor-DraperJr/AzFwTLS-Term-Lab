# Lab Setup: Azure Firewall TLS Inspection with Enterprise CA

Enabling TLS inspection on Azure Firewall Premium requires a Public Key Infrastructure (PKI) environment and careful configuration. This lab will guide you through building a **test environment** with all the necessary Azure and on-premises resources to simulate a production setup, including an **Enterprise CA** for issuing the intermediate certificate needed by Azure Firewall.

## Lab Environment Components and Architecture

In this lab, you will set up a **hybrid environment** with an on-premises-style CA and Azure networking resources:

- **Active Directory & Certificate Authority**: A Windows Server acting as an **Enterprise Root CA** (using AD CS). This will be configured in a new Active Directory forest for simplicity. The CA server will issue an **Intermediate (subordinate) CA certificate** specifically for Azure Firewall's TLS inspection.

- **Azure Virtual Network (VNet)**: A virtual network to host both the Azure Firewall and the VMs (CA server and client). Within this VNet:
  - An **AzureFirewallSubnet** (at least /26) will contain the Azure Firewall instance.
  - A **Server subnet** (e.g. /27 or /24 as needed) will host the CA server and client VM.
  - (Optional) If using Azure Bastion or jumpbox, a small **management subnet** for that service can be added.

- **Azure Firewall Premium**: Deployed to the AzureFirewallSubnet with a **Firewall Policy (Premium)** attached. The Firewall Policy is where TLS inspection is configured. Azure Firewall Premium is required for TLS inspection capabilities.

- **Azure Key Vault**: Used to **import and store the intermediate certificate** (in .pfx format) and its private key. Azure Firewall will fetch the certificate from Key Vault during TLS inspection. A **Managed Identity** (system-assigned or user-assigned) will be used by the firewall to access Key Vault.

- **Test Client VM**: A Windows 10/11 (or Linux) VM in the VNet, representative of an end-user machine. Ideally, domain-joined to the AD so that it automatically **trusts the Root CA** certificate via Active Directory group policy.

- **Network Routing**: To ensure the client VM's outbound web traffic flows through the Azure Firewall, configure a **User-Defined Route (UDR)** on the client subnet. This route should send `0.0.0.0/0` traffic to the Firewall's private IP.

## Step-by-Step Lab Deployment

### 1. Create an Azure Resource Group
Begin by creating a new resource group to contain all Azure resources for this lab:

```azurecli
az group create -n RG-FW-Lab -l eastus
```

### 2. Set Up the Virtual Network and Subnets
Deploy a VNet with the subnets for Firewall and VMs:

```azurecli
az network vnet create -g RG-FW-Lab -n VNet-FW-Lab --address-prefixes 10.0.0.0/16 \
    --subnet-name AzureFirewallSubnet --subnet-prefix 10.0.0.0/26
az network vnet subnet create -g RG-FW-Lab --vnet-name VNet-FW-Lab \
    -n ServerSubnet --address-prefixes 10.0.1.0/24
```

### 3. Deploy the Azure Firewall Premium
Deploy the firewall into the AzureFirewallSubnet:

```azurecli
az network firewall policy create -g RG-FW-Lab -n FW-Lab-Policy --tier Premium
az network public-ip create -g RG-FW-Lab -n FW-Lab-PIP --sku Standard
az network firewall create -g RG-FW-Lab -n AzureFirewallLab --policy-name FW-Lab-Policy \
    --vnet-name VNet-FW-Lab --public-ip-address FW-Lab-PIP
```

### 4. Set Up Routing
Create a route table to direct outbound traffic from the ServerSubnet to the firewall:

```azurecli
az network route-table create -g RG-FW-Lab -n FW-Lab-RT
az network route-table route create -g RG-FW-Lab --route-table-name FW-Lab-RT -n DefaultRoute \
    --address-prefix 0.0.0.0/0 --next-hop-type VirtualAppliance --next-hop-ip-address 10.0.0.4
az network vnet subnet update -g RG-FW-Lab -n ServerSubnet --vnet-name VNet-FW-Lab \
    --route-table FW-Lab-RT
```

### 5. Provision the Windows Server (Domain Controller + CA)
Create a Windows Server VM that will serve as our Enterprise Root CA:

- Deploy the VM into the **ServerSubnet**
- Install Active Directory Domain Services
- Promote the server to a Domain Controller
- Install Active Directory Certificate Services (AD CS)
- Set up the CA as an **Enterprise Root CA**

### 6. Prepare a Subordinate CA Certificate for Azure Firewall
This is the most critical part: obtaining a certificate that Azure Firewall will use for TLS inspection:

- Create a certificate template for Subordinate CA
- Request the certificate via Web Enrollment
- Export the certificate in the correct format (PFX without password, without chain)

### 7. Create Azure Key Vault and Import Certificate
Set up a Key Vault to hold the certificate and configure access for the firewall.

### 8. Configure Azure Firewall TLS Inspection
Enable TLS inspection on the firewall using the certificate from Key Vault.

### 9. Deploy the Test Client VM
Set up a client machine to generate traffic and test the TLS inspection.

### 10. Create a Test Application Rule
In the Firewall Policy, create a rule to allow outbound web traffic with TLS inspection enabled.

### 11. Test TLS Inspection Functionality
Verify that everything is working by generating HTTPS traffic from the client.

## AI Integration Points

Throughout this lab, AI tools can assist with:

- **Bicep Template Generation**: Use GitHub Copilot to generate infrastructure-as-code templates
- **Certificate Script Creation**: AI can generate PowerShell or OpenSSL scripts for certificate management
- **Troubleshooting**: AI can help diagnose issues and suggest solutions
- **Automation**: AI can help create end-to-end automation scripts

## Security Considerations

⚠️ **This is a lab environment** - Do not use in production without proper security review and hardening.

- Use strong passwords for all VMs
- Implement proper network security groups
- Follow principle of least privilege for Key Vault access
- Regularly rotate certificates in production environments
