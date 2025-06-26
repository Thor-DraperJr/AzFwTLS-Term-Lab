// Simplified Azure Firewall TLS Inspection Lab Template
// This template deploys the core infrastructure in a single file for MCP deployment

@description('Location for all resources')
param location string = resourceGroup().location

@description('Administrator username for VMs')
param adminUsername string = 'azureadmin'

@description('Administrator password for VMs')
@secure()
param adminPassword string = 'AzureFirewall@TLS2025!'

// Variables
var resourcePrefix = 'azfw-tls-lab'
var vnetName = '${resourcePrefix}-vnet'
var firewallName = '${resourcePrefix}-firewall'
var firewallPolicyName = '${resourcePrefix}-policy'
var firewallPublicIpName = '${resourcePrefix}-fw-pip'
var keyVaultName = '${resourcePrefix}-kv-${uniqueString(resourceGroup().id)}'
var routeTableName = '${resourcePrefix}-rt'
var caVmName = '${resourcePrefix}-ca-vm'
var clientVmName = '${resourcePrefix}-client-vm'

// Virtual Network
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'AzureFirewallSubnet'
        properties: {
          addressPrefix: '10.0.0.0/26'
        }
      }
      {
        name: 'ServerSubnet'
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
    ]
  }
}

// Public IP for Azure Firewall
resource firewallPublicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: firewallPublicIpName
  location: location
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

// Firewall Policy
resource firewallPolicy 'Microsoft.Network/firewallPolicies@2023-05-01' = {
  name: firewallPolicyName
  location: location
  properties: {
    sku: {
      tier: 'Premium'
    }
    threatIntelMode: 'Alert'
  }
}

// Azure Firewall
resource azureFirewall 'Microsoft.Network/azureFirewalls@2023-05-01' = {
  name: firewallName
  location: location
  properties: {
    sku: {
      name: 'AZFW_VNet'
      tier: 'Premium'
    }
    ipConfigurations: [
      {
        name: 'IpConf'
        properties: {
          publicIPAddress: {
            id: firewallPublicIp.id
          }
          subnet: {
            id: '${virtualNetwork.id}/subnets/AzureFirewallSubnet'
          }
        }
      }
    ]
    firewallPolicy: {
      id: firewallPolicy.id
    }
  }
  identity: {
    type: 'SystemAssigned'
  }
}

// Route Table
resource routeTable 'Microsoft.Network/routeTables@2023-05-01' = {
  name: routeTableName
  location: location
  properties: {
    routes: [
      {
        name: 'DefaultRoute'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: azureFirewall.properties.ipConfigurations[0].properties.privateIPAddress
        }
      }
    ]
  }
}

// Key Vault
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: tenant().tenantId
    enabledForDeployment: true
    enabledForTemplateDeployment: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    accessPolicies: [
      {
        tenantId: tenant().tenantId
        objectId: azureFirewall.identity.principalId
        permissions: {
          certificates: [
            'get'
            'list'
          ]
          secrets: [
            'get'
            'list'
          ]
        }
      }
    ]
  }
}

// Network Security Group for CA Server
resource caServerNsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: '${caVmName}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'RDP'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3389'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1000
          direction: 'Inbound'
        }
      }
      {
        name: 'HTTP-CertSrv'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '80'
          sourceAddressPrefix: '10.0.0.0/16'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1001
          direction: 'Inbound'
        }
      }
    ]
  }
}

// Public IP for CA Server
resource caServerPublicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: '${caVmName}-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// Network Interface for CA Server
resource caServerNic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: '${caVmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: '${virtualNetwork.id}/subnets/ServerSubnet'
          }
          publicIPAddress: {
            id: caServerPublicIp.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: caServerNsg.id
    }
  }
}

// CA Server VM
resource caServerVm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: caVmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    osProfile: {
      computerName: 'CA-SERVER'
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter'
        version: 'latest'
      }
      osDisk: {
        name: '${caVmName}-osdisk'
        caching: 'ReadWrite'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: caServerNic.id
        }
      ]
    }
  }
}

// Network Security Group for Client
resource clientNsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: '${clientVmName}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'RDP'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3389'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1000
          direction: 'Inbound'
        }
      }
    ]
  }
}

// Public IP for Client VM
resource clientPublicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: '${clientVmName}-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// Network Interface for Client VM
resource clientNic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: '${clientVmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: '${virtualNetwork.id}/subnets/ServerSubnet'
          }
          publicIPAddress: {
            id: clientPublicIp.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: clientNsg.id
    }
  }
}

// Client VM
resource clientVm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: clientVmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2s'
    }
    osProfile: {
      computerName: 'CLIENT-VM'
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsDesktop'
        offer: 'Windows-11'
        sku: 'win11-22h2-pro'
        version: 'latest'
      }
      osDisk: {
        name: '${clientVmName}-osdisk'
        caching: 'ReadWrite'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: clientNic.id
        }
      ]
    }
  }
}

// Associate route table with server subnet
resource subnetRouteTableAssociation 'Microsoft.Network/virtualNetworks/subnets@2023-05-01' = {
  parent: virtualNetwork
  name: 'ServerSubnet'
  properties: {
    addressPrefix: '10.0.1.0/24'
    routeTable: {
      id: routeTable.id
    }
  }
  dependsOn: [
    caServerNic
    clientNic
  ]
}

// Outputs
output resourceGroupName string = resourceGroup().name
output firewallPublicIp string = firewallPublicIp.properties.ipAddress
output firewallPrivateIp string = azureFirewall.properties.ipConfigurations[0].properties.privateIPAddress
output keyVaultName string = keyVault.name
output caServerPublicIp string = caServerPublicIp.properties.ipAddress
output clientPublicIp string = clientPublicIp.properties.ipAddress
output firewallIdentityPrincipalId string = azureFirewall.identity.principalId
