// Simplified deployment for VMs in West US 2 backup region
param adminUsername string = 'azureadmin'
@secure()
param adminPassword string

// Create a simple VNet for VMs in West US 2
resource westVnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: 'azfw-tls-lab-west-vnet'
  location: 'westus2'
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.1.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'ca-subnet'
        properties: {
          addressPrefix: '10.1.1.0/24'
        }
      }
      {
        name: 'client-subnet'
        properties: {
          addressPrefix: '10.1.2.0/24'
        }
      }
    ]
  }
}

// Network Security Group for VMs
resource vmNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'azfw-tls-lab-west-nsg'
  location: 'westus2'
  properties: {
    securityRules: [
      {
        name: 'AllowRDP'
        properties: {
          priority: 1000
          access: 'Allow'
          direction: 'Inbound'
          destinationPortRange: '3389'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'AllowHTTPS'
        properties: {
          priority: 1001
          access: 'Allow'
          direction: 'Inbound'
          destinationPortRange: '443'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

// Public IP for CA Server
resource caPublicIP 'Microsoft.Network/publicIPAddresses@2023-09-01' = {
  name: 'ca-server-pip'
  location: 'westus2'
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
  sku: {
    name: 'Standard'
  }
}

// Public IP for Client VM
resource clientPublicIP 'Microsoft.Network/publicIPAddresses@2023-09-01' = {
  name: 'client-vm-pip'
  location: 'westus2'
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
  sku: {
    name: 'Standard'
  }
}

// Network Interface for CA Server
resource caNetworkInterface 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: 'ca-server-nic'
  location: 'westus2'
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: westVnet.properties.subnets[0].id
          }
          publicIPAddress: {
            id: caPublicIP.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: vmNsg.id
    }
  }
}

// Network Interface for Client VM
resource clientNetworkInterface 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: 'client-vm-nic'
  location: 'westus2'
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: westVnet.properties.subnets[1].id
          }
          publicIPAddress: {
            id: clientPublicIP.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: vmNsg.id
    }
  }
}

// CA Server Virtual Machine
resource caServerVM 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: 'ca-server-vm'
  location: 'westus2'
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    osProfile: {
      computerName: 'ca-server'
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
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: caNetworkInterface.id
        }
      ]
    }
  }
}

// Client Virtual Machine
resource clientVM 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: 'client-vm'
  location: 'westus2'
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    osProfile: {
      computerName: 'client-vm'
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
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: clientNetworkInterface.id
        }
      ]
    }
  }
}

// Output the public IP addresses for connection
output caServerPublicIP string = caPublicIP.properties.ipAddress
output clientVMPublicIP string = clientPublicIP.properties.ipAddress
output caServerPrivateIP string = caNetworkInterface.properties.ipConfigurations[0].properties.privateIPAddress
output clientVMPrivateIP string = clientNetworkInterface.properties.ipConfigurations[0].properties.privateIPAddress
