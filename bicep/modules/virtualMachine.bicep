// Virtual Machine module for CA server and client VMs
// Creates Windows VMs with appropriate networking and security configurations

@description('Location for the VM')
param location string

@description('Name of the virtual machine')
param vmName string

@description('Size of the virtual machine')
param vmSize string

@description('Administrator username')
param adminUsername string

@description('Administrator password')
@secure()
param adminPassword string

@description('Subnet resource ID where VM will be deployed')
param subnetId string

@description('Purpose of the VM (ca-server or client)')
@allowed([
  'ca-server'
  'client'
])
param vmPurpose string

@description('Enable public IP for the VM')
param enablePublicIp bool = true

// Variables based on VM purpose
var vmConfig = vmPurpose == 'ca-server' ? {
  computerName: 'CA-SERVER'
  osDiskType: 'Premium_LRS'
  imageReference: {
    publisher: 'MicrosoftWindowsServer'
    offer: 'WindowsServer'
    sku: '2022-datacenter'
    version: 'latest'
  }
  nsgRules: [
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
    {
      name: 'HTTPS-CertSrv'
      properties: {
        protocol: 'Tcp'
        sourcePortRange: '*'
        destinationPortRange: '443'
        sourceAddressPrefix: '10.0.0.0/16'
        destinationAddressPrefix: '*'
        access: 'Allow'
        priority: 1002
        direction: 'Inbound'
      }
    }
  ]
} : {
  computerName: 'CLIENT-VM'
  osDiskType: 'StandardSSD_LRS'
  imageReference: {
    publisher: 'MicrosoftWindowsDesktop'
    offer: 'Windows-11'
    sku: 'win11-22h2-pro'
    version: 'latest'
  }
  nsgRules: [
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

// Create Network Security Group
resource networkSecurityGroup 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: '${vmName}-nsg'
  location: location
  properties: {
    securityRules: vmConfig.nsgRules
  }
}

// Create Public IP (if enabled)
resource publicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = if (enablePublicIp) {
  name: '${vmName}-pip'
  location: location
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: toLower('${vmName}-${uniqueString(resourceGroup().id)}')
    }
  }
}

// Create Network Interface
resource networkInterface 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnetId
          }
          publicIPAddress: enablePublicIp ? {
            id: publicIp.id
          } : null
        }
      }
    ]
    networkSecurityGroup: {
      id: networkSecurityGroup.id
    }
  }
}

// Create Virtual Machine
resource virtualMachine 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: vmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: vmConfig.computerName
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
        patchSettings: {
          patchMode: 'AutomaticByOS'
          assessmentMode: 'ImageDefault'
        }
      }
    }
    storageProfile: {
      imageReference: vmConfig.imageReference
      osDisk: {
        name: '${vmName}-osdisk'
        caching: 'ReadWrite'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: vmConfig.osDiskType
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterface.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: false
      }
    }
  }
}

// Install required features via PowerShell DSC (for CA server)
resource vmExtension 'Microsoft.Compute/virtualMachines/extensions@2023-07-01' = if (vmPurpose == 'ca-server') {
  parent: virtualMachine
  name: 'InstallADCS'
  properties: {
    publisher: 'Microsoft.Powershell'
    type: 'DSC'
    typeHandlerVersion: '2.77'
    autoUpgradeMinorVersion: true
    settings: {
      wmfVersion: 'latest'
      configuration: {
        url: 'https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/application-workloads/active-directory/active-directory-new-domain/DSC/CreateADPDC.zip'
        script: 'CreateADPDC.ps1'
        function: 'CreateADPDC'
      }
      configurationArguments: {
        DomainName: 'lab.local'
        DomainNetbiosName: 'LAB'
        SafeModeAdministratorPassword: {
          userName: 'Administrator'
          password: 'PrivateSettingsRef:AdminPassword'
        }
      }
    }
    protectedSettings: {
      configurationArguments: {
        AdminPassword: adminPassword
      }
    }
  }
}

// Outputs
output vmId string = virtualMachine.id
output vmName string = virtualMachine.name
output vmPublicIp string = enablePublicIp ? publicIp.properties.ipAddress : ''
output vmPrivateIp string = networkInterface.properties.ipConfigurations[0].properties.privateIPAddress
output vmFqdn string = enablePublicIp ? publicIp.properties.dnsSettings.fqdn : ''
