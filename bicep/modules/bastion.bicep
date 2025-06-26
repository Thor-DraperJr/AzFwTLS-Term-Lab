// Azure Bastion module for secure VM access
// Creates Azure Bastion for secure RDP/SSH access without public IPs

@description('Location for Azure Bastion')
param location string

@description('Name of the Azure Bastion')
param bastionName string

@description('Name of the public IP for Bastion')
param bastionPublicIpName string

@description('Bastion subnet resource ID')
param bastionSubnetId string

// Create public IP for Azure Bastion
resource bastionPublicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: bastionPublicIpName
  location: location
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: toLower('${bastionName}-${uniqueString(resourceGroup().id)}')
    }
  }
}

// Create Azure Bastion
resource azureBastion 'Microsoft.Network/bastionHosts@2023-05-01' = {
  name: bastionName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    ipConfigurations: [
      {
        name: 'IpConf'
        properties: {
          publicIPAddress: {
            id: bastionPublicIp.id
          }
          subnet: {
            id: bastionSubnetId
          }
        }
      }
    ]
  }
}

// Outputs
output bastionId string = azureBastion.id
output bastionName string = azureBastion.name
output bastionFqdn string = bastionPublicIp.properties.dnsSettings.fqdn
