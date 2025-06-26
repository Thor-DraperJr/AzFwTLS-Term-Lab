// Virtual Network module for Azure Firewall TLS Lab
// Creates VNet with required subnets for firewall, servers, and optional bastion

@description('Location for the virtual network')
param location string

@description('Name of the virtual network')
param vnetName string

@description('Virtual network address prefix')
param vnetAddressPrefix string

@description('Azure Firewall subnet prefix')
param firewallSubnetPrefix string

@description('Server subnet prefix')
param serverSubnetPrefix string

@description('Bastion subnet prefix')
param bastionSubnetPrefix string

@description('Deploy bastion subnet')
param deployBastion bool

// Create Virtual Network
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    subnets: concat([
      // Azure Firewall Subnet (name must be exactly "AzureFirewallSubnet")
      {
        name: 'AzureFirewallSubnet'
        properties: {
          addressPrefix: firewallSubnetPrefix
          delegations: []
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      // Server Subnet for CA and client VMs
      {
        name: 'ServerSubnet'
        properties: {
          addressPrefix: serverSubnetPrefix
          delegations: []
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
    ], deployBastion ? [
      // Azure Bastion Subnet (name must be exactly "AzureBastionSubnet")
      {
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefix: bastionSubnetPrefix
          delegations: []
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
    ] : [])
  }
}

// Outputs
output vnetId string = virtualNetwork.id
output vnetName string = virtualNetwork.name
output firewallSubnetId string = virtualNetwork.properties.subnets[0].id
output serverSubnetId string = virtualNetwork.properties.subnets[1].id
output bastionSubnetId string = deployBastion ? virtualNetwork.properties.subnets[2].id : ''
