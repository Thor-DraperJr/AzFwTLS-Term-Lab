// Route Table Association module
// Associates a route table with a subnet

@description('Virtual network name')
param vnetName string

@description('Subnet name to associate with route table')
param subnetName string

@description('Resource ID of the route table')
param routeTableId string

// Reference existing VNet
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-05-01' existing = {
  name: vnetName
}

// Update subnet to associate with route table
resource subnetUpdate 'Microsoft.Network/virtualNetworks/subnets@2023-05-01' = {
  parent: virtualNetwork
  name: subnetName
  properties: {
    addressPrefix: virtualNetwork.properties.subnets[1].properties.addressPrefix
    routeTable: {
      id: routeTableId
    }
    delegations: []
    privateEndpointNetworkPolicies: 'Disabled'
    privateLinkServiceNetworkPolicies: 'Enabled'
  }
}
