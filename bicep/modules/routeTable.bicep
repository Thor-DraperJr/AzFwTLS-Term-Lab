// Route Table module for forcing traffic through Azure Firewall
// Creates UDR to send all internet traffic (0.0.0.0/0) to the firewall

@description('Location for the route table')
param location string

@description('Name of the route table')
param routeTableName string

@description('Private IP address of the Azure Firewall')
param firewallPrivateIp string

// Create Route Table
resource routeTable 'Microsoft.Network/routeTables@2023-05-01' = {
  name: routeTableName
  location: location
  properties: {
    disableBgpRoutePropagation: false
    routes: [
      {
        name: 'DefaultRoute'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: firewallPrivateIp
        }
      }
    ]
  }
}

// Outputs
output routeTableId string = routeTable.id
output routeTableName string = routeTable.name
