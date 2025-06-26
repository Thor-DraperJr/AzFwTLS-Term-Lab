// Main Bicep template for Azure Firewall TLS Inspection Lab
// This template deploys the complete infrastructure needed for testing TLS inspection

@description('Location for all resources')
param location string = resourceGroup().location

@description('Administrator username for VMs')
param adminUsername string

@description('Administrator password for VMs')
@secure()
param adminPassword string

@description('Virtual network address prefix')
param vnetAddressPrefix string = '10.0.0.0/16'

@description('Azure Firewall subnet prefix')
param firewallSubnetPrefix string = '10.0.0.0/26'

@description('Server subnet prefix (for CA and client VMs)')
param serverSubnetPrefix string = '10.0.1.0/24'

@description('Bastion subnet prefix (optional)')
param bastionSubnetPrefix string = '10.0.2.0/27'

@description('Deploy Azure Bastion for secure VM access')
param deployBastion bool = false

@description('VM size for the CA server')
param caVmSize string = 'Standard_D2s_v3'

@description('VM size for the client machine')
param clientVmSize string = 'Standard_B2s'

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
var bastionName = '${resourcePrefix}-bastion'
var bastionPublicIpName = '${resourcePrefix}-bastion-pip'

// Deploy Virtual Network with subnets
module virtualNetwork 'modules/virtualNetwork.bicep' = {
  name: 'deploy-vnet'
  params: {
    location: location
    vnetName: vnetName
    vnetAddressPrefix: vnetAddressPrefix
    firewallSubnetPrefix: firewallSubnetPrefix
    serverSubnetPrefix: serverSubnetPrefix
    bastionSubnetPrefix: bastionSubnetPrefix
    deployBastion: deployBastion
  }
}

// Deploy route table for server subnet
module routeTable 'modules/routeTable.bicep' = {
  name: 'deploy-route-table'
  params: {
    location: location
    routeTableName: routeTableName
    firewallPrivateIp: '10.0.0.4' // Standard first available IP in firewall subnet
  }
}

// Associate route table with server subnet
module routeTableAssociation 'modules/routeTableAssociation.bicep' = {
  name: 'associate-route-table'
  params: {
    vnetName: vnetName
    subnetName: 'ServerSubnet'
    routeTableId: routeTable.outputs.routeTableId
  }
  dependsOn: [
    virtualNetwork
    routeTable
  ]
}

// Deploy Azure Firewall Premium
module firewall 'modules/firewall.bicep' = {
  name: 'deploy-firewall'
  params: {
    location: location
    firewallName: firewallName
    firewallPolicyName: firewallPolicyName
    firewallPublicIpName: firewallPublicIpName
    vnetName: vnetName
    firewallSubnetId: virtualNetwork.outputs.firewallSubnetId
  }
  dependsOn: [
    virtualNetwork
  ]
}

// Deploy Key Vault for certificate storage
module keyVault 'modules/keyVault.bicep' = {
  name: 'deploy-keyvault'
  params: {
    location: location
    keyVaultName: keyVaultName
    firewallIdentityPrincipalId: firewall.outputs.firewallIdentityPrincipalId
  }
  dependsOn: [
    firewall
  ]
}

// Deploy CA Server VM
module caServer 'modules/virtualMachine.bicep' = {
  name: 'deploy-ca-server'
  params: {
    location: location
    vmName: caVmName
    vmSize: caVmSize
    adminUsername: adminUsername
    adminPassword: adminPassword
    subnetId: virtualNetwork.outputs.serverSubnetId
    vmPurpose: 'ca-server'
    enablePublicIp: !deployBastion
  }
  dependsOn: [
    virtualNetwork
  ]
}

// Deploy Client VM
module clientVm 'modules/virtualMachine.bicep' = {
  name: 'deploy-client-vm'
  params: {
    location: location
    vmName: clientVmName
    vmSize: clientVmSize
    adminUsername: adminUsername
    adminPassword: adminPassword
    subnetId: virtualNetwork.outputs.serverSubnetId
    vmPurpose: 'client'
    enablePublicIp: !deployBastion
  }
  dependsOn: [
    virtualNetwork
  ]
}

// Deploy Azure Bastion (optional)
module bastion 'modules/bastion.bicep' = if (deployBastion) {
  name: 'deploy-bastion'
  params: {
    location: location
    bastionName: bastionName
    bastionPublicIpName: bastionPublicIpName
    bastionSubnetId: virtualNetwork.outputs.bastionSubnetId
  }
  dependsOn: [
    virtualNetwork
  ]
}

// Outputs
output resourceGroupName string = resourceGroup().name
output vnetName string = vnetName
output firewallName string = firewallName
output firewallPublicIp string = firewall.outputs.firewallPublicIp
output firewallPrivateIp string = firewall.outputs.firewallPrivateIp
output keyVaultName string = keyVaultName
output keyVaultUri string = keyVault.outputs.keyVaultUri
output caServerName string = caVmName
output clientVmName string = clientVmName
output caServerPublicIp string = deployBastion ? '' : caServer.outputs.vmPublicIp
output clientVmPublicIp string = deployBastion ? '' : clientVm.outputs.vmPublicIp
output bastionName string = deployBastion ? bastionName : ''
