// Azure Firewall Premium module
// Deploys Azure Firewall Premium with policy for TLS inspection

@description('Location for the firewall')
param location string

@description('Name of the Azure Firewall')
param firewallName string

@description('Name of the Firewall Policy')
param firewallPolicyName string

@description('Name of the public IP for the firewall')
param firewallPublicIpName string

@description('Virtual network name')
param vnetName string

@description('Firewall subnet resource ID')
param firewallSubnetId string

// Create public IP for Azure Firewall
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
    dnsSettings: {
      domainNameLabel: toLower('${firewallName}-${uniqueString(resourceGroup().id)}')
    }
  }
}

// Create Firewall Policy (Premium tier for TLS inspection)
resource firewallPolicy 'Microsoft.Network/firewallPolicies@2023-05-01' = {
  name: firewallPolicyName
  location: location
  properties: {
    sku: {
      tier: 'Premium'
    }
    threatIntelMode: 'Alert'
    intrusionDetection: {
      mode: 'Alert'
    }
    dnsSettings: {
      servers: []
      enableProxy: true
    }
    // TLS inspection will be configured after certificate is available
    transportSecurity: {
      certificateAuthority: {
        // Will be populated with Key Vault reference after certificate upload
        keyVaultSecretId: ''
        name: 'TLSInspectionCA'
      }
    }
  }
}

// Create Azure Firewall Premium
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
            id: firewallSubnetId
          }
        }
      }
    ]
    firewallPolicy: {
      id: firewallPolicy.id
    }
    // Enable system-assigned managed identity for Key Vault access
    // This will be created automatically when needed
  }
  identity: {
    type: 'SystemAssigned'
  }
}

// Create basic network rules for lab testing
resource networkRuleCollection 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2023-05-01' = {
  parent: firewallPolicy
  name: 'DefaultNetworkRuleCollectionGroup'
  properties: {
    priority: 200
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'NetworkRuleCollection'
        priority: 1000
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'AllowDNS'
            ipProtocols: [
              'UDP'
            ]
            sourceAddresses: [
              '10.0.1.0/24'
            ]
            destinationAddresses: [
              '*'
            ]
            destinationPorts: [
              '53'
            ]
          }
        ]
      }
    ]
  }
}

// Create application rules for web traffic with TLS inspection
resource applicationRuleCollection 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2023-05-01' = {
  parent: firewallPolicy
  name: 'DefaultApplicationRuleCollectionGroup'
  properties: {
    priority: 300
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'ApplicationRuleCollection'
        priority: 1000
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'ApplicationRule'
            name: 'AllowWeb'
            protocols: [
              {
                protocolType: 'Http'
                port: 80
              }
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            sourceAddresses: [
              '10.0.1.0/24'
            ]
            targetFqdns: [
              '*'
            ]
            // TLS inspection will be enabled after certificate configuration
            // terminateTLS: true
          }
        ]
      }
    ]
  }
  dependsOn: [
    networkRuleCollection
  ]
}

// Outputs
output firewallId string = azureFirewall.id
output firewallName string = azureFirewall.name
output firewallPublicIp string = firewallPublicIp.properties.ipAddress
output firewallPrivateIp string = azureFirewall.properties.ipConfigurations[0].properties.privateIPAddress
output firewallPolicyId string = firewallPolicy.id
output firewallPolicyName string = firewallPolicy.name
output firewallIdentityPrincipalId string = azureFirewall.identity.principalId
