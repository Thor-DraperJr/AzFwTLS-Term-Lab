// Key Vault module for storing TLS inspection certificates
// Creates Key Vault with appropriate access policies for Azure Firewall

@description('Location for Key Vault')
param location string

@description('Name of the Key Vault')
param keyVaultName string

@description('Principal ID of the Azure Firewall managed identity')
param firewallIdentityPrincipalId string

// Get current user/service principal for Key Vault access
var currentUserId = 'PLACEHOLDER_USER_ID' // Will be replaced with actual user ID during deployment

// Create Key Vault
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
    enabledForDiskEncryption: false
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: false
    enableRbacAuthorization: false
    accessPolicies: [
      // Access policy for Azure Firewall managed identity
      {
        tenantId: tenant().tenantId
        objectId: firewallIdentityPrincipalId
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
      // Access policy for deployment user (placeholder - will need to be updated)
      {
        tenantId: tenant().tenantId
        objectId: currentUserId
        permissions: {
          certificates: [
            'all'
          ]
          secrets: [
            'all'
          ]
          keys: [
            'all'
          ]
        }
      }
    ]
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// Outputs
output keyVaultId string = keyVault.id
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
