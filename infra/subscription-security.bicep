targetScope = 'subscription'

param principalId string

// The AI pricing resource is subscription-scoped; RG Reader cannot observe it.
resource securityReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, principalId, 'agentharness-defender-security-reader')
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '39bc4728-0917-49c7-9d2c-d95423bc2eb4')
  }
}
