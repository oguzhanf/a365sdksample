targetScope = 'resourceGroup'

param location string
param configuration object

var deployGravitee = !(configuration.?harnessOnly ?? false)
var deployChat = !empty(configuration.model.name) && !(configuration.model.?deferDeployment ?? false)
var appServiceLocation = configuration.?appServiceLocation ?? location
var gatewayLocation = configuration.?gatewayLocation ?? location
var consoleAuthMode = configuration.?consoleAuthMode ?? 'password'
var approvedB2BGuestObjectIds = configuration.?approvedB2BGuestObjectIds ?? []
var approvedB2BGuestSettings = toObject(
  range(0, length(approvedB2BGuestObjectIds)),
  index => 'Harness__AllowedB2BGuestObjectIds__${index}',
  index => approvedB2BGuestObjectIds[index]
)
var approvedB2BGuestAdministratorObjectIds = configuration.?approvedB2BGuestAdministratorObjectIds ?? []
var approvedB2BGuestAdministratorSettings = toObject(
  range(0, length(approvedB2BGuestAdministratorObjectIds)),
  index => 'Harness__AllowedB2BGuestAdministratorObjectIds__${index}',
  index => approvedB2BGuestAdministratorObjectIds[index]
)
var suffix = uniqueString(subscription().id, resourceGroup().id)
var vaultName = 'ah-kv-${suffix}'
var storageName = 'ahstage${suffix}'
var openAiName = 'agentharness-ai-${suffix}'
var workspaceName = 'agentharness-logs-${suffix}'
var tags = {
  application: 'AgentHarness'
  environment: 'demo'
}
var vaultSecretsUser = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var vaultSecretsOfficer = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
var blobReader = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')
var blobContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
var defenderPricingId = subscriptionResourceId('Microsoft.Security/pricings', 'AI')

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: 1 }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'agentharness-insights-${suffix}'
  location: location
  kind: 'web'
  tags: tags
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: vaultName
  location: location
  tags: tags
  properties: {
    tenantId: configuration.tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'None'
    }
  }
}

resource operatorSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, configuration.deployerPrincipalId, 'secrets-officer')
  properties: {
    principalId: configuration.deployerPrincipalId
    principalType: 'User'
    roleDefinitionId: vaultSecretsOfficer
  }
}

resource appNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'agentharness-harness-vnet'
  location: appServiceLocation
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['10.79.0.0/24'] }
    subnets: [
      {
        name: 'app-integration'
        properties: {
          addressPrefix: '10.79.0.0/26'
          delegations: [{ name: 'web', properties: { serviceName: 'Microsoft.Web/serverFarms' } }]
        }
      }
      {
        name: 'private-endpoints'
        properties: { addressPrefix: '10.79.0.64/27', privateEndpointNetworkPolicies: 'Enabled' }
      }
    ]
  }
}

resource vaultDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
  tags: tags
}

resource vaultDnsAppLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: vaultDns
  name: 'agentharness-harness'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: appNetwork.id }
  }
}

resource vaultPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: 'agentharness-key-vault-private-endpoint'
  location: appServiceLocation
  tags: tags
  properties: {
    subnet: { id: '${appNetwork.id}/subnets/private-endpoints' }
    privateLinkServiceConnections: [
      {
        name: 'key-vault'
        properties: { privateLinkServiceId: vault.id, groupIds: ['vault'] }
      }
    ]
  }
}

resource vaultDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: vaultPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [{ name: 'vault', properties: { privateDnsZoneId: vaultDns.id } }]
  }
}

resource staging 'Microsoft.Storage/storageAccounts@2025-01-01' = if (deployGravitee) {
  name: storageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'None'
    }
  }
}

resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' = if (deployGravitee) {
  parent: staging
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 7 }
    containerDeleteRetentionPolicy: { enabled: true, days: 7 }
  }
}

resource artifacts 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = if (deployGravitee) {
  parent: blobs
  name: 'deployment'
  properties: { publicAccess: 'None' }
}

resource artifactLifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2025-01-01' = if (deployGravitee) {
  parent: staging
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'expire-deployment-bundles'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: { blobTypes: ['blockBlob'], prefixMatch: ['deployment/'] }
            actions: { baseBlob: { delete: { daysAfterModificationGreaterThan: 7 } } }
          }
        }
      ]
    }
  }
}

resource artifactUploader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployGravitee) {
  scope: artifacts
  name: guid(artifacts.id, configuration.deployerPrincipalId, 'upload')
  properties: {
    principalId: configuration.deployerPrincipalId
    principalType: 'User'
    roleDefinitionId: blobContributor
  }
}

resource openAi 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: openAiName
  location: location
  kind: 'OpenAI'
  tags: tags
  sku: { name: 'S0' }
  properties: {
    customSubDomainName: openAiName
    disableLocalAuth: true
    publicNetworkAccess: 'Enabled'
    networkAcls: { defaultAction: 'Allow' }
  }
}

resource chat 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = if (deployChat) {
  parent: openAi
  name: configuration.model.deployment
  sku: {
    name: configuration.model.sku
    capacity: configuration.model.capacity
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: configuration.model.name
      version: configuration.model.version
    }
    versionUpgradeOption: 'NoAutoUpgrade'
  }
}

resource computerUse 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = if (!empty(configuration.computerUseModel.name)) {
  parent: openAi
  name: configuration.computerUseModel.deployment
  sku: {
    name: configuration.computerUseModel.sku
    capacity: configuration.computerUseModel.capacity
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: configuration.computerUseModel.name
      version: configuration.computerUseModel.version
    }
    versionUpgradeOption: 'NoAutoUpgrade'
  }
}

resource plan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: 'agentharness-plan-${suffix}'
  location: appServiceLocation
  tags: tags
  kind: 'linux'
  sku: { name: 'B1', tier: 'Basic', capacity: 1 }
  properties: { reserved: true }
}

resource harness 'Microsoft.Web/sites@2024-11-01' = {
  name: configuration.harnessName
  location: appServiceLocation
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    clientAffinityEnabled: false
    virtualNetworkSubnetId: '${appNetwork.id}/subnets/app-integration'
    outboundVnetRouting: { allTraffic: true }
    siteConfig: {
      alwaysOn: true
      numberOfWorkers: 1
      linuxFxVersion: 'DOTNETCORE|9.0'
      appCommandLine: 'dotnet AgentHarness.dll'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
      healthCheckPath: '/healthz'
      remoteDebuggingEnabled: false
    }
  }
}

resource ftpAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-11-01' = {
  parent: harness
  name: 'ftp'
  properties: { allow: false }
}

resource scmAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-11-01' = {
  parent: harness
  name: 'scm'
  properties: { allow: false }
}

resource appSettings 'Microsoft.Web/sites/config@2024-11-01' = {
  parent: harness
  name: 'appsettings'
  properties: union({
    ASPNETCORE_ENVIRONMENT: 'Production'
    WEBSITE_RUN_FROM_PACKAGE: '1'
    WEBSITES_ENABLE_APP_SERVICE_STORAGE: 'true'
    SCM_DO_BUILD_DURING_DEPLOYMENT: 'false'
    Data__Path: '/home/data'
    AzureAd__Instance: 'https://login.microsoftonline.com/'
    AzureAd__TenantId: configuration.tenantId
    AzureAd__Domain: configuration.tenantDomain
    AzureAd__ClientId: configuration.harnessClientId
    AzureAd__ClientSecret: '@Microsoft.KeyVault(SecretUri=${vault.properties.vaultUri}secrets/harness-oidc-client-secret)'
    Harness__TenantId: configuration.tenantId
    Harness__TenantName: configuration.tenantName
    Harness__ClientId: configuration.harnessClientId
    Harness__ServicePrincipalId: configuration.harnessServicePrincipalId
    Harness__InternalApiClientId: configuration.internalApiClientId
    Harness__InternalApiServicePrincipalId: configuration.internalApiServicePrincipalId
    Harness__GraviteeClientId: configuration.graviteeClientId
    Harness__GraviteeServicePrincipalId: configuration.graviteeServicePrincipalId
    Harness__SubscriptionId: subscription().subscriptionId
    Harness__ResourceGroup: resourceGroup().name
    Harness__PublicUrl: 'https://${harness.properties.defaultHostName}'
    Harness__GraviteeUrl: deployGravitee ? 'https://${publicIp.properties.dnsSettings.fqdn}' : ''
    Harness__GraviteeStatus: deployGravitee ? 'Configured' : 'Pending'
    Harness__GraviteeConsoleAuthMode: consoleAuthMode
    Harness__KeyVaultUri: vault.properties.vaultUri
    Harness__OpenAiResourceId: openAi.id
    Harness__ManagedIdentityPrincipalId: harness.identity.principalId
    Harness__DefenderPricingResourceId: defenderPricingId
    AzureOpenAI__Endpoint: 'https://${openAiName}.openai.azure.com/'
    AzureOpenAI__Deployment: deployChat ? configuration.model.deployment : ''
    Harness__ModelStatus: deployChat ? 'Configured' : 'Pending'
    AzureOpenAI__ComputerUseDeployment: empty(configuration.computerUseModel.name) ? '' : configuration.computerUseModel.deployment
    APPLICATIONINSIGHTS_CONNECTION_STRING: insights.properties.ConnectionString
    Agent365__EnableExporter: 'false'
    AgentChannels__Enabled: 'false'
    Bootstrap__AdministratorObjectId: configuration.administratorObjectId
  }, approvedB2BGuestSettings, approvedB2BGuestAdministratorSettings)
}

resource harnessSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, harness.id, 'secrets-user')
  properties: {
    principalId: harness.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: vaultSecretsUser
  }
}

resource modelUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: openAi
  name: guid(openAi.id, harness.id, 'openai-user')
  properties: {
    principalId: harness.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd')
  }
}

resource harnessReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, harness.id, 'resource-reader')
  properties: {
    principalId: harness.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = if (deployGravitee) {
  name: 'agentharness-gravitee-nsg'
  location: gatewayLocation
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'public-http'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
        }
      }
      {
        name: 'public-https'
        properties: {
          priority: 110
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'deny-other-inbound'
        properties: {
          priority: 4096
          access: 'Deny'
          direction: 'Inbound'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource network 'Microsoft.Network/virtualNetworks@2024-05-01' = if (deployGravitee) {
  name: 'agentharness-gravitee-vnet'
  location: gatewayLocation
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['10.78.0.0/24'] }
    subnets: [
      {
        name: 'gravitee'
        properties: {
          addressPrefix: '10.78.0.0/27'
          networkSecurityGroup: { id: nsg.id }
          defaultOutboundAccess: false
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = if (deployGravitee) {
  name: 'agentharness-gravitee-public-ip'
  location: gatewayLocation
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    dnsSettings: { domainNameLabel: configuration.graviteeDnsLabel }
    idleTimeoutInMinutes: 10
  }
}

resource appToGateway 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = if (deployGravitee) {
  parent: appNetwork
  name: 'to-gravitee'
  properties: {
    remoteVirtualNetwork: { id: network.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: false
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

resource gatewayToApp 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = if (deployGravitee) {
  parent: network
  name: 'to-harness'
  properties: {
    remoteVirtualNetwork: { id: appNetwork.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: false
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

resource vaultDnsGatewayLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (deployGravitee) {
  parent: vaultDns
  name: 'agentharness-gravitee'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: network.id }
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = if (deployGravitee) {
  name: 'agentharness-gravitee-nic'
  location: gatewayLocation
  tags: tags
  properties: {
    enableAcceleratedNetworking: true
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: { id: '${network.id}/subnets/gravitee' }
          publicIPAddress: { id: publicIp.id }
        }
      }
    ]
  }
}

resource dataDisk 'Microsoft.Compute/disks@2024-03-02' = if (deployGravitee) {
  name: 'agentharness-gravitee-data'
  location: gatewayLocation
  tags: tags
  sku: { name: 'StandardSSD_LRS' }
  properties: {
    creationData: { createOption: 'Empty' }
    diskSizeGB: 128
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-11-01' = if (deployGravitee) {
  name: configuration.vmName
  location: gatewayLocation
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: configuration.vmSize }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: { secureBootEnabled: true, vTpmEnabled: true }
    }
    osProfile: {
      computerName: 'agentharness-gravitee'
      adminUsername: 'agentharnessadmin'
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: {
          publicKeys: [
            { path: '/home/agentharnessadmin/.ssh/authorized_keys', keyData: configuration.adminSshPublicKey }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        diskSizeGB: 64
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
        deleteOption: 'Delete'
      }
      dataDisks: [
        {
          name: dataDisk.name
          lun: 0
          createOption: 'Attach'
          managedDisk: { id: dataDisk.id }
          deleteOption: 'Detach'
          caching: 'None'
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [{ id: nic.id, properties: { primary: true } }]
    }
    diagnosticsProfile: { bootDiagnostics: { enabled: true } }
  }
}

resource vmSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployGravitee) {
  scope: vault
  name: guid(vault.id, vm.id, 'secrets-user')
  properties: {
    principalId: vm.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: vaultSecretsUser
  }
}

resource vmArtifacts 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployGravitee) {
  scope: artifacts
  name: guid(artifacts.id, vm.id, 'download')
  properties: {
    principalId: vm.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: blobReader
  }
}

resource aiDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: openAi
  name: 'agentharness-ai-audit'
  properties: {
    workspaceId: workspace.id
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

resource vaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: vault
  name: 'agentharness-key-vault-audit'
  properties: {
    workspaceId: workspace.id
    logs: [{ categoryGroup: 'audit', enabled: true }]
  }
}

output harnessPrincipalId string = harness.identity.principalId
output deployment object = {
  tenantId: configuration.tenantId
  tenantName: configuration.tenantName
  tenantDomain: configuration.tenantDomain
  administratorObjectId: configuration.administratorObjectId
  clientId: configuration.harnessClientId
  servicePrincipalId: configuration.harnessServicePrincipalId
  internalApiClientId: configuration.internalApiClientId
  internalApiServicePrincipalId: configuration.internalApiServicePrincipalId
  graviteeClientId: configuration.graviteeClientId
  graviteeServicePrincipalId: configuration.graviteeServicePrincipalId
  plannedHarnessUrl: configuration.plannedHarnessUrl
  plannedGraviteeUrl: configuration.plannedGraviteeUrl
  subscriptionId: subscription().subscriptionId
  resourceGroup: resourceGroup().name
  location: location
  appServiceLocation: appServiceLocation
  gatewayLocation: gatewayLocation
  consoleAuthMode: consoleAuthMode
  consoleSsoStatus: deployGravitee && consoleAuthMode == 'entra-oidc' ? 'Configured' : 'PendingOptional'
  harnessName: harness.name
  harnessResourceId: harness.id
  harnessPrincipalId: harness.identity.principalId
  harnessUrl: 'https://${harness.properties.defaultHostName}'
  appServicePlanResourceId: plan.id
  applicationInsightsResourceId: insights.id
  logAnalyticsResourceId: workspace.id
  components: deployGravitee ? 'Full' : 'HarnessOnly'
  graviteeStatus: deployGravitee ? 'Configured' : 'Pending'
  graviteeUrl: deployGravitee ? 'https://${publicIp.properties.dnsSettings.fqdn}' : ''
  vmName: deployGravitee ? vm.name : ''
  vmResourceId: deployGravitee ? vm.id : ''
  vmPrincipalId: deployGravitee ? vm.identity.principalId : ''
  gatewayNetworkSecurityGroupResourceId: deployGravitee ? nsg.id : ''
  keyVaultName: vault.name
  keyVaultResourceId: vault.id
  keyVaultUri: vault.properties.vaultUri
  keyVaultPrivateEndpointId: vaultPrivateEndpoint.id
  appNetworkResourceId: appNetwork.id
  storageAccountName: deployGravitee ? staging.name : ''
  artifactContainerUrl: deployGravitee ? '${staging.properties.primaryEndpoints.blob}deployment' : ''
  openAiResourceId: openAi.id
  openAiEndpoint: 'https://${openAiName}.openai.azure.com/'
  modelDeployment: deployChat ? configuration.model.deployment : ''
  modelStatus: deployChat ? 'Configured' : 'Pending'
  computerUseDeployment: empty(configuration.computerUseModel.name) ? '' : configuration.computerUseModel.deployment
  defenderPricingResourceId: defenderPricingId
  defenderPricingScope: 'subscription'
}
