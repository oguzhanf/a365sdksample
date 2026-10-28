#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [ValidateSet('Validate','Models','Plan','Apply')][string]$Mode = 'Validate',
    [switch]$HarnessOnly,
    [ValidatePattern('^[a-z0-9]+$')][string]$Location = 'eastus',
    [ValidatePattern('^[a-z0-9]*$')][string]$AppServiceLocation = '',
    [ValidatePattern('^[a-z0-9]*$')][string]$GatewayLocation = '',
    [switch]$SkipHarnessPublish,
    [switch]$CreateNewInfrastructure,
    [ValidateSet('password','entra-oidc')][string]$ConsoleAuthMode = 'password',
    [string]$ModelName,
    [string]$ModelVersion,
    [ValidatePattern('^[A-Za-z0-9-]+$')][string]$ModelSku = 'GlobalStandard',
    [ValidateRange(1,1000)][int]$ModelCapacity = 10,
    [ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$ModelDeployment = 'agentharness-chat',
    [string]$ComputerUseModelName = '',
    [string]$ComputerUseModelVersion = '',
    [string]$ComputerUseDeployment = 'agentharness-computer-use',
    [string]$ResourceGroupName,
    [string]$HarnessName,
    [string]$GraviteeDnsLabel,
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}[a-zA-Z0-9]$')][string]$VmName = 'agentharness-gravitee',
    [string]$VmSize = 'Standard_D4s_v5',
    [string]$AcmeEmail,
    [string]$AdminSshPublicKeyPath,
    [string]$GraviteeLicensePath,
    [switch]$UseStoredGraviteeLicense,
    [switch]$AcknowledgeSubscriptionDefenderAI,
    [string]$EntraStatePath = (Join-Path $PSScriptRoot 'entra-state.json'),
    [string]$AgentCatalogPath,
    [string]$OutputPath = 'artifacts\deployment-state.json'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
Set-Location $root
. (Join-Path $PSScriptRoot 'Deployment.Common.ps1')

if ($Mode -eq 'Validate') {
    & (Join-Path $PSScriptRoot 'Validate.ps1')
    return
}
if (!(Test-Path -LiteralPath $EntraStatePath -PathType Leaf)) { throw 'Run Initialize-Entra.ps1 with customer configuration before accessing Azure.' }
$entra = Get-Content -LiteralPath $EntraStatePath -Raw | ConvertFrom-Json
if ((Get-OptionalProperty $entra 'SubscriptionId') -ne $SubscriptionId) { throw 'The explicit subscription does not match the initialized customer configuration.' }
$account = Initialize-CachedAzureSession -TenantId $entra.TenantId -SubscriptionId $SubscriptionId `
    -AdministratorObjectId $entra.AdministratorObjectId -AdministratorUpn $entra.AdministratorUpn
$OutputPath = Assert-LocalStatePath -Path $OutputPath
$existing = if (Test-Path -LiteralPath $OutputPath -PathType Leaf) { Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json } else { $null }
if (!$ResourceGroupName) { $ResourceGroupName = if ($existing) { $existing.resourceGroup } else { 'rg-agentharness-demo' } }
if ($ResourceGroupName -notmatch '^[A-Za-z0-9._()-]{1,90}$' -or $ResourceGroupName.EndsWith('.')) { throw 'Supply a valid Azure resource-group name.' }
if ($existing -and $Mode -in @('Plan','Apply')) {
    if ($existing.subscriptionId -ne $SubscriptionId -or $existing.resourceGroup -ne $ResourceGroupName -or
        (Get-OptionalProperty $existing 'tenantId') -ne $entra.TenantId -or
        (Get-OptionalProperty $existing 'clientId') -ne $entra.ClientId) {
        throw 'Existing deployment state belongs to another explicit target. Refusing to create replacement resources from branding defaults.'
    }
    foreach ($field in @('harnessResourceId','keyVaultResourceId','openAiResourceId','appNetworkResourceId')) {
        $resourceId = Get-OptionalProperty $existing $field
        if (!$resourceId -or !$resourceId.StartsWith("/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/",[StringComparison]::OrdinalIgnoreCase)) {
            throw 'The saved existing-resource IDs are incomplete or outside the explicit target. No infrastructure was changed.'
        }
    }
    if ($CreateNewInfrastructure) { throw 'New-infrastructure creation cannot be combined with an existing deployment state file.' }
    if (!$HarnessOnly) {
        throw 'A saved environment must not be recreated. Only -HarnessOnly publication of the saved site is supported; gateway changes require a separately reviewed operation.'
    }
    if (@('ModelName','ModelVersion','ModelSku','ModelCapacity','ModelDeployment','ComputerUseModelName','ComputerUseModelVersion','ComputerUseDeployment') |
        Where-Object { $PSBoundParameters.ContainsKey($_) }) {
        throw 'Existing-state hosting preserves its actual model deployments. Model changes require an explicit, separately verified ARM operation.'
    }
    if (!$HarnessName) { $HarnessName=$existing.harnessName }
    if ($HarnessName -ne $existing.harnessName) { throw 'The requested site does not match saved state. Automatic hostname migration is not supported.' }
    if ($Mode -eq 'Plan') {
        [pscustomobject]@{subscriptionId=$SubscriptionId;resourceGroup=$existing.resourceGroup;harnessResourceId=$existing.harnessResourceId;harnessUrl=$existing.harnessUrl;sharedInfrastructure='Preserved from deployment state';action='Package/publish existing harness only; no model, vault, logging, network or plan deployment'}
        return
    }
    if ($SkipHarnessPublish) {
        Write-Host 'Existing-state target verified; publication skipped. No shared infrastructure or source credentials were changed.'
        return
    }
    $package = & (Join-Path $PSScriptRoot 'Package.ps1') -HarnessOnly -AgentCatalogPath $AgentCatalogPath
    Refresh-AppVaultReferences -ResourceId $existing.harnessResourceId
    Publish-HarnessZip -ResourceId $existing.harnessResourceId -ZipPath $package.HarnessZip
    & (Join-Path $PSScriptRoot 'Smoke.ps1') -SubscriptionId $SubscriptionId -StatePath $OutputPath -EntraStatePath $EntraStatePath -HarnessOnly
    $latest = Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
    $latest | Add-Member -NotePropertyName harnessPublishedAt -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
    $latest | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
    Write-Host "Republished the saved canonical harness without recreating shared resources: $($existing.harnessUrl)"
    return
}
if ($Mode -in @('Plan','Apply') -and !$CreateNewInfrastructure) {
    throw 'No saved environment was found. New billable infrastructure requires explicit -CreateNewInfrastructure.'
}
if (!$AppServiceLocation) { $AppServiceLocation=$Location }
$plannedHarnessUrl = Get-OptionalProperty $entra 'PlannedHarnessUrl'
$plannedGraviteeUrl = Get-OptionalProperty $entra 'PlannedGraviteeUrl'
if (!$HarnessName -and $plannedHarnessUrl) {
    $hostName = ([uri](Assert-HttpsOrigin -Uri $plannedHarnessUrl)).Host
    if ($hostName -match '^([a-z][a-z0-9-]{2,58}[a-z0-9])\.azurewebsites\.net$') { $HarnessName=$Matches[1] }
}
if ($plannedGraviteeUrl) {
    $gatewayHost = ([uri](Assert-HttpsOrigin -Uri $plannedGraviteeUrl)).Host
    if ($gatewayHost -match '^([a-z][a-z0-9-]{2,58}[a-z0-9])\.([a-z0-9]+)\.cloudapp\.azure\.com$') {
        if (!$GraviteeDnsLabel) { $GraviteeDnsLabel=$Matches[1] }
        if (!$GatewayLocation) { $GatewayLocation=$Matches[2] }
    }
}
if (!$GatewayLocation) { $GatewayLocation=$Location }
$catalog = @()
try { $catalog = @(Get-AvailableModels -SubscriptionId $SubscriptionId -Location $Location) }
catch {
    if (!$HarnessOnly) { throw }
    Write-Warning 'The live model catalog is unavailable. Harness hosting will proceed with model status Pending.'
}
if ($Mode -eq 'Models') {
    $catalog | ForEach-Object {
        $model = Get-OptionalProperty $_ 'model' $_
        [pscustomobject]@{
            Name=$model.name
            Version=$model.version
            Format=$model.format
            Skus=(@(Get-OptionalProperty $model 'skus' (Get-OptionalProperty $_ 'skus' @())) | ForEach-Object { $_.name }) -join ','
            Lifecycle=Get-OptionalProperty $model 'lifecycleStatus'
            InferenceRetirement=Get-OptionalProperty (Get-OptionalProperty $model 'deprecation') 'inference'
            Capabilities=Get-OptionalProperty $model 'capabilities'
        }
    } | Format-Table -Wrap
    return
}
if (!$HarnessOnly) {
    Assert-AvailableModel -Catalog $catalog -Name $ModelName -Version $ModelVersion -Sku $ModelSku -RequireChat
}
if ($ComputerUseModelName) {
    Assert-AvailableModel -Catalog $catalog -Name $ComputerUseModelName -Version $ComputerUseModelVersion -Sku $ModelSku
    if ($ComputerUseDeployment -eq $ModelDeployment) { throw 'Chat and computer-use deployments must have distinct names.' }
}
$names = @($HarnessName)
if (!$HarnessOnly) { $names += $GraviteeDnsLabel }
foreach ($name in $names) {
    if ($name -notmatch '^[a-z][a-z0-9-]{2,58}[a-z0-9]$') { throw 'Invalid Azure app name or public DNS label.' }
}
if ($plannedHarnessUrl -ne "https://$HarnessName.azurewebsites.net" -or
    (!$HarnessOnly -and $plannedGraviteeUrl -ne "https://$GraviteeDnsLabel.$GatewayLocation.cloudapp.azure.com")) {
    throw 'The target names and gateway region must match the initialized planned HTTPS origins. Reinitialize the customer configuration before changing them.'
}
if (!$HarnessOnly -and $AcmeEmail -notmatch '^[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') {
    throw 'Supply an explicit -AcmeEmail contact for the gateway TLS certificate.'
}
if ($Mode -eq 'Apply') {
    if (!$AcknowledgeSubscriptionDefenderAI) {
        throw 'Apply requires -AcknowledgeSubscriptionDefenderAI. The AI pricing plan and MI Security Reader assignment have subscription scope.'
    }
    if (!$HarnessOnly -and $ConsoleAuthMode -eq 'entra-oidc' -and !$GraviteeLicensePath -and !$UseStoredGraviteeLicense) {
        throw 'Console Entra OIDC requires a valid license including apim-openid-connect-sso. Supply -GraviteeLicensePath, or -UseStoredGraviteeLicense for an existing vault secret.'
    }
    if (!$HarnessOnly -and $ConsoleAuthMode -eq 'entra-oidc' -and $GraviteeLicensePath -and !(Test-Path -LiteralPath $GraviteeLicensePath -PathType Leaf)) {
        throw 'The supplied Gravitee license file does not exist.'
    }
}
$me = Invoke-InfraRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
$sshKey = if ($AdminSshPublicKeyPath) { (Get-Content -LiteralPath $AdminSshPublicKeyPath -Raw).Trim() } else { New-PublicOnlySshKey }
if ($sshKey -notmatch '^ssh-rsa [A-Za-z0-9+/=]+(?: .*)?$') { throw 'Supply an RSA SSH public key. No public SSH access will be allowed.' }
$configuration = @{
    tenantId=$entra.TenantId
    tenantName=$entra.TenantName
    tenantDomain=$entra.TenantDomain
    resourceGroupName=$ResourceGroupName
    plannedHarnessUrl=$plannedHarnessUrl
    plannedGraviteeUrl=$plannedGraviteeUrl
    deployerPrincipalId=$me.id
    administratorObjectId=$entra.AdministratorObjectId
    harnessClientId=$entra.ClientId
    harnessServicePrincipalId=$entra.ServicePrincipalId
    approvedB2BGuestObjectIds=@(Get-OptionalProperty $entra 'ApprovedB2BGuestObjectIds' @())
    approvedB2BGuestAdministratorObjectIds=@(Get-OptionalProperty $entra 'ApprovedB2BGuestAdministratorObjectIds' @())
    internalApiClientId=$entra.InternalApiClientId
    internalApiServicePrincipalId=$entra.InternalApiServicePrincipalId
    graviteeClientId=$entra.GraviteeClientId
    graviteeServicePrincipalId=$entra.GraviteeServicePrincipalId
    harnessName=$HarnessName
    harnessOnly=[bool]$HarnessOnly
    appServiceLocation=$AppServiceLocation
    gatewayLocation=$GatewayLocation
    consoleAuthMode=$ConsoleAuthMode
    graviteeDnsLabel=$GraviteeDnsLabel
    vmName=$VmName
    vmSize=$VmSize
    adminSshPublicKey=$sshKey
    model=@{name=[string]$ModelName;version=[string]$ModelVersion;deployment=$ModelDeployment;sku=$ModelSku;capacity=$ModelCapacity;deferDeployment=[bool]$HarnessOnly}
    computerUseModel=@{name=$ComputerUseModelName;version=$ComputerUseModelVersion;deployment=$ComputerUseDeployment;sku=$ModelSku;capacity=$ModelCapacity}
}
$working = Join-Path $root 'artifacts\infra'
New-Item -Path $working -ItemType Directory -Force | Out-Null
$parametersPath = Join-Path $working 'parameters.json'
@{
    '$schema'='https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion='1.0.0.0'
    parameters=@{location=@{value=$Location};configuration=@{value=$configuration}}
} | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $parametersPath -Encoding utf8NoBOM
$template = Join-Path $PSScriptRoot 'subscription.bicep'
& az bicep build --file $template --outfile (Join-Path $working 'subscription.json') --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'Bicep compilation failed.' }
if ($Mode -eq 'Plan') {
    & az deployment sub what-if --subscription $SubscriptionId --location $Location --name agentharness-agent-harness --template-file $template --parameters "@$parametersPath" --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw 'Azure what-if failed. No deployment was attempted.' }
    Write-Host 'Plan only: no resources, credentials, consent, or pricing settings were changed.'
    return
}

Write-Host "Applying to explicitly selected subscription $SubscriptionId; resource group $ResourceGroupName."
if ($HarnessOnly) { Write-Host 'HarnessOnly: B1 persistent web app, private Key Vault/VNet, telemetry, AI account and MI roles; gateway VM/network/disks/staging are deferred.' }
else { Write-Host 'Billable scopes: B1 app plan; D4s_v5 VM and disks/IP; Azure OpenAI tokens/capacity; storage; logs; Key Vault; subscription-wide Defender AI.' }
$package = & (Join-Path $PSScriptRoot 'Package.ps1') -HarnessOnly:$HarnessOnly -AgentCatalogPath $AgentCatalogPath
$providers = @('Microsoft.Resources','Microsoft.Authorization','Microsoft.Security','Microsoft.Web','Microsoft.Network','Microsoft.KeyVault','Microsoft.CognitiveServices','Microsoft.OperationalInsights','Microsoft.Insights')
if (!$HarnessOnly) { $providers += @('Microsoft.Compute','Microsoft.Storage') }
$registeredProviders = Invoke-InfraRequest GET "https://management.azure.com/subscriptions/$SubscriptionId/providers?api-version=2021-04-01"
foreach ($provider in $providers) {
    if (@($registeredProviders.value | Where-Object { $_.namespace -eq $provider -and $_.registrationState -eq 'Registered' }).Count) { continue }
    & az provider register --namespace $provider --subscription $SubscriptionId --wait --only-show-errors --output none
    if ($LASTEXITCODE -ne 0) { throw "Could not register provider $provider in the explicit subscription." }
}
$defender = Enable-VerifiedDefenderAI -SubscriptionId $SubscriptionId -AcknowledgeSubscriptionScope
$deploymentJson = & az deployment sub create --subscription $SubscriptionId --location $Location --name agentharness-agent-harness --template-file $template --parameters "@$parametersPath" --only-show-errors --output json
if ($LASTEXITCODE -ne 0) { throw 'Azure infrastructure deployment failed. Inspect the explicit subscription deployment for partial resources.' }
$deployment = ($deploymentJson | ConvertFrom-Json).properties.outputs.deployment.value
if ($deployment.subscriptionId -ne $SubscriptionId -or $deployment.resourceGroup -ne $ResourceGroupName -or
    $deployment.tenantId -ne $entra.TenantId -or $deployment.clientId -ne $entra.ClientId) { throw 'Deployment output scope did not match the explicit target.' }
$deployment | Add-Member -NotePropertyName defender -NotePropertyValue $defender -Force
New-Item -Path (Split-Path ([IO.Path]::GetFullPath($OutputPath))) -ItemType Directory -Force | Out-Null
$deployment | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM

Connect-VaultControlPlane -VaultUri $deployment.keyVaultUri -ResourceId $deployment.keyVaultResourceId
Write-Host 'Core ARM deployment succeeded. Provisioning the OIDC secret through the cached administrator ARM session; the vault stays private.'
Wait-VaultAccess -VaultUri $deployment.keyVaultUri
Ensure-AppSecret -VaultUri $deployment.keyVaultUri -Name harness-oidc-client-secret -ObjectId $entra.ApplicationObjectId -ClientId $entra.ClientId
Ensure-AppRedirect -ObjectId $entra.ApplicationObjectId -ClientId $entra.ClientId -RedirectUri "$($deployment.harnessUrl)/signin-oidc"
if ($HarnessOnly) {
    if ($SkipHarnessPublish) {
        Write-Host 'Core infrastructure is saved; harness publication was explicitly skipped. No login or model readiness is claimed.'
        return
    }
    Write-Host 'Core infrastructure created. Publishing the harness without waiting for Gravitee or a model deployment.'
    Refresh-AppVaultReferences -ResourceId $deployment.harnessResourceId
    Publish-HarnessZip -ResourceId $deployment.harnessResourceId -ZipPath $package.HarnessZip
    & (Join-Path $PSScriptRoot 'Smoke.ps1') -SubscriptionId $SubscriptionId -StatePath $OutputPath -EntraStatePath $EntraStatePath -HarnessOnly
    $deployment | Add-Member -NotePropertyName loginUrl -NotePropertyValue "$($deployment.harnessUrl)/auth/login" -Force
    $deployment | Add-Member -NotePropertyName loginReadyVerifiedAt -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
    $deployment | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
    Write-Host "LIVE login ready, Key Vault reference resolved: $($deployment.harnessUrl)/auth/login"
    $modelResult = Enable-HarnessChatModel -SubscriptionId $SubscriptionId -Location $Location -AccountResourceId $deployment.openAiResourceId -SiteResourceId $deployment.harnessResourceId -Catalog $catalog -PreferredName $ModelName -PreferredVersion $ModelVersion -Sku $ModelSku -Capacity $ModelCapacity -DeploymentName $ModelDeployment
    $deployment.modelStatus = $modelResult.status
    $deployment.modelDeployment = $modelResult.deployment
    $deployment | Add-Member -NotePropertyName model -NotePropertyValue $modelResult -Force
    $deployment | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
    if ($modelResult.status -eq 'Ready') {
        & (Join-Path $PSScriptRoot 'Smoke.ps1') -SubscriptionId $SubscriptionId -StatePath $OutputPath -EntraStatePath $EntraStatePath -HarnessOnly
    } else { Write-Warning 'The login/admin shell is live; no model deployment was claimed. Model status remains Pending.' }
    Write-Host "HarnessOnly completed in $SubscriptionId. URL: $($deployment.harnessUrl); state: $OutputPath"
    return
}
if ($ConsoleAuthMode -eq 'entra-oidc') {
    Ensure-AppSecret -VaultUri $deployment.keyVaultUri -Name gravitee-oidc-client-secret -ObjectId $entra.GraviteeApplicationObjectId -ClientId $entra.GraviteeClientId
}
foreach ($name in @('gravitee-demo-admin-password','gravitee-jwt-secret','gravitee-mongodb-password','gravitee-elasticsearch-password')) {
    Ensure-RandomVaultSecret -VaultUri $deployment.keyVaultUri -Name $name
}
if ($ConsoleAuthMode -eq 'entra-oidc' -and $GraviteeLicensePath) {
    $license = Get-Content -LiteralPath $GraviteeLicensePath -Raw
    try {
        if ([string]::IsNullOrWhiteSpace($license)) { throw 'The Gravitee license file is empty.' }
        Set-VaultSecret -VaultUri $deployment.keyVaultUri -Name gravitee-license -Value $license
    } finally { $license=$null }
} elseif ($ConsoleAuthMode -eq 'entra-oidc' -and $null -eq (Get-VaultSecretOrNull -VaultUri $deployment.keyVaultUri -Name gravitee-license)) {
    throw 'The expected stored Gravitee license does not exist; no console OIDC configuration will be attempted.'
}
# APIM 4.12's oidc-client-ts callback is the console root, not an API callback.
if ($ConsoleAuthMode -eq 'entra-oidc') {
    Ensure-AppRedirect -ObjectId $entra.GraviteeApplicationObjectId -ClientId $entra.GraviteeClientId -RedirectUri $deployment.graviteeUrl
    Ensure-GraviteeOidcConsent -ObjectId $entra.GraviteeApplicationObjectId -ClientId $entra.GraviteeClientId -ServicePrincipalId $entra.GraviteeServicePrincipalId
}

$zip = $package.HarnessZip
$backendPublish = $package.BackendPublish
$bundle = Join-Path $working 'bundle'
if (Test-Path -LiteralPath $bundle) { Remove-Item -LiteralPath $bundle -Recurse -Force }
New-Item -Path (Join-Path $bundle 'internal-api\publish') -ItemType Directory -Force | Out-Null
foreach ($file in @('compose.json','Caddyfile','bootstrap.sh','provision.py')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "gravitee\$file") -Destination $bundle
}
Copy-Item -LiteralPath 'src\AgentHarness.InternalApi\Dockerfile' -Destination (Join-Path $bundle 'internal-api\Dockerfile')
Copy-Item -Path (Join-Path $backendPublish '*') -Destination (Join-Path $bundle 'internal-api\publish') -Recurse
New-Item -Path (Join-Path $bundle 'internal-api\publish\data') -ItemType Directory -Force | Out-Null
$runtimeDirectory = Join-Path $bundle 'internal-api\publish\runtimes'
if (Test-Path -LiteralPath $runtimeDirectory) {
    Get-ChildItem -LiteralPath $runtimeDirectory -Directory | Where-Object Name -ne 'linux-x64' | Remove-Item -Recurse -Force
}
@{
    tenantId=$entra.TenantId;harnessClientId=$entra.ClientId;internalApiClientId=$entra.InternalApiClientId
    graviteeClientId=$entra.GraviteeClientId;graviteeUrl=$deployment.graviteeUrl;keyVaultUri=$deployment.keyVaultUri;acmeEmail=$AcmeEmail;consoleAuthMode=$ConsoleAuthMode
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $bundle 'public.json') -Encoding utf8NoBOM
$bundleZip = Join-Path $working 'gravitee.zip'
if (Test-Path -LiteralPath $bundleZip) { Remove-Item -LiteralPath $bundleZip -Force }
[IO.Compression.ZipFile]::CreateFromDirectory($bundle, $bundleZip)
$storageResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$($deployment.storageAccountName)"
$storageStatus = Invoke-InfraRequest GET "https://management.azure.com$storageResourceId`?api-version=2025-01-01"
if ($storageStatus.properties.publicNetworkAccess -eq 'Disabled') {
    Write-Host 'Staging storage is private. Transferring only the checksum-verified, non-secret Linux deployment bundle through ARM Run Command.'
    $bundleHash = (Get-FileHash -LiteralPath $bundleZip -Algorithm SHA256).Hash.ToLowerInvariant()
    Invoke-VmBundle -VmResourceId $deployment.vmResourceId -InlineBundlePath $bundleZip -Sha256 $bundleHash -Location $GatewayLocation
} else {
    $blob = Publish-PrivateBundle -SubscriptionId $SubscriptionId -ContainerUrl $deployment.artifactContainerUrl -Path $bundleZip
    Invoke-VmBundle -VmResourceId $deployment.vmResourceId -BundleUri $blob.uri -Sha256 $blob.sha256 -Location $GatewayLocation
}
$deployment | Add-Member -NotePropertyName vmBootstrapVerifiedAt -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
$deployment | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
Refresh-AppVaultReferences -ResourceId $deployment.harnessResourceId
if (!$SkipHarnessPublish) { Publish-HarnessZip -ResourceId $deployment.harnessResourceId -ZipPath $zip }
& (Join-Path $PSScriptRoot 'Smoke.ps1') -SubscriptionId $SubscriptionId -StatePath $OutputPath -EntraStatePath $EntraStatePath
$deployment.graviteeStatus='Ready'
$deployment | Add-Member -NotePropertyName loginUrl -NotePropertyValue "$($deployment.harnessUrl)/auth/login" -Force
$deployment | Add-Member -NotePropertyName fullSmokeVerifiedAt -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
$deployment | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
Write-Host "Deployment and unauthenticated checks verified. State: $OutputPath"
Write-Host 'Complete the delegated-reader/approver smoke matrix with real Entra user tokens; no interactive sign-in or fabricated success was used.'
