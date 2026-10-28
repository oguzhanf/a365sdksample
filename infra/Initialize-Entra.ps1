#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$')][string]$TenantDomain,
    [Parameter(Mandatory)][string]$AdministratorObjectId,
    [Parameter(Mandatory)][ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')][string]$AdministratorUpn,
    [Parameter(Mandatory)][uri]$HarnessUrl,
    [Parameter(Mandatory)][uri]$GraviteeUrl,
    [ValidatePattern('^[^\r\n]{1,100}$')][string]$ApplicationName = 'AgentHarness',
    [ValidateLength(1,200)][string]$TenantName,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'entra-state.json')
)
. (Join-Path $PSScriptRoot 'AzureSession.ps1')
$OutputPath = Assert-LocalStatePath -Path $OutputPath
$plannedHarnessUrl = Assert-HttpsOrigin -Uri $HarnessUrl
$plannedGraviteeUrl = Assert-HttpsOrigin -Uri $GraviteeUrl
if ($plannedHarnessUrl -eq $plannedGraviteeUrl) { throw 'The harness and gateway must have distinct HTTPS origins.' }
if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
    $previous = Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
    foreach ($field in @('TenantId','SubscriptionId','AdministratorObjectId','ApplicationName')) {
        $property = $previous.PSObject.Properties[$field]
        if ($property -and $property.Value -ne (Get-Variable -Name $field -ValueOnly)) {
            throw 'The local state belongs to another configuration. Choose a separate ignored output path.'
        }
    }
}
Initialize-CachedAzureSession -TenantId $TenantId -SubscriptionId $SubscriptionId `
    -AdministratorObjectId $AdministratorObjectId -AdministratorUpn $AdministratorUpn | Out-Null
$admin = Invoke-CachedAzureRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
if (!$TenantName) { $TenantName=$TenantDomain.ToLowerInvariant() }
$graphSp = @(Get-GraphCollection -Path "v1.0/servicePrincipals?`$filter=appId%20eq%20'00000003-0000-0000-c000-000000000000'&`$select=id,appRoles,oauth2PermissionScopes")[0]

function New-AppRole {
    param([string]$Value, [string]$Description)
    return @{ id=[guid]::NewGuid().ToString(); allowedMemberTypes=@('User'); displayName=$Value; description=$Description; isEnabled=$true; value=$Value }
}

function Get-OrCreateApplication {
    param([string]$Name, [object[]]$Roles, [string[]]$Redirects, [object[]]$Access = @())
    $escapedName = $Name.Replace("'","''")
    $found = @(Get-GraphCollection -Path ("v1.0/applications?`$filter=" + [uri]::EscapeDataString("displayName eq '$escapedName'")))
    if ($found.Count -gt 1) { throw "More than one application is named $Name. Resolve the duplicate before continuing." }
    if ($found.Count -eq 1) {
        $app = $found[0]
        if ($app.signInAudience -ne 'AzureADMyOrg') { throw "Existing application $Name is not single-tenant; refusing to reuse it." }
        $existingValues = @($app.appRoles | ForEach-Object { $_.value })
        foreach ($role in $Roles) {
            if ($existingValues -notcontains $role.value) { throw "Existing application $Name is missing role $($role.value); refusing to overwrite its roles." }
        }
        $redirectUris = @($app.web.redirectUris) + @($Redirects) | Select-Object -Unique
        if (@($Redirects | Where-Object { $_ -notin @($app.web.redirectUris) }).Count) {
            Invoke-CachedAzureRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" `
                -Body @{web=@{redirectUris=@($redirectUris)}} | Out-Null
        }
    } else {
        $app = Invoke-CachedAzureRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body @{
            displayName=$Name; signInAudience='AzureADMyOrg'; appRoles=$Roles
            web=@{ redirectUris=$Redirects; implicitGrantSettings=@{enableIdTokenIssuance=$false;enableAccessTokenIssuance=$false} }
            api=@{ requestedAccessTokenVersion=2 }
            optionalClaims=@{ idToken=@(@{name='acct';essential=$true},@{name='email';essential=$false}); accessToken=@(@{name='acct';essential=$true}) }
            requiredResourceAccess=$Access
        }
    }
    $principals = @(Get-GraphCollection -Path ("v1.0/servicePrincipals?`$filter=" + [uri]::EscapeDataString("appId eq '$($app.appId)'")))
    $sp = if ($principals.Count) { $principals[0] } else {
        Invoke-CachedAzureRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body @{appId=$app.appId}
    }
    $owners = @(Get-GraphCollection -Path "v1.0/applications/$($app.id)/owners?`$select=id")
    if (@($owners | ForEach-Object { $_.id }) -notcontains $admin.id) {
        Invoke-CachedAzureRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners/`$ref" -Body @{'@odata.id'="https://graph.microsoft.com/v1.0/users/$($admin.id)"} | Out-Null
    }
    return @{Application=$app; Principal=$sp}
}

$applicationPermissions = @(
    'Application.Read.All', 'AppRoleAssignment.ReadWrite.All', 'User.Read.All',
    'AgentIdentityBlueprint.Create', 'AgentIdentityBlueprint.ReadWrite.All',
    'AgentIdentityBlueprintPrincipal.Create', 'AgentIdentity.Create.All', 'AgentIdentity.ReadWrite.All',
    'AgentRegistration.ReadWrite.All', 'Content.Process.All', 'ProtectionScopes.Compute.All'
)
$permissionRoles = @()
$unavailable = @()
foreach ($name in $applicationPermissions) {
    $role = @($graphSp.appRoles | Where-Object { $_.value -eq $name -and $_.isEnabled -and $_.allowedMemberTypes -contains 'Application' })
    if ($role.Count -eq 1) { $permissionRoles += @{id=$role[0].id;type='Role';value=$name} }
    else { $unavailable += $name }
}
$mandatory = @('Application.Read.All','AppRoleAssignment.ReadWrite.All','User.Read.All')
foreach ($name in $mandatory) { if ($unavailable -contains $name) { throw "Required Graph permission $name is unavailable." } }
$graphAccess = @{ resourceAppId='00000003-0000-0000-c000-000000000000'; resourceAccess=@($permissionRoles | ForEach-Object { @{id=$_.id;type='Role'} }) }
$harness = Get-OrCreateApplication -Name $ApplicationName -Roles @(
    (New-AppRole 'AgentHarnessAdministrators' 'Manage this harness, its agents, and approved application role assignments.'),
    (New-AppRole 'AgentHarnessUsers' 'Use the agents and demonstrations in this harness.')
) -Redirects @("$($HarnessUrl.AbsoluteUri.TrimEnd('/'))/signin-oidc") -Access @($graphAccess)
$internal = Get-OrCreateApplication -Name "$ApplicationName Internal API" -Roles @(
    (New-AppRole 'InternalApi.Reader' 'Read synthetic purchase orders through Gravitee.'),
    (New-AppRole 'InternalApi.Approver' 'Approve synthetic purchase orders through Gravitee.')
) -Redirects @()
$gravitee = Get-OrCreateApplication -Name "$ApplicationName Gravitee" -Roles @(
    (New-AppRole 'Gravitee.Administrator' 'Administer the Gravitee demo platform.'),
    (New-AppRole 'Gravitee.User' 'Use the Gravitee demo platform.')
) -Redirects @($plannedGraviteeUrl)

$scope = @($internal.Application.api.oauth2PermissionScopes | Where-Object { $_.value -eq 'access_as_user' })
if (!$scope.Count) {
    $scopeId = [guid]::NewGuid().ToString()
    Invoke-CachedAzureRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($internal.Application.id)" -Body @{
        identifierUris=@("api://$($internal.Application.appId)")
        api=@{requestedAccessTokenVersion=2;oauth2PermissionScopes=@(@{
            id=$scopeId; value='access_as_user'; type='Admin'; isEnabled=$true
            adminConsentDisplayName='Access the Gravitee-protected internal API'
            adminConsentDescription='Access the synthetic internal API on behalf of the signed-in user. Gravitee applies API authorization.'
        })}
    } | Out-Null
} else { $scopeId = $scope[0].id }
Invoke-CachedAzureRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($harness.Application.id)" -Body @{
    requiredResourceAccess=@($graphAccess,@{resourceAppId=$internal.Application.appId;resourceAccess=@(@{id=$scopeId;type='Scope'})})
} | Out-Null
foreach ($app in @($harness,$gravitee)) {
    Invoke-CachedAzureRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($app.Principal.id)" -Body @{appRoleAssignmentRequired=$true} | Out-Null
}

$current = @(Get-GraphCollection -Path "v1.0/servicePrincipals/$($harness.Principal.id)/appRoleAssignments")
foreach ($permission in $permissionRoles) {
    if (!($current | Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $permission.id })) {
        Invoke-CachedAzureRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($harness.Principal.id)/appRoleAssignments" -Body @{
            principalId=$harness.Principal.id; resourceId=$graphSp.id; appRoleId=$permission.id
        } | Out-Null
    }
}
foreach ($assignment in @(
    @{App=$harness;Value='AgentHarnessAdministrators'}, @{App=$harness;Value='AgentHarnessUsers'},
    @{App=$internal;Value='InternalApi.Reader'}, @{App=$internal;Value='InternalApi.Approver'},
    @{App=$gravitee;Value='Gravitee.Administrator'}
)) {
    $app = $assignment.App
    $role = @($app.Application.appRoles | Where-Object { $_.value -eq $assignment.Value })[0]
    $existing = @(Get-GraphCollection -Path "v1.0/servicePrincipals/$($app.Principal.id)/appRoleAssignedTo")
    if (!($existing | Where-Object { $_.principalId -eq $admin.id -and $_.appRoleId -eq $role.id })) {
        Invoke-CachedAzureRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($app.Principal.id)/appRoleAssignedTo" -Body @{
            principalId=$admin.id;resourceId=$app.Principal.id;appRoleId=$role.id
        } | Out-Null
    }
}
$grants = @(Get-GraphCollection -Path ("v1.0/oauth2PermissionGrants?`$filter=" + [uri]::EscapeDataString("clientId eq '$($harness.Principal.id)'")))
if (!($grants | Where-Object { $_.resourceId -eq $internal.Principal.id -and $_.consentType -eq 'AllPrincipals' })) {
    Invoke-CachedAzureRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body @{
        clientId=$harness.Principal.id;resourceId=$internal.Principal.id;consentType='AllPrincipals';scope='access_as_user'
    } | Out-Null
}
$state = [ordered]@{
    TenantId=$TenantId;TenantName=$TenantName;TenantDomain=$TenantDomain.ToLowerInvariant();SubscriptionId=$SubscriptionId
    ApplicationName=$ApplicationName;ClientId=$harness.Application.appId;ApplicationObjectId=$harness.Application.id
    ServicePrincipalId=$harness.Principal.id
    InternalApiClientId=$internal.Application.appId;InternalApiApplicationObjectId=$internal.Application.id;InternalApiServicePrincipalId=$internal.Principal.id
    GraviteeClientId=$gravitee.Application.appId;GraviteeApplicationObjectId=$gravitee.Application.id;GraviteeServicePrincipalId=$gravitee.Principal.id
    AdministratorObjectId=$admin.id;AdministratorUpn=$AdministratorUpn
    PlannedHarnessUrl=$plannedHarnessUrl;PlannedGraviteeUrl=$plannedGraviteeUrl
    HarnessUrl=$plannedHarnessUrl;GraviteeUrl=$plannedGraviteeUrl
    GrantedGraphApplicationPermissions=@($permissionRoles | ForEach-Object { $_.value });UnavailableGraphApplicationPermissions=$unavailable
    ConfiguredAt=[datetimeoffset]::UtcNow.ToString('O')
}
New-Item -Path (Split-Path $OutputPath) -ItemType Directory -Force | Out-Null
$state | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Host 'Verified single-tenant application registrations and role assignments. Customer configuration was saved to the ignored local state file.'
