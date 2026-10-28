#requires -Version 7.2
<#
.SYNOPSIS
Creates or verifies Purview policies scoped only to AgentHarness.
.DESCRIPTION
Preview is offline. Apply creates missing objects only. DlpOnly requires confirmed
DLP entitlement and administrative authority. All also requires existing approved
PAYG billing, auditing, and DSPM onboarding. Conflicting objects are never modified.

Authentication uses an explicitly selected existing SCC REST connection, an
in-memory SecureString SCC token, the Azure CLI token cache, or an explicitly
authorized ephemeral application identity. There is no interactive authentication,
installation, billing setup, or tenant-wide policy change.
.PARAMETER StatePath
Ignored customer Entra state created with explicit tenant, subscription,
administrator, application, and initial tenant-domain inputs. Preview requires this
configuration but does not authenticate.
.PARAMETER PolicySet
All configures DLP and collection. DlpOnly configures only the application DLP
policy/rule and does not activate collection, Audit, or billing.
.PARAMETER EphemeralAppOnly
Explicitly authorizes a short-lived dedicated automation identity using the cached
Graph administrator. Grants only EOP Exchange.ManageAsApp and Compliance Administrator.
Its certificate key stays in memory; all temporary grants/credentials/objects are
removed in finally. Does not add privileges to the harness application.
.PARAMETER Action
Preview returns the proposed configuration without authentication or changes.
Apply creates missing objects and verifies their read-back configuration.
Verify checks existing policies without creating policies. EphemeralAppOnly still
creates and removes temporary authentication objects.
.PARAMETER PrerequisitesConfirmed
Attests that the tenant administrator has independently verified the prerequisites.
DlpOnly requires DLP entitlement and authority; All additionally requires approved
PAYG, Audit, and DSPM onboarding. Does not activate these prerequisites.
.PARAMETER ConnectionId
Reuses this existing SCC REST connection in the current PowerShell process.
The connection must belong to the expected tenant and is never disconnected.
.PARAMETER AccessToken
An already acquired SCC token held in memory as a SecureString. Never pass a
token literal on a command line or write one to a transcript or evidence file.
.EXAMPLE
.\tools\Configure-Purview.ps1 -Action Preview
.EXAMPLE
.\tools\Configure-Purview.ps1 -Action Verify
.EXAMPLE
.\tools\Configure-Purview.ps1 -Action Apply -PrerequisitesConfirmed
.EXAMPLE
.\tools\Configure-Purview.ps1 -Action Apply -PolicySet DlpOnly -PrerequisitesConfirmed -EphemeralAppOnly
#>
[CmdletBinding(DefaultParameterSetName = 'Cached')]
param(
    [ValidateSet('Preview', 'Apply', 'Verify')]
    [string]$Action = 'Preview',

    [switch]$PrerequisitesConfirmed,

    [ValidateSet('All', 'DlpOnly')]
    [string]$PolicySet = 'All',

    [Parameter(Mandatory, ParameterSetName = 'Ephemeral')]
    [switch]$EphemeralAppOnly,

    [Parameter(ParameterSetName = 'Ephemeral')]
    [switch]$UseCertificateAuthentication,

    [Parameter(ParameterSetName = 'Ephemeral')]
    [switch]$IncludeExchangeBootstrapPermission,

    [Parameter(ParameterSetName = 'Ephemeral')]
    [securestring]$GraphAccessToken,

    [Parameter(Mandatory, ParameterSetName = 'Existing')]
    [guid]$ConnectionId,

    [Parameter(Mandatory, ParameterSetName = 'Token')]
    [securestring]$AccessToken,

    [string]$StatePath = (Join-Path $PSScriptRoot '..\infra\entra-state.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

. (Join-Path $PSScriptRoot 'HarnessConfiguration.ps1')
$state = Read-HarnessConfiguration -StatePath $StatePath `
    -DomainFields @('TenantDomain') -UpnFields @('AdministratorUpn')
$tenantId = $state.TenantId
$subscriptionId = $state.SubscriptionId
$organization = $state.TenantDomain
$administratorUpn = $state.AdministratorUpn
$administratorObjectId = $state.AdministratorObjectId
$applicationId = $state.ClientId
$applicationName = if ([string]::IsNullOrWhiteSpace([string]$state['ApplicationName'])) { 'AgentHarness' } else { [string]$state['ApplicationName'] }
if (-not $organization.EndsWith('.onmicrosoft.com', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'TenantDomain must explicitly configure the tenant initial onmicrosoft.com domain.'
}
$sccResource = 'https://ps.compliance.protection.outlook.com/'
$eopResourceAppId = '00000007-0000-0ff1-ce00-000000000000'
$eopManageAsAppRoleId = '455e5cd2-84e8-4751-8344-5672145dfa17'
$exchangeResourceAppId = '00000002-0000-0ff1-ce00-000000000000'
$exchangeManageAsAppRoleId = 'dc50a0fb-09a3-484d-be87-e023b12c6440'
$complianceAdministratorRoleId = '17315797-102d-40b4-93e0-432062caca18'
$policyName = 'AgentHarness - App DLP'
$ruleName = 'AgentHarness - Block credit card prompts'
$collectionName = 'AgentHarness - App collection'
$creditCardTypeId = '50842eb7-edc8-4019-85dd-5a5c1f2bb085'

function Get-PolicyField {
    param([AllowNull()][object]$Value, [string]$Name)
    if ($null -eq $Value) { return }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            if ([string]$key -ieq $Name) {
                if ($null -ne $Value[$key]) { return $Value[$key] }
                return
            }
        }
        return
    }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -ne $property -and $null -ne $property.Value) { return $property.Value }
}

function ConvertFrom-PolicyValue {
    param([AllowNull()][object]$Value, [string]$Label)
    foreach ($item in @($Value)) {
        if ($null -eq $item) { continue }
        if ($item -is [string]) {
            if ([string]::IsNullOrWhiteSpace($item)) { continue }
            try { ConvertFrom-Json -InputObject $item -Depth 40 -ErrorAction Stop }
            catch { throw "Cannot verify $Label because the service did not return readable JSON. No existing object will be changed." }
        }
        else { $item }
    }
}

function Get-ExactNamedPolicy {
    param([AllowEmptyCollection()][object[]]$Items, [string]$Name)
    $matches = @($Items | Where-Object { (Get-PolicyField $_ 'Name') -ieq $Name })
    if ($matches.Count -gt 1) { throw "More than one object matches '$Name'; refusing to choose one." }
    if ($matches.Count -eq 1) { return $matches[0] }
    return $null
}

function Assert-OnlyHarnessLocation {
    param([object]$Policy, [string]$Label)
    $locations = @(ConvertFrom-PolicyValue (Get-PolicyField $Policy 'Locations') "$Label Locations")
    if ($locations.Count -ne 1) { throw "$Label must have exactly one app location. Refusing a missing, broad, or additional scope." }
    $location = $locations[0]
    $expected = @{
        Workload = 'Applications'
        Location = $applicationId
        LocationSource = 'Entra'
        LocationType = 'Individual'
    }
    foreach ($field in $expected.Keys) {
        if ([string](Get-PolicyField $location $field) -ine $expected[$field]) {
            throw "$Label has conflicting $field. Only the individual AgentHarness Entra app is permitted."
        }
    }
    $inclusions = @(Get-PolicyField $location 'Inclusions')
    if ($inclusions.Count -ne 1 -or
        [string](Get-PolicyField $inclusions[0] 'Type') -ine 'Tenant' -or
        [string](Get-PolicyField $inclusions[0] 'Identity') -ine 'All' -or
        @(Get-PolicyField $location 'Exclusions').Count -ne 0) {
        throw "$Label has conflicting user inclusions or exclusions. Existing scope will not be overwritten."
    }
    foreach ($field in @(
        'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'TeamsLocation',
        'EndpointDlpLocation', 'OnPremisesScannerDlpLocation', 'PowerBIDlpLocation',
        'ThirdPartyAppDlpLocation'
    )) {
        $otherLocations = @(Get-PolicyField $Policy $field | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($otherLocations.Count -ne 0) { throw "$Label also targets $field; refusing to reuse a policy with another workload." }
    }
}

function Assert-HarnessDlpPolicy {
    param([object]$Policy)
    Assert-OnlyHarnessLocation $Policy "DLP policy '$policyName'"
    $planes = @(Get-PolicyField $Policy 'EnforcementPlanes')
    if ([string](Get-PolicyField $Policy 'Mode') -ine 'Enable' -or
        $planes.Count -ne 1 -or [string]$planes[0] -ine 'Application') {
        throw "DLP policy '$policyName' must be enabled with only the Application enforcement plane. No existing policy will be modified."
    }
}

function Assert-HarnessDlpRule {
    param([object]$Rule)
    $exceptions = @(Get-PolicyField $Rule 'Exceptions')
    $conditions = @(Get-PolicyField $Rule 'Conditions')
    if ($exceptions.Count -ne 0 -or $conditions.Count -gt 1) {
        throw "Rule '$ruleName' has additional conditions or exceptions. Refusing to treat a different rule as the demo block rule."
    }
    foreach ($property in $Rule.PSObject.Properties) {
        if ($property.Name -like 'ExceptIf*') {
            $configured = @($property.Value | Where-Object {
                $null -ne $_ -and [string]$_ -notin @('', 'False', '0')
            })
            if ($configured.Count -gt 0) { throw "Rule '$ruleName' has a configured $($property.Name) exception." }
        }
    }
    $restrictions = @(ConvertFrom-PolicyValue (Get-PolicyField $Rule 'RestrictAccess') "$ruleName RestrictAccess")
    if ($restrictions.Count -ne 1 -or
        [string](Get-PolicyField $restrictions[0] 'setting') -ine 'UploadText' -or
        [string](Get-PolicyField $restrictions[0] 'value') -ine 'Block' -or
        [string](Get-PolicyField $Rule 'Disabled') -ine 'False') {
        throw "Rule '$ruleName' must be enabled and explicitly Block UploadText. No existing rule will be modified."
    }
    $types = @(ConvertFrom-PolicyValue (Get-PolicyField $Rule 'ContentContainsSensitiveInformation') "$ruleName sensitive information types")
    if ($types.Count -ne 1 -or
        ([string](Get-PolicyField $types[0] 'Name') -ine 'credit card number' -and
         [string](Get-PolicyField $types[0] 'id') -ine $creditCardTypeId)) {
        throw "Rule '$ruleName' does not have the expected credit card number condition."
    }
    $minimumCount = Get-PolicyField $types[0] 'minCount'
    if ($null -ne $minimumCount -and [int]$minimumCount -ne 1) {
        throw "Rule '$ruleName' has a conflicting minimum match count."
    }
    if ([string](Get-PolicyField $Rule 'GenerateAlert') -ine 'True' -or
        @(Get-PolicyField $Rule 'GenerateIncidentReport') -inotcontains 'siteadmin' -or
        @(Get-PolicyField $Rule 'NotifyUser') -inotcontains $administratorUpn) {
        throw "Rule '$ruleName' has conflicting alert, incident report, or notification settings."
    }
}

function Assert-HarnessCollection {
    param([object]$Policy)
    Assert-OnlyHarnessLocation $Policy "Collection policy '$collectionName'"
    $configItems = @(ConvertFrom-PolicyValue (Get-PolicyField $Policy 'ScenarioConfig') "$collectionName ScenarioConfig")
    if ($configItems.Count -ne 1) { throw "Collection policy '$collectionName' has no unambiguous ScenarioConfig." }
    $config = $configItems[0]
    $activities = @(Get-PolicyField $config 'Activities')
    $planes = @(Get-PolicyField $config 'EnforcementPlanes')
    $types = @(Get-PolicyField $config 'SensitiveTypeIds')
    if ([string](Get-PolicyField $Policy 'Mode') -ine 'Enable' -or
        $activities.Count -ne 2 -or $activities -inotcontains 'UploadText' -or $activities -inotcontains 'DownloadText' -or
        $planes.Count -ne 1 -or [string]$planes[0] -ine 'Application' -or
        $types.Count -ne 1 -or [string]$types[0] -ine 'All' -or
        [string](Get-PolicyField $config 'IsIngestionEnabled') -ine 'True' -or
        @(Get-PolicyField $config 'ExcludedSensitiveTypeIds').Count -ne 0) {
        throw "Collection policy '$collectionName' has conflicting mode, activities, classifiers, ingestion, or enforcement plane."
    }
}

function Get-SccTokenBinding {
    param([object]$Claims)
    if (-not [string]::IsNullOrWhiteSpace([string](Get-PolicyField $Claims 'scp'))) {
        if ([string](Get-PolicyField $Claims 'oid') -ine $administratorObjectId) {
            throw 'The delegated SCC token is not the configured administrator. No connection or policy change was attempted.'
        }
        foreach ($field in @('upn', 'preferred_username', 'unique_name')) {
            $userPrincipalName = [string](Get-PolicyField $Claims $field)
            if (-not [string]::IsNullOrWhiteSpace($userPrincipalName)) {
                if ($userPrincipalName -ine $administratorUpn) {
                    throw 'The delegated SCC token user name differs from the configured administrator.'
                }
                return @{ UserPrincipalName = $userPrincipalName }
            }
        }
        if ([string](Get-PolicyField $Claims 'oid') -ieq $administratorObjectId) {
            return @{ UserPrincipalName = $administratorUpn }
        }
        throw 'The delegated SCC token has no usable user name. Supply an existing SCC connection; no authentication fallback will be attempted.'
    }
    if ([string](Get-PolicyField $Claims 'idtyp') -ieq 'app' -or @(Get-PolicyField $Claims 'roles').Count -gt 0) {
        return @{ Organization = $organization }
    }
    throw 'The SCC token type could not be identified. No interactive authentication will be attempted.'
}

function Get-SafeFailure {
    param([System.Management.Automation.ErrorRecord]$Failure)
    $providerMessage = ''
    if ($null -ne $Failure.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($Failure.ErrorDetails.Message)) {
        try {
            $details = $Failure.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
            $errorValue = Get-PolicyField $details 'error'
            $code = if ($errorValue -is [string]) { $errorValue } else { [string](Get-PolicyField $errorValue 'code') }
            $description = if ($errorValue -is [string]) { [string](Get-PolicyField $details 'error_description') } else { [string](Get-PolicyField $errorValue 'message') }
            if ($code -or $description) { $providerMessage = " Provider: $code $description" }
        }
        catch { $providerMessage = ' Provider error details were not readable JSON.' }
    }
    $message = [regex]::Replace(
        ($Failure.Exception.Message + $providerMessage),
        '[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}',
        '[REDACTED_TOKEN]'
    )
    return "$message [ErrorId: $($Failure.FullyQualifiedErrorId)]"
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-EphemeralSccToken {
    param([hashtable]$Context)
    $Context.Stage = 'Verify cached Graph administrator'
    $me = Invoke-CachedAzureRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
    if ($me.id -ine $administratorObjectId) { throw 'The cached Graph user is not the approved administrator. No temporary app was created.' }
    $Context.Stage = 'Verify role-grant authority'
    $assignments = Invoke-CachedAzureRequest -Method GET -Uri (
        'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20%27' +
        $administratorObjectId + '%27&$expand=roleDefinition'
    )
    $authorized = @($assignments.value | Where-Object {
        $_.directoryScopeId -eq '/' -and $_.roleDefinition.templateId -in @(
            '62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        )
    })
    if ($authorized.Count -eq 0) { throw 'An active tenant-root Global Administrator or Privileged Role Administrator assignment is required. No role activation or privilege escalation was attempted.' }
    $Context.Stage = 'Verify documented EOP permission'
    $resourceResult = Invoke-CachedAzureRequest -Method GET -Uri (
        'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId%20eq%20%27' +
        $eopResourceAppId + '%27&$select=id,appId,appRoles'
    )
    $resources = @($resourceResult.value)
    if ($resources.Count -ne 1) { throw 'The documented Microsoft Exchange Online Protection service principal is missing or ambiguous.' }
    $resource = $resources[0]
    $permissions = @($resource.appRoles | Where-Object {
        $_.id -ieq $eopManageAsAppRoleId -and $_.value -eq 'Exchange.ManageAsApp' -and
        $_.isEnabled -and $_.allowedMemberTypes -contains 'Application'
    })
    if ($permissions.Count -ne 1) { throw 'The documented SCC Exchange.ManageAsApp application permission was not found. No alternative/broader permission will be granted.' }
    $requiredAccess = @(@{
        resourceAppId = $eopResourceAppId
        resourceAccess = @(@{ id = $eopManageAsAppRoleId; type = 'Role' })
    })
    $exchangeResource = $null
    if ($IncludeExchangeBootstrapPermission) {
        $exchangeResult = Invoke-CachedAzureRequest -Method GET -Uri (
            'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId%20eq%20%27' +
            $exchangeResourceAppId + '%27&$select=id,appId,appRoles'
        )
        $exchangeResources = @($exchangeResult.value)
        if ($exchangeResources.Count -ne 1) { throw 'The documented Exchange Online bootstrap resource is missing or ambiguous.' }
        $exchangeResource = $exchangeResources[0]
        $exchangePermissions = @($exchangeResource.appRoles | Where-Object {
            $_.id -ieq $exchangeManageAsAppRoleId -and $_.value -eq 'Exchange.ManageAsApp' -and
            $_.isEnabled -and $_.allowedMemberTypes -contains 'Application'
        })
        if ($exchangePermissions.Count -ne 1) { throw 'The exact documented Exchange bootstrap permission could not be verified.' }
        $requiredAccess += @{
            resourceAppId = $exchangeResourceAppId
            resourceAccess = @(@{ id = $exchangeManageAsAppRoleId; type = 'Role' })
        }
    }

    $now = [DateTimeOffset]::UtcNow
    $Context.DisplayName = 'AgentHarness Purview Setup - ' + [guid]::NewGuid().ToString('N')
    $Context.KeyId = [guid]::NewGuid().ToString()
    if ($UseCertificateAuthentication) {
        $Context.Certificate = New-SelfSignedCertificate -Type Custom -Subject ('CN=' + $Context.DisplayName) `
            -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeySpec Signature `
            -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' -KeyExportPolicy NonExportable `
            -KeyUsage DigitalSignature -CertStoreLocation 'Cert:\CurrentUser\My' `
            -NotBefore $now.AddMinutes(-5).LocalDateTime -NotAfter $now.AddHours(1).LocalDateTime -ErrorAction Stop
        $Context.CertificateStorePath = 'Cert:\CurrentUser\My\' + $Context.Certificate.Thumbprint
    }
    else {
        $Context.SigningKey = [Security.Cryptography.RSA]::Create(2048)
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            ('CN=' + $Context.DisplayName), $Context.SigningKey,
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $Context.Certificate = $request.CreateSelfSigned($now.AddMinutes(-5), $now.AddHours(1))
    }
    if ($Context.Certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
        $Context.Certificate.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow.AddMinutes(30) -or
        $Context.Certificate.NotAfter.ToUniversalTime() -gt [DateTime]::UtcNow.AddMinutes(70)) {
        throw 'The temporary certificate validity does not match its intended one-hour UTC lifetime.'
    }
    $Context.Stage = 'Create owned certificate-backed automation application'
    $app = Invoke-CachedAzureRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body @{
        displayName = $Context.DisplayName
        signInAudience = 'AzureADMyOrg'
        notes = 'Temporary, one-hour AgentHarness app-scoped Purview policy setup. Remove all grants and credentials after this run.'
        requiredResourceAccess = $requiredAccess
        keyCredentials = @(@{
            keyId = $Context.KeyId
            type = 'AsymmetricX509Cert'
            usage = 'Verify'
            customKeyIdentifier = [Convert]::ToBase64String($Context.Certificate.GetCertHash())
            key = [Convert]::ToBase64String($Context.Certificate.RawData)
            startDateTime = $Context.Certificate.NotBefore.ToUniversalTime().ToString('o')
            endDateTime = $Context.Certificate.NotAfter.ToUniversalTime().ToString('o')
        })
    }
    $Context.AppObjectId = [string]$app.id
    $Context.ClientId = [string]$app.appId
    $Context.Stage = 'Create owned automation service principal'
    $sp = Invoke-CachedAzureRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body @{
        appId = $Context.ClientId
        accountEnabled = $true
        appRoleAssignmentRequired = $true
    }
    $Context.ServicePrincipalId = [string]$sp.id
    $Context.Stage = 'Grant documented EOP application permission'
    $grant = Invoke-CachedAzureRequest -Method POST -Uri (
        'https://graph.microsoft.com/v1.0/servicePrincipals/' + $resource.id + '/appRoleAssignedTo'
    ) -Body @{ principalId = $sp.id; resourceId = $resource.id; appRoleId = $eopManageAsAppRoleId }
    $Context.AppRoleAssignmentId = [string]$grant.id
    if ($IncludeExchangeBootstrapPermission) {
        $exchangeGrant = Invoke-CachedAzureRequest -Method POST -Uri (
            'https://graph.microsoft.com/v1.0/servicePrincipals/' + $exchangeResource.id + '/appRoleAssignedTo'
        ) -Body @{ principalId = $sp.id; resourceId = $exchangeResource.id; appRoleId = $exchangeManageAsAppRoleId }
        $Context.ExchangeAppRoleAssignmentId = [string]$exchangeGrant.id
        $exchangeReadBack = Invoke-CachedAzureRequest -Method GET -Uri (
            'https://graph.microsoft.com/v1.0/servicePrincipals/' + $Context.ServicePrincipalId +
            '/appRoleAssignments/' + $Context.ExchangeAppRoleAssignmentId
        )
        if ($exchangeReadBack.principalId -ine $sp.id -or $exchangeReadBack.resourceId -ine $exchangeResource.id -or
            $exchangeReadBack.appRoleId -ine $exchangeManageAsAppRoleId) {
            throw 'The temporary Exchange bootstrap permission did not match read-back.'
        }
        $Context.ExchangeBootstrapGrantVerified = $true
    }
    $Context.Stage = 'Assign temporary Compliance Administrator'
    $role = Invoke-CachedAzureRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -Body @{
        principalId = $sp.id
        roleDefinitionId = $complianceAdministratorRoleId
        directoryScopeId = '/'
    }
    $Context.DirectoryRoleAssignmentId = [string]$role.id
    $grantReadBack = Invoke-CachedAzureRequest -Method GET -Uri (
        'https://graph.microsoft.com/v1.0/servicePrincipals/' + $Context.ServicePrincipalId + '/appRoleAssignments/' + $Context.AppRoleAssignmentId
    )
    $roleReadBack = Invoke-CachedAzureRequest -Method GET -Uri (
        'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/' + $Context.DirectoryRoleAssignmentId
    )
    if ($grantReadBack.principalId -ine $Context.ServicePrincipalId -or $grantReadBack.resourceId -ine $resource.id -or
        $grantReadBack.appRoleId -ine $eopManageAsAppRoleId -or $roleReadBack.principalId -ine $Context.ServicePrincipalId -or
        $roleReadBack.roleDefinitionId -ine $complianceAdministratorRoleId -or $roleReadBack.directoryScopeId -ne '/') {
        throw 'The exact temporary EOP permission and Compliance Administrator grants could not be verified.'
    }
    $Context.ApiGrantVerified = $true
    $Context.DirectoryRoleVerified = $true
    Write-Information -InformationAction Continue -MessageData (
        "Owned temporary SCC app $($Context.ClientId), SP $($Context.ServicePrincipalId): documented EOP management permission, Exchange bootstrap=$IncludeExchangeBootstrapPermission, and Compliance Administrator; certificate expires within one hour."
    )
    Start-Sleep -Seconds 30

    if ($UseCertificateAuthentication) { return $null }

    $Context.Stage = 'Acquire application-only SCC token'
    $tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $issuedAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = @{ alg = 'PS256'; typ = 'JWT'; 'x5t#S256' = ConvertTo-Base64Url $Context.Certificate.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256) }
    $payload = @{
        aud = $tokenEndpoint
        iss = $Context.ClientId
        sub = $Context.ClientId
        jti = [guid]::NewGuid().ToString()
        iat = $issuedAt
        nbf = $issuedAt - 30
        exp = $issuedAt + 300
    }
    $unsigned = (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json -Compress)))) + '.' +
        (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))))
    $signature = $Context.SigningKey.SignData(
        [Text.Encoding]::ASCII.GetBytes($unsigned), [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pss
    )
    $assertion = $unsigned + '.' + (ConvertTo-Base64Url $signature)
    $response = $null
    try {
        $response = Invoke-RestMethod -Method POST -Uri $tokenEndpoint -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -ErrorAction Stop -Body @{
            client_id = $Context.ClientId
            grant_type = 'client_credentials'
            # Preserve the trailing slash in the SCC resource identifier.
            scope = $sccResource + '/.default'
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion = $assertion
        }
        return [string]$response.access_token
    }
    finally {
        $assertion = $null
        $response = $null
        $signature = $null
        $unsigned = $null
    }
}

function Test-OwnedGraphObjectAbsent {
    param([string]$Uri)
    try {
        $null = Invoke-CachedAzureRequest -Method GET -Uri $Uri
        return $false
    }
    catch {
        $response = Get-PolicyField $_.Exception 'Response'
        if ($null -ne $response -and [int](Get-PolicyField $response 'StatusCode') -eq 404) { return $true }
        throw
    }
}

function Remove-EphemeralSccIdentity {
    param([hashtable]$Context)
    if ($Context.Count -eq 0) { return }
    $failures = [System.Collections.Generic.List[string]]::new()
    try {
        if (-not $Context.ContainsKey('AppObjectId') -and $Context.ContainsKey('DisplayName')) {
            $filter = [uri]::EscapeDataString("displayName eq '$($Context.DisplayName)'")
            $recovery = Invoke-CachedAzureRequest -Method GET -Uri (
                'https://graph.microsoft.com/v1.0/applications?$filter=' + $filter + '&$select=id,appId,keyCredentials'
            )
            $ownedApps = @($recovery.value | Where-Object { $Context.KeyId -in @($_.keyCredentials.keyId) })
            if ($ownedApps.Count -gt 1) { throw 'Ambiguous owned-application recovery; no unrelated app will be removed.' }
            if ($ownedApps.Count -eq 1) {
                $Context.AppObjectId = [string]$ownedApps[0].id
                $Context.ClientId = [string]$ownedApps[0].appId
            }
        }
        if (-not $Context.ContainsKey('ServicePrincipalId') -and $Context.ContainsKey('ClientId')) {
            $recovery = Invoke-CachedAzureRequest -Method GET -Uri (
                'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId%20eq%20%27' + $Context.ClientId + '%27&$select=id'
            )
            if (@($recovery.value).Count -eq 1) { $Context.ServicePrincipalId = [string]$recovery.value[0].id }
        }
    }
    catch { $failures.Add('Recover owned IDs: ' + (Get-SafeFailure $_)) }

    $steps = @(
        @{ Name = 'Disable owned SP'; Run = {
            if ($Context.ContainsKey('ServicePrincipalId')) {
                Invoke-CachedAzureRequest -Method PATCH -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $Context.ServicePrincipalId) -Body @{ accountEnabled = $false } | Out-Null
            }
        } }
        @{ Name = 'Remove owned directory roles'; Run = {
            if ($Context.ContainsKey('ServicePrincipalId')) {
                $roles = Invoke-CachedAzureRequest -Method GET -Uri (
                    'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20%27' + $Context.ServicePrincipalId + '%27'
                )
                foreach ($assignment in $roles.value) {
                    Invoke-CachedAzureRequest -Method DELETE -Uri ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/' + $assignment.id) | Out-Null
                }
            }
        } }
        @{ Name = 'Remove owned API grants'; Run = {
            if ($Context.ContainsKey('ServicePrincipalId')) {
                $grants = Invoke-CachedAzureRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $Context.ServicePrincipalId + '/appRoleAssignments')
                foreach ($assignment in $grants.value) {
                    Invoke-CachedAzureRequest -Method DELETE -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $Context.ServicePrincipalId + '/appRoleAssignments/' + $assignment.id) | Out-Null
                }
            }
        } }
        @{ Name = 'Clear owned app credentials'; Run = {
            if ($Context.ContainsKey('AppObjectId')) {
                Invoke-CachedAzureRequest -Method PATCH -Uri ('https://graph.microsoft.com/v1.0/applications/' + $Context.AppObjectId) -Body @{ keyCredentials = @(); passwordCredentials = @() } | Out-Null
            }
        } }
        @{ Name = 'Delete owned SP'; Run = {
            if ($Context.ContainsKey('ServicePrincipalId')) {
                Invoke-CachedAzureRequest -Method DELETE -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $Context.ServicePrincipalId) | Out-Null
            }
        } }
        @{ Name = 'Delete owned application'; Run = {
            if ($Context.ContainsKey('AppObjectId')) {
                Invoke-CachedAzureRequest -Method DELETE -Uri ('https://graph.microsoft.com/v1.0/applications/' + $Context.AppObjectId) | Out-Null
            }
        } }
    )
    try {
        foreach ($step in $steps) {
            try { & $step.Run }
            catch { $failures.Add($step.Name + ': ' + (Get-SafeFailure $_)) }
        }
        if ($Context.ContainsKey('DirectoryRoleAssignmentId') -and
            -not (Test-OwnedGraphObjectAbsent ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/' + $Context.DirectoryRoleAssignmentId))) {
            $failures.Add('Owned directory role assignment still exists.')
        }
        if ($Context.ContainsKey('ServicePrincipalId') -and
            -not (Test-OwnedGraphObjectAbsent ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $Context.ServicePrincipalId))) {
            $failures.Add('Owned service principal is still active in the directory.')
        }
        if ($Context.ContainsKey('AppObjectId') -and
            -not (Test-OwnedGraphObjectAbsent ('https://graph.microsoft.com/v1.0/applications/' + $Context.AppObjectId))) {
            $failures.Add('Owned application is still active in the directory.')
        }
    }
    catch { $failures.Add('Cleanup read-back: ' + (Get-SafeFailure $_)) }
    finally {
        if ($Context.ContainsKey('Certificate')) { $Context.Certificate.Dispose() }
        if ($Context.ContainsKey('SigningKey')) { $Context.SigningKey.Dispose() }
        if ($Context.ContainsKey('CertificateStorePath')) {
            try { Remove-Item -LiteralPath $Context.CertificateStorePath -DeleteKey -Force -ErrorAction Stop }
            catch { $failures.Add('Remove owned certificate and key: ' + (Get-SafeFailure $_)) }
        }
    }
    if ($failures.Count -gt 0) {
        throw "Temporary SCC identity cleanup requires attention (app $($Context['AppObjectId']), SP $($Context['ServicePrincipalId'])): $($failures -join '; ')"
    }
    if ($Context.ContainsKey('AppObjectId')) {
        Write-Information -InformationAction Continue -MessageData (
            "Owned SCC automation identity cleanup verified (app $($Context['AppObjectId']), SP $($Context['ServicePrincipalId'])): grants removed, credentials cleared, active objects deleted, in-memory keys disposed."
        )
    }
    else {
        Write-Information -InformationAction Continue -MessageData 'No owned automation application was created; in-memory key material was disposed.'
    }
}

$locations = @(
    [ordered]@{
        Workload = 'Applications'
        Location = $applicationId
        LocationDisplayName = $applicationName
        LocationSource = 'Entra'
        LocationType = 'Individual'
        Inclusions = @(@{ Type = 'Tenant'; Identity = 'All' })
    }
)
$scenarioConfig = [ordered]@{
    Activities = @('UploadText', 'DownloadText')
    EnforcementPlanes = @('Application')
    SensitiveTypeIds = @('All')
    IsIngestionEnabled = $true
}
$locationsJson = ConvertTo-Json -InputObject $locations -Depth 10 -Compress
$scenarioJson = ConvertTo-Json -InputObject $scenarioConfig -Depth 10 -Compress
if ($Action -eq 'Preview') {
    [pscustomobject]@{
        Action = 'Preview'
        TenantId = $tenantId
        ApplicationId = $applicationId
        PolicySet = $PolicySet
        DlpPolicy = @{ Name = $policyName; Mode = 'Enable'; EnforcementPlanes = @('Application'); Locations = $locations }
        DlpRule = @{
            Name = $ruleName
            Policy = $policyName
            ContentContainsSensitiveInformation = @{ Name = 'credit card number' }
            GenerateAlert = $true
            GenerateIncidentReport = @('siteadmin')
            NotifyUser = @($administratorUpn)
            RestrictAccess = @(@{ setting = 'UploadText'; value = 'Block' })
        }
        CollectionPolicy = if ($PolicySet -eq 'All') { @{ Name = $collectionName; FeatureScenario = 'KnowYourData'; Mode = 'Enable'; Locations = $locations; ScenarioConfig = $scenarioConfig } } else { $null }
        Prerequisites = if ($PolicySet -eq 'All') { 'Confirm DLP entitlement/authority, existing approved PAYG billing, Audit, and DSPM onboarding before Apply.' } else { 'Confirm DLP entitlement and administrative authority. DlpOnly does not activate collection, Audit, or billing.' }
    }
    return
}

if ($Action -eq 'Apply' -and -not $PrerequisitesConfirmed) {
    throw 'Apply requires -PrerequisitesConfirmed: DlpOnly requires DLP entitlement and administrative authority; All additionally requires existing approved PAYG billing, Audit, and DSPM onboarding. This script does not activate tenant-wide prerequisites or Azure billing.'
}
if ($PSCmdlet.ParameterSetName -eq 'Ephemeral' -and -not $EphemeralAppOnly) {
    throw 'EphemeralAppOnly must be explicitly enabled before creating temporary directory objects.'
}
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement | Where-Object { $_.Version -ge [version]'3.10.1' })) {
    throw 'ExchangeOnlineManagement 3.10.1 or later is required. Install the missing dependency in CurrentUser scope before retrying. This script does not install modules or authenticate interactively.'
}
Import-Module ExchangeOnlineManagement -MinimumVersion 3.10.1 -ErrorAction Stop

$ownedPrefix = 'AgentHarnessPv' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$priorConnectionIds = @(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { [string]$_.ConnectionId })
$created = [System.Collections.Generic.List[string]]::new()
$plainToken = $null
$tokenResult = $null
$automation = @{}
$operationFailure = $null
try {
    if ($PSCmdlet.ParameterSetName -eq 'Existing') {
        $connections = @(Get-ConnectionInformation -ConnectionId $ConnectionId.ToString() -ErrorAction Stop)
    }
    else {
        # Disconnect-ExchangeOnline can also close legacy remote sessions, even with ConnectionId.
        if (@(Get-PSSession -ErrorAction Stop).Count -ne 0) {
            throw 'Existing remote PowerShell sessions detected. Use -ConnectionId for an existing SCC REST session or run in a separate PowerShell process.'
        }
        if ($PSCmdlet.ParameterSetName -eq 'Ephemeral') {
            . (Join-Path $PSScriptRoot '..\infra\AzureSession.ps1')
            if ($null -ne $GraphAccessToken) {
                $graphToken = ConvertFrom-SecureString -SecureString $GraphAccessToken -AsPlainText
                $graphPayload = $graphToken.Split('.')[1].Replace('-', '+').Replace('_', '/')
                $graphPayload = $graphPayload.PadRight($graphPayload.Length + ((4 - $graphPayload.Length % 4) % 4), '=')
                $graphClaims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($graphPayload)) | ConvertFrom-Json -ErrorAction Stop
                if ($graphClaims.tid -ine $tenantId -or $graphClaims.oid -ine $administratorObjectId -or
                    [string]$graphClaims.aud -notin @('00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com', 'https://graph.microsoft.com/') -or
                    [long]$graphClaims.exp -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) {
                    throw 'The supplied Graph token does not match the expected administrator, tenant, resource, or lifetime.'
                }
                $script:TokenCache['https://graph.microsoft.com/'] = $graphToken
                $graphToken = $null
            }
            Initialize-CachedAzureSession -TenantId $tenantId -SubscriptionId $subscriptionId `
                -AdministratorObjectId $administratorObjectId -AdministratorUpn $administratorUpn | Out-Null
            $plainToken = New-EphemeralSccToken $automation
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Token') {
            $plainToken = ConvertFrom-SecureString -SecureString $AccessToken -AsPlainText
        }
        else {
            . (Join-Path $PSScriptRoot '..\infra\AzureSession.ps1')
            Initialize-CachedAzureSession -TenantId $tenantId -SubscriptionId $subscriptionId `
                -AdministratorObjectId $administratorObjectId -AdministratorUpn $administratorUpn | Out-Null
            $null = Get-Command az -ErrorAction Stop
            $PSNativeCommandUseErrorActionPreference = $false
            $tokenResult = & az account get-access-token --subscription $subscriptionId --tenant $tenantId --resource $sccResource --query accessToken --output tsv --only-show-errors 2>&1
            if ($LASTEXITCODE -ne 0) {
                $code = [regex]::Match(($tokenResult -join "`n"), 'AADSTS\d+').Value
                throw "Cached Azure CLI SCC token acquisition failed (exit $LASTEXITCODE; $code). No interactive fallback or additional consent attempt was made."
            }
            $plainToken = ($tokenResult -join '').Trim()
        }
        $certificateMode = $PSCmdlet.ParameterSetName -eq 'Ephemeral' -and $UseCertificateAuthentication
        if (-not $certificateMode) {
        if ([string]::IsNullOrWhiteSpace($plainToken)) { throw 'No SCC access token was supplied or obtained from the Azure CLI cache.' }
        try {
            $payload = $plainToken.Split('.')[1].Replace('-', '+').Replace('_', '/')
            $payload = $payload.PadRight($payload.Length + ((4 - $payload.Length % 4) % 4), '=')
            $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json -ErrorAction Stop
        }
        catch { throw 'The supplied SCC token could not be inspected. Token contents have not been logged.' }
        $isDelegated = -not [string]::IsNullOrWhiteSpace([string](Get-PolicyField $claims 'scp'))
        $audience = ([string]$claims.aud).TrimEnd('/')
        if ($PSCmdlet.ParameterSetName -eq 'Ephemeral') {
            Write-Information -InformationAction Continue -MessageData (
                "Owned application-token metadata: audience=$audience; delegated=$isDelegated; Exchange.ManageAsApp=$(@(Get-PolicyField $claims 'roles') -contains 'Exchange.ManageAsApp'); ComplianceAdministratorClaim=$(@(Get-PolicyField $claims 'wids') -contains $complianceAdministratorRoleId)."
            )
        }
        $validAudience = $audience -ieq $sccResource.TrimEnd('/') -or (-not $isDelegated -and $audience -ieq $eopResourceAppId)
        if ($claims.tid -ine $tenantId -or -not $validAudience -or
            [long]$claims.exp -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) {
            throw 'The SCC token has a different tenant/audience or has expired. No connection or policy change was attempted.'
        }
        if ($PSCmdlet.ParameterSetName -eq 'Ephemeral' -and
            ($isDelegated -or -not $automation.ApiGrantVerified -or -not $automation.DirectoryRoleVerified -or
             ([string](Get-PolicyField $claims 'appid') -ine $automation.ClientId -and
              [string](Get-PolicyField $claims 'azp') -ine $automation.ClientId))) {
            throw 'The application token or exact temporary EOP/Compliance Administrator grant read-back did not match the owned identity. No SCC connection was attempted.'
        }
        }
        $nouns = @('DlpCompliancePolicy', 'DlpComplianceRule')
        if ($PolicySet -eq 'All') { $nouns += 'FeatureConfiguration' }
        $commandNames = @($nouns | ForEach-Object { "Get-$_"; if ($Action -eq 'Apply') { "New-$_" } })
        $moduleBasePath = Join-Path $PSScriptRoot '..\artifacts'
        if ($PSCmdlet.ParameterSetName -eq 'Ephemeral') { $automation.Stage = 'Connect to SCC with application-only token' }
        $connectionParameters = @{
            ShowBanner = $false; Prefix = $ownedPrefix; CommandName = $commandNames
            EXOModuleBasePath = $moduleBasePath; ErrorAction = 'Stop'
        }
        if ($certificateMode) {
            $connectionParameters.AppId = $automation.ClientId
            $connectionParameters.Organization = $organization
            $connectionParameters.CertificateThumbprint = $automation.Certificate.Thumbprint
        }
        else {
            $connectionParameters.AccessToken = $plainToken
            $tokenBinding = if ($PSCmdlet.ParameterSetName -eq 'Ephemeral') {
                @{ Organization = $organization; AppId = $automation.ClientId }
            }
            else { Get-SccTokenBinding $claims }
            foreach ($key in $tokenBinding.Keys) { $connectionParameters[$key] = $tokenBinding[$key] }
        }
        Connect-IPPSSession @connectionParameters | Out-Null
        $connections = @(Get-ConnectionInformation -ModulePrefix $ownedPrefix -ErrorAction Stop)
    }
    $plainToken = $null
    $tokenResult = $null
    if ($connections.Count -ne 1) { throw 'Exactly one unambiguous SCC REST connection is required.' }
    $connection = $connections[0]
    if ([string]$connection.TenantID -ine $tenantId -or $connection.State -ine 'Connected' -or
        [string]$connection.IsEopSession -ine 'True') {
        throw 'The selected connection is not an active SCC REST connection in the harness tenant.'
    }
    if ($PSCmdlet.ParameterSetName -eq 'Ephemeral') { $automation.Stage = 'Read/apply exact harness-scoped policy configuration' }
    $prefix = [string]$connection.ModulePrefix
    $samePrefixConnections = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object {
        $_.State -ieq 'Connected' -and [string]$_.ModulePrefix -ieq $prefix
    })
    if ($samePrefixConnections.Count -ne 1) { throw 'The SCC command prefix is shared by other connections. Refusing ambiguous command routing.' }
    $commands = @{}
    $nouns = @('DlpCompliancePolicy', 'DlpComplianceRule')
    if ($PolicySet -eq 'All') { $nouns += 'FeatureConfiguration' }
    foreach ($noun in $nouns) {
        foreach ($verb in $(if ($Action -eq 'Apply') { @('Get', 'New') } else { @('Get') })) {
            $name = "$verb-$prefix$noun"
            $commands["$verb$noun"] = Get-Command -Name $name -ErrorAction Stop
        }
    }

    # Filter exact names: these Get cmdlets can return every object for an unknown identity.
    $policy = Get-ExactNamedPolicy @(& $commands.GetDlpCompliancePolicy -ErrorAction Stop) $policyName
    $rule = Get-ExactNamedPolicy @(& $commands.GetDlpComplianceRule -ErrorAction Stop) $ruleName
    $collection = $null
    if ($PolicySet -eq 'All') {
        $collection = Get-ExactNamedPolicy @(& $commands.GetFeatureConfiguration -FeatureScenario KnowYourData -ErrorAction Stop) $collectionName
    }
    if ($null -ne $policy) { Assert-HarnessDlpPolicy $policy }
    if ($null -ne $rule) {
        if ($null -eq $policy) { throw "Rule '$ruleName' already exists without the expected policy. Refusing a name collision." }
        $policyRule = Get-ExactNamedPolicy @(& $commands.GetDlpComplianceRule -Policy $policyName -ErrorAction Stop) $ruleName
        if ($null -eq $policyRule) { throw "Rule '$ruleName' belongs to another policy. No objects will be changed." }
        Assert-HarnessDlpRule $policyRule
    }
    if ($null -ne $collection) { Assert-HarnessCollection $collection }
    if ($Action -eq 'Verify' -and ($null -eq $policy -or $null -eq $rule -or ($PolicySet -eq 'All' -and $null -eq $collection))) {
        throw "The expected app DLP policy and blocking rule must exist; All also requires collection. Verify made no policy changes."
    }
    if ($null -eq $policy) {
        & $commands.NewDlpCompliancePolicy -Name $policyName -Mode Enable -Locations $locationsJson `
            -EnforcementPlanes @('Application') -Confirm:$false -ErrorAction Stop | Out-Null
        $created.Add($policyName)
    }
    $policy = Get-ExactNamedPolicy @(& $commands.GetDlpCompliancePolicy -Identity $policyName -ErrorAction Stop) $policyName
    if ($null -eq $policy) { throw 'DLP policy read-back was missing. No broad-scope fallback or rollback will be attempted.' }
    Assert-HarnessDlpPolicy $policy
    if ($null -eq $rule) {
        & $commands.NewDlpComplianceRule -Name $ruleName -Policy $policyName `
            -ContentContainsSensitiveInformation @{ Name = 'credit card number' } -GenerateAlert $true `
            -GenerateIncidentReport @('siteadmin') -NotifyUser @($administratorUpn) `
            -RestrictAccess @(@{ setting = 'UploadText'; value = 'Block' }) -Confirm:$false -ErrorAction Stop | Out-Null
        $created.Add($ruleName)
    }
    $rule = Get-ExactNamedPolicy @(& $commands.GetDlpComplianceRule -Policy $policyName -ErrorAction Stop) $ruleName
    if ($null -eq $rule) { throw 'The blocking rule was not found in the harness policy during read-back.' }
    Assert-HarnessDlpRule $rule
    if ($PolicySet -eq 'All') {
        if ($null -eq $collection) {
            & $commands.NewFeatureConfiguration -FeatureScenario KnowYourData -Name $collectionName -Mode Enable `
                -ScenarioConfig $scenarioJson -Locations $locationsJson -Confirm:$false -ErrorAction Stop | Out-Null
            $created.Add($collectionName)
        }
        $collection = Get-ExactNamedPolicy @(& $commands.GetFeatureConfiguration -FeatureScenario KnowYourData -Identity $collectionName -ErrorAction Stop) $collectionName
        if ($null -eq $collection) { throw 'App-scoped collection policy read-back was missing. No all-app fallback will be attempted.' }
        Assert-HarnessCollection $collection
    }
    [pscustomobject]@{
        Status = 'ConfigurationReadBackVerified'
        VerifiedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        TenantId = $tenantId
        ApplicationId = $applicationId
        PolicySet = $PolicySet
        DlpPolicy = $policyName
        DlpPolicyId = [string](Get-PolicyField $policy 'Guid')
        DlpRule = $ruleName
        DlpRuleId = [string](Get-PolicyField $rule 'Guid')
        UploadText = 'Block'
        CollectionPolicy = if ($PolicySet -eq 'All') { $collectionName } else { $null }
        CollectionActivities = if ($PolicySet -eq 'All') { @('UploadText', 'DownloadText') } else { @() }
        IngestionEnabled = if ($PolicySet -eq 'All') { $true } else { $null }
        CreatedObjects = $created.ToArray()
        RuntimeInlinePolicyVerified = $false
        AuditActivationVerified = $false
        Note = 'Configuration read-back is not runtime inline-DLP, Audit, eDiscovery, CC, IRM, or Defender verification. Follow docs\GOVERNANCE.md.'
    }
}
catch {
    $safeFailure = Get-SafeFailure $_
    if ($automation.ContainsKey('Stage')) { $safeFailure = "$($automation.Stage): $safeFailure" }
    if ($created.Count -gt 0) {
        Write-Warning "Partial setup: created $($created -join '; '). Objects were not deleted or weakened; inspect them and rerun after resolving the failure."
    }
    $operationFailure = "Purview $Action failed: $safeFailure No interactive authentication or broad-scope fallback was attempted."
    throw $operationFailure
}
finally {
    $plainToken = $null
    $tokenResult = $null
    $AccessToken = $null
    $GraphAccessToken = $null
    try {
        $ownedConnections = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object {
            [string]$_.ModulePrefix -eq $ownedPrefix -and [string]$_.ConnectionId -notin $priorConnectionIds
        })
        if ($ownedConnections.Count -gt 0) {
            if (@(Get-PSSession -ErrorAction Stop).Count -ne 0) {
                Write-Warning 'An unrelated remote session appeared. Owned SCC REST connections were left open rather than risk disconnecting unrelated sessions.'
            }
            else {
                foreach ($owned in $ownedConnections) {
                    Disconnect-ExchangeOnline -ConnectionId $owned.ConnectionId -Confirm:$false -ErrorAction Stop
                }
            }
        }
    }
    finally {
        if ($PSCmdlet.ParameterSetName -eq 'Ephemeral') {
            try { Remove-EphemeralSccIdentity $automation }
            catch {
                $cleanupFailure = Get-SafeFailure $_
                if ($operationFailure) { throw "$operationFailure Cleanup: $cleanupFailure" }
                throw $cleanupFailure
            }
        }
    }
}
