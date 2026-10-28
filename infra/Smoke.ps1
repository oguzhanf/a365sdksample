#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$StatePath = 'artifacts\deployment-state.json',
    [string]$EntraStatePath = (Join-Path $PSScriptRoot 'entra-state.json'),
    [switch]$HarnessOnly,
    [string]$EvidencePath = 'artifacts\smoke-results.json',
    [Security.SecureString]$ReaderAccessToken,
    [Security.SecureString]$ApproverAccessToken,
    [Security.SecureString]$NoRoleAccessToken,
    [Security.SecureString]$ExpiredAccessToken,
    [Security.SecureString]$WrongAudienceAccessToken,
    [Security.SecureString]$WrongTenantAccessToken,
    [Security.SecureString]$OtherClientAccessToken
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot)
. (Join-Path $PSScriptRoot 'Deployment.Common.ps1')
$entra = Get-Content -LiteralPath $EntraStatePath -Raw | ConvertFrom-Json
if ((Get-OptionalProperty $entra 'SubscriptionId') -ne $SubscriptionId) { throw 'The explicit subscription does not match the initialized customer configuration.' }
Initialize-CachedAzureSession -TenantId $entra.TenantId -SubscriptionId $SubscriptionId `
    -AdministratorObjectId $entra.AdministratorObjectId -AdministratorUpn $entra.AdministratorUpn | Out-Null
$EvidencePath = Assert-LocalStatePath -Path $EvidencePath
$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if ($state.subscriptionId -ne $SubscriptionId -or (Get-OptionalProperty $state 'tenantId') -ne $entra.TenantId -or
    (Get-OptionalProperty $state 'clientId') -ne $entra.ClientId -or $state.resourceGroup -notmatch '^[A-Za-z0-9._()-]{1,90}$') {
    throw 'State does not belong to the explicitly selected subscription, tenant, and application.'
}
foreach ($field in @('harnessResourceId','keyVaultResourceId','openAiResourceId','appNetworkResourceId','defenderPricingResourceId')) {
    $resourceId = Get-OptionalProperty $state $field
    if (!$resourceId -or !$resourceId.StartsWith("/subscriptions/$SubscriptionId/",[StringComparison]::OrdinalIgnoreCase)) {
        throw 'A saved Azure resource ID is missing or outside the explicitly selected subscription.'
    }
}
$urls = @($state.harnessUrl)
if (!$HarnessOnly) { $urls += $state.graviteeUrl }
foreach ($url in $urls) {
    $uri = [uri]$url
    if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/') { throw 'Smoke checks require real HTTPS origins without credentials, paths or query strings.' }
}
if (([uri]$state.harnessUrl).Host -ne "$($state.harnessName).azurewebsites.net" -or
    $state.harnessResourceId -ne "/subscriptions/$SubscriptionId/resourceGroups/$($state.resourceGroup)/providers/Microsoft.Web/sites/$($state.harnessName)") {
    throw 'The saved canonical harness hostname and resource ID do not agree.'
}
$checks = [Collections.Generic.List[object]]::new()
$clientHandler = [Net.Http.HttpClientHandler]::new()
$clientHandler.AllowAutoRedirect = $false
$client = [Net.Http.HttpClient]::new($clientHandler)
$client.Timeout = [TimeSpan]::FromSeconds(30)

function Send-SmokeRequest {
    param([string]$Method, [string]$Url, [string]$Authorization)
    $attempts = if ($Method -eq 'GET') { 3 } else { 1 }
    for ($attempt=0; $attempt -lt $attempts; $attempt++) {
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Url)
    if ($Authorization) { $request.Headers.TryAddWithoutValidation('Authorization',$Authorization) | Out-Null }
    $request.Headers.TryAddWithoutValidation('X-Requested-With','XMLHttpRequest') | Out-Null
    if ($Method -eq 'POST') { $request.Content = [Net.Http.StringContent]::new('{}',[Text.Encoding]::UTF8,'application/json') }
    try {
        $response = $client.Send($request)
        try {
            return @{status=[int]$response.StatusCode;body=$response.Content.ReadAsStringAsync().GetAwaiter().GetResult();location=if($response.Headers.Location){$response.Headers.Location.OriginalString}else{''}}
        } finally { $response.Dispose() }
    } catch {
        if ($attempt -eq $attempts - 1) { throw 'Verified HTTPS request transport failed after bounded retries; response content was suppressed.' }
        Start-Sleep -Seconds 3
    } finally { $request.Dispose() }
    }
}

function Assert-Status {
    param([string]$Name, [string]$Method, [string]$Url, [int[]]$Expected, [string]$Authorization)
    $response = Send-SmokeRequest -Method $Method -Url $Url -Authorization $Authorization
    if ($response.status -notin $Expected) { throw "$Name failed: HTTP $($response.status); expected $($Expected -join '/'). Response content suppressed." }
    $checks.Add([pscustomobject]@{Check=$Name;Result='Passed';HttpStatus=$response.status})
    return $response
}

function Get-TokenClaims {
    param([string]$Token)
    $parts = $Token.Split('.')
    if ($parts.Count -ne 3) { throw 'Supply an actual delegated Entra access token for a token-matrix case.' }
    $payload = $parts[1].Replace('-','+').Replace('_','/')
    $payload = $payload.PadRight($payload.Length + ((4 - $payload.Length % 4) % 4),'=')
    try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json }
    catch { throw 'A supplied token has an unreadable claims payload.' }
}

function Invoke-DelegatedMatrix {
    param([Security.SecureString]$SecureToken, [ValidateSet('Reader','Approver','NoRole','Expired','WrongAudience','WrongTenant','OtherClient')][string]$Case)
    if ($null -eq $SecureToken) { return }
    $token = [Net.NetworkCredential]::new('', $SecureToken).Password
    try {
        $claims = Get-TokenClaims -Token $token
        $roles = @(Get-OptionalProperty $claims 'roles' @())
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($Case -in @('Reader','Approver','NoRole')) {
            if ($claims.tid -ne $entra.TenantId -or $claims.aud -ne $entra.InternalApiClientId -or $claims.azp -ne $entra.ClientId -or
                @($claims.scp -split ' ') -notcontains 'access_as_user' -or [long]$claims.exp -le $now) {
                throw "$Case requires an unexpired, correctly scoped delegated token from the configured tenant issued to the harness for the internal API."
            }
        }
        $target = "$($state.graviteeUrl)/gateway/internal/purchaseorders"
        $authorization = "Bearer $token"
        switch ($Case) {
            'Reader' {
                if ($roles -notcontains 'InternalApi.Reader' -or $roles -contains 'InternalApi.Approver') { throw 'Reader case needs Reader without Approver.' }
                Assert-Status 'Reader can GET orders' GET $target @(200) $authorization | Out-Null
                Assert-Status 'Reader cannot approve' POST "$target/PO-1001/approve" @(403) $authorization | Out-Null
            }
            'Approver' {
                if ($roles -notcontains 'InternalApi.Approver') { throw 'Approver case needs InternalApi.Approver.' }
                Assert-Status 'Approver can GET orders' GET $target @(200) $authorization | Out-Null
                Assert-Status 'Approver can approve synthetic PO-1001' POST "$target/PO-1001/approve" @(200,204) $authorization | Out-Null
            }
            'NoRole' {
                if (@($roles | Where-Object { $_ -in @('InternalApi.Reader','InternalApi.Approver') }).Count) { throw 'NoRole case needs neither internal API role.' }
                Assert-Status 'No-role token cannot read' GET $target @(403) $authorization | Out-Null
                Assert-Status 'No-role token cannot approve' POST "$target/PO-1001/approve" @(403) $authorization | Out-Null
            }
            'Expired' {
                if ([long]$claims.exp -gt $now) { throw 'Expired case requires an expired real token.' }
                Assert-Status 'Expired token rejected' GET $target @(401,403) $authorization | Out-Null
            }
            'WrongAudience' {
                if ($claims.aud -eq $entra.InternalApiClientId) { throw 'WrongAudience case needs a different audience.' }
                Assert-Status 'Wrong audience rejected' GET $target @(401,403) $authorization | Out-Null
            }
            'WrongTenant' {
                if ($claims.tid -eq $entra.TenantId) { throw 'WrongTenant case needs another tenant.' }
                Assert-Status 'Wrong tenant rejected' GET $target @(401,403) $authorization | Out-Null
            }
            'OtherClient' {
                if ($claims.azp -eq $entra.ClientId) { throw 'OtherClient case needs another authorized-party client ID.' }
                Assert-Status 'Unsubscribed client rejected' GET $target @(401,403) $authorization | Out-Null
            }
        }
        if ($Case -in @('Reader','Approver')) {
            Assert-Status "$Case cannot reach backend health through the gateway" GET "$($state.graviteeUrl)/gateway/internal/healthz" @(403) $authorization | Out-Null
            Assert-Status "$Case cannot use an unlisted method" DELETE $target @(403) $authorization | Out-Null
        }
    } finally { $token=$null; $authorization=$null; $claims=$null }
}

try {
    $healthy = $false
    $healthDeadline = [DateTimeOffset]::UtcNow.AddMinutes(8)
    for ($attempt=0; $attempt -lt 60 -and [DateTimeOffset]::UtcNow -lt $healthDeadline; $attempt++) {
        try {
            $health = Send-SmokeRequest GET "$($state.harnessUrl)/healthz"
            if ($health.status -eq 200 -and ($health.body | ConvertFrom-Json).application -eq 'AgentHarness') { $healthy=$true; break }
        } catch { }
        Start-Sleep -Seconds 10
    }
    if (!$healthy) { throw 'Harness health did not become ready over verified HTTPS.' }
    $checks.Add([pscustomobject]@{Check='Harness HTTPS health';Result='Passed';HttpStatus=200})
    Assert-Status 'Harness API requires sign-in' GET "$($state.harnessUrl)/api/agents" @(401) | Out-Null
    $signIn = Assert-Status 'Harness redirects sign-in to Entra' GET "$($state.harnessUrl)/auth/login" @(302,303)
    $signInUri = [uri]$signIn.location
    $query = [System.Web.HttpUtility]::ParseQueryString($signInUri.Query)
    if ($signInUri.Scheme -ne 'https' -or $signInUri.Host -ne 'login.microsoftonline.com' -or
        $signInUri.AbsolutePath -notlike "/$($entra.TenantId)/*" -or $query['client_id'] -ne $entra.ClientId -or
        $query['redirect_uri'] -ne "$($state.harnessUrl)/signin-oidc") {
        throw 'The sign-in redirect does not target the owned client, tenant, and actual HTTPS callback.'
    }
    if (!$HarnessOnly) {
    $consoleReady = $false
    for ($attempt=0; $attempt -lt 60; $attempt++) {
        try {
            $console = Send-SmokeRequest GET "$($state.graviteeUrl)/"
            if ($console.status -eq 200) { $consoleReady=$true; break }
        } catch { }
        Start-Sleep -Seconds 5
    }
    if (!$consoleReady) { throw 'Gravitee console did not become reachable with publicly trusted HTTPS; check DNS, ACME, and Caddy logs.' }
    Assert-Status 'Gravitee console is reachable' GET "$($state.graviteeUrl)/" @(200) | Out-Null
    $gateway = "$($state.graviteeUrl)/gateway/internal/purchaseorders"
    Assert-Status 'Gateway rejects anonymous requests' GET $gateway @(401,403) | Out-Null
    Assert-Status 'Gateway rejects invalid signatures' GET $gateway @(401,403) 'Bearer deliberately.invalid.token' | Out-Null
    $management = "$($state.graviteeUrl)/management/organizations/DEFAULT/environments/DEFAULT"
    Assert-Status 'Management API rejects anonymous access' GET "$management/apis" @(401,403) | Out-Null
    $defaultCredentials = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('admin:admin'))
    Assert-Status 'Default admin/admin is disabled' GET "$management/apis" @(401,403) $defaultCredentials | Out-Null
    if (Get-OptionalProperty $state 'vmBootstrapVerifiedAt') {
        $checks.Add([pscustomobject]@{Check='Key Vault demo-admin credential verified by successful private VM provisioning';Result='Passed';HttpStatus=200})
    } else {
        $password = (Get-VaultSecretOrNull -VaultUri $state.keyVaultUri -Name gravitee-demo-admin-password).value
        if (!$password -or $password.Length -lt 40) { throw 'The strong Gravitee administrator secret is missing.' }
        $basic = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("demo-admin:$password"))
        try { Assert-Status 'Key Vault demo-admin credential works' GET "$management/apis" @(200) $basic | Out-Null }
        finally { $password=$null; $basic=$null }
    }
    }
    $ai = Invoke-InfraRequest GET "https://management.azure.com$($state.openAiResourceId)?api-version=2025-06-01"
    if ($ai.properties.disableLocalAuth -ne $true) { throw 'Azure OpenAI local API-key authentication is not disabled.' }
    $pricing = Invoke-InfraRequest GET "https://management.azure.com$($state.defenderPricingResourceId)?api-version=2024-01-01"
    if ($pricing.properties.pricingTier -ne 'Standard') { throw 'Defender AI read-back failed.' }
    $assignmentsUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=" + [uri]::EscapeDataString("principalId eq '$($state.harnessPrincipalId)'")
    $assignments = Invoke-InfraRequest GET $assignmentsUri
    $securityReader = @($assignments.value | Where-Object {
        $_.properties.scope -eq "/subscriptions/$SubscriptionId" -and $_.properties.roleDefinitionId.EndsWith('/39bc4728-0917-49c7-9d2c-d95423bc2eb4')
    })
    if (!$securityReader.Count) { throw 'Harness MI lacks subscription-scoped Security Reader for Defender AI visibility.' }
    foreach ($required in @(
        @($state.keyVaultResourceId,'4633458b-17de-408a-b874-0445c86b69e6'),
        @($state.openAiResourceId,'5e0bd9bd-7b93-4f28-af87-19fc36ad61bd'),
        @("/subscriptions/$SubscriptionId/resourceGroups/$($state.resourceGroup)",'acdd72a7-3385-48ef-bd42-f606fba81ae7'))) {
        if (!@($assignments.value | Where-Object {
            $_.properties.scope -eq $required[0] -and $_.properties.roleDefinitionId.EndsWith("/$($required[1])")
        }).Count) { throw 'Harness MI is missing a required existing-vault, existing-model or resource-group role.' }
    }
    $checks.Add([pscustomobject]@{Check='Azure OpenAI MI-only and actual Defender AI pricing/reader assignment';Result='Passed';HttpStatus=200})
    $vault = Invoke-InfraRequest GET "https://management.azure.com$($state.keyVaultResourceId)?api-version=2024-11-01"
    $site = Invoke-InfraRequest GET "https://management.azure.com$($state.harnessResourceId)?api-version=2024-11-01"
    $routing = Get-OptionalProperty $site.properties 'outboundVnetRouting'
    if ($vault.properties.publicNetworkAccess -ne 'Disabled' -or !$vault.properties.enableRbacAuthorization -or
        $site.properties.virtualNetworkSubnetId -ne "$($state.appNetworkResourceId)/subnets/app-integration" -or
        (!(Get-OptionalProperty $routing 'applicationTraffic' $false) -and !(Get-OptionalProperty $routing 'allTraffic' $false))) {
        throw 'The private existing vault, cloned VNet integration, RBAC or outbound application routing is not verified.'
    }
    $checks.Add([pscustomobject]@{Check='Existing private Key Vault, cloned integration subnet and application VNet routing';Result='Passed';HttpStatus=200})
    if (!$HarnessOnly) {
    $nsgId = Get-OptionalProperty $state 'gatewayNetworkSecurityGroupResourceId'
    if (!$nsgId) {
        $vm = Invoke-InfraRequest GET "https://management.azure.com$($state.vmResourceId)?api-version=2024-11-01"
        $nicId = $vm.properties.networkProfile.networkInterfaces[0].id
        $nic = Invoke-InfraRequest GET "https://management.azure.com$nicId`?api-version=2024-05-01"
        $subnetId = $nic.properties.ipConfigurations[0].properties.subnet.id
        $subnet = Invoke-InfraRequest GET "https://management.azure.com$subnetId`?api-version=2024-05-01"
        $nsgId = (Get-OptionalProperty $subnet.properties 'networkSecurityGroup').id
    }
    if (!$nsgId -or !$nsgId.StartsWith("/subscriptions/$SubscriptionId/resourceGroups/$($state.resourceGroup)/",[StringComparison]::OrdinalIgnoreCase)) { throw 'The actual gateway NSG could not be resolved within the explicit target.' }
    $nsg = Invoke-InfraRequest GET "https://management.azure.com$nsgId`?api-version=2024-05-01"
    $allowed = @($nsg.properties.securityRules | Where-Object { $_.properties.direction -eq 'Inbound' -and $_.properties.access -eq 'Allow' })
    if ($allowed.Count -ne 2 -or @($allowed | Where-Object { $_.properties.destinationPortRange -notin @('80','443') }).Count) {
        throw 'Unexpected VM inbound NSG exposure.'
    }
    $checks.Add([pscustomobject]@{Check='VM NSG exposes only HTTP/HTTPS, not SSH or backend/data ports';Result='Passed';HttpStatus=200})
    }
    $reference = $null
    for ($attempt=0; $attempt -lt 12; $attempt++) {
    $references = Invoke-InfraRequest GET "https://management.azure.com$($state.harnessResourceId)/config/configreferences/appsettings?api-version=2024-11-01"
    $referenceItems = @(Get-OptionalProperty $references 'value' @()) | Where-Object {
        ([uri]::UnescapeDataString(($_.id -split '/')[-1])) -eq 'AzureAd__ClientSecret'
    }
    $referenceItems = @($referenceItems)
    $reference = if ($referenceItems.Count -eq 1) { $referenceItems[0].properties } else {
        Get-OptionalProperty (Get-OptionalProperty $references 'properties') 'AzureAd__ClientSecret'
    }
    if ($null -ne $reference -and $reference.status -eq 'Resolved') { break }
    if ($attempt -lt 11) {
        Refresh-AppVaultReferences -ResourceId $state.harnessResourceId
        Start-Sleep -Seconds 10
    }
    }
    if ($null -eq $reference -or $reference.status -ne 'Resolved') { throw 'The App Service OIDC Key Vault reference is not resolved.' }
    $checks.Add([pscustomobject]@{Check='OIDC client secret Key Vault reference';Result='Passed';HttpStatus=200})
    if (!$HarnessOnly) {
    Invoke-DelegatedMatrix $ReaderAccessToken Reader
    Invoke-DelegatedMatrix $ApproverAccessToken Approver
    Invoke-DelegatedMatrix $NoRoleAccessToken NoRole
    Invoke-DelegatedMatrix $ExpiredAccessToken Expired
    Invoke-DelegatedMatrix $WrongAudienceAccessToken WrongAudience
    Invoke-DelegatedMatrix $WrongTenantAccessToken WrongTenant
    Invoke-DelegatedMatrix $OtherClientAccessToken OtherClient
    }
    New-Item -Path (Split-Path $EvidencePath) -ItemType Directory -Force | Out-Null
    @{
        verifiedAt=[DateTimeOffset]::UtcNow.ToString('o')
        subscriptionId=$SubscriptionId
        components=if($HarnessOnly){'HarnessOnly'}else{'Full'}
        harnessUrl=$state.harnessUrl
        loginUrl="$($state.harnessUrl)/auth/login"
        tenantId=$entra.TenantId
        clientId=$entra.ClientId
        callbackUri=$query['redirect_uri']
        keyVaultReferenceStatus=$reference.status
        checks=$checks.ToArray()
        delegatedUserLogin='Not tested; verify a real authorized user sign-in separately'
    } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM
    $checks | Format-Table -AutoSize
    if (!$HarnessOnly -and (!$ReaderAccessToken -or !$ApproverAccessToken -or !$NoRoleAccessToken)) {
        Write-Warning 'Delegated authorization matrix is incomplete: supply real Reader-only, Approver, and no-role tokens as SecureString variables. No user sign-in or authorization success was fabricated.'
    }
} finally { $client.Dispose(); $clientHandler.Dispose() }
