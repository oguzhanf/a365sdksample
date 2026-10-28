Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:TokenCache = @{}
$script:AzureSessionContext = $null

function Assert-CachedAzureSubscription {
    param([string]$SubscriptionId, [string]$TenantId)
    foreach ($value in @($SubscriptionId,$TenantId)) {
        if ($value -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -or [guid]$value -eq [guid]::Empty) {
            throw 'Supply explicit, nonempty SubscriptionId and TenantId GUIDs. No default subscription or name match will be used.'
        }
    }
    $json = & az account list --all --output json --only-show-errors 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'The cached Azure CLI session is unavailable. No interactive login was attempted.' }
    try { $accounts = @($json | ConvertFrom-Json) }
    catch { throw 'The cached subscription list could not be read.' }
    $selected = @($accounts | Where-Object { $_.id -eq $SubscriptionId -and $_.tenantId -eq $TenantId -and $_.state -eq 'Enabled' })
    if ($selected.Count -ne 1) { throw 'The explicit subscription is not enabled and accessible in the configured tenant.' }
    return $selected[0]
}

function Initialize-CachedAzureSession {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')][string]$AdministratorObjectId,
        [string]$AdministratorUpn
    )
    $previous = $script:AzureSessionContext
    $script:AzureSessionContext = $null
    if ($previous -and ($previous.TenantId -ne $TenantId -or $previous.SubscriptionId -ne $SubscriptionId -or
        $previous.AdministratorObjectId -ne $AdministratorObjectId)) {
        $script:TokenCache.Clear()
    }
    if ([guid]$AdministratorObjectId -eq [guid]::Empty) { throw 'A nonempty configured administrator object ID is required.' }
    $selected = Assert-CachedAzureSubscription -SubscriptionId $SubscriptionId -TenantId $TenantId
    $script:AzureSessionContext = @{
        TenantId=$TenantId;SubscriptionId=$SubscriptionId;AdministratorObjectId=$AdministratorObjectId;Verified=$false
    }
    try {
        $token = Get-CachedAzureToken -Resource 'https://graph.microsoft.com/'
        $administrator = Invoke-RestMethod -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName' `
            -Headers @{Authorization="Bearer $token";'OData-Version'='4.0'} -TimeoutSec 90 -MaximumRedirection 0
        if ($administrator.id -ne $AdministratorObjectId -or
            ($AdministratorUpn -and $administrator.userPrincipalName -ne $AdministratorUpn)) {
            throw 'The cached account is not the configured administrator.'
        }
        $script:AzureSessionContext.Verified = $true
    } catch {
        $script:AzureSessionContext = $null
        $script:TokenCache.Clear()
        throw 'Cached authentication did not verify the configured tenant and administrator. No interactive authentication was attempted.'
    } finally { $token=$null }
    return $selected
}

function Get-CachedAzureToken {
    param([Parameter(Mandatory)][ValidateSet('https://graph.microsoft.com/', 'https://management.azure.com/', 'https://vault.azure.net', 'https://storage.azure.com/')][string]$Resource)
    if (!$script:AzureSessionContext) { throw 'Initialize-CachedAzureSession with an explicit tenant, subscription, and administrator before requesting tokens.' }
    $wasCached = $script:TokenCache.ContainsKey($Resource)
    if (!$wasCached) {
        $token = & az account get-access-token --subscription $script:AzureSessionContext.SubscriptionId `
            --tenant $script:AzureSessionContext.TenantId --resource $Resource --query accessToken --output tsv --only-show-errors 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
            throw "The cached Azure session cannot obtain a token for $Resource. No interactive authentication was attempted."
        }
        $script:TokenCache[$Resource] = $token.Trim()
    }
    try {
        $parts = $script:TokenCache[$Resource].Split('.')
        if ($parts.Count -ne 3) { throw 'Unreadable cached access token.' }
        $payload = $parts[1].Replace('-','+').Replace('_','/')
        $payload = $payload.PadRight($payload.Length + ((4 - $payload.Length % 4) % 4),'=')
        $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
        $audiences = switch ($Resource) {
            'https://graph.microsoft.com/' { @('00000003-0000-0000-c000-000000000000','https://graph.microsoft.com','https://graph.microsoft.com/') }
            'https://management.azure.com/' { @('https://management.azure.com','https://management.azure.com/','https://management.core.windows.net','https://management.core.windows.net/') }
            'https://vault.azure.net' { @('https://vault.azure.net','https://vault.azure.net/') }
            'https://storage.azure.com/' { @('https://storage.azure.com','https://storage.azure.com/') }
        }
        if ($claims.tid -ne $script:AzureSessionContext.TenantId -or $claims.oid -ne $script:AzureSessionContext.AdministratorObjectId -or
            $claims.aud -notin $audiences) {
            throw 'The cached token does not match the configured boundary.'
        }
        if ([long]$claims.exp -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) {
            if ($wasCached -and $script:AzureSessionContext.Verified) {
                $script:TokenCache.Remove($Resource)
                return Get-CachedAzureToken -Resource $Resource
            }
            throw 'The cached token has expired.'
        }
    } catch {
        $script:TokenCache.Remove($Resource)
        throw 'The cached access token is expired or does not match the configured tenant, administrator, and resource.'
    } finally { $claims=$null; $payload=$null }
    return $script:TokenCache[$Resource]
}

function Invoke-CachedAzureRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PATCH','PUT','DELETE')][string]$Method,
        [Parameter(Mandatory)][uri]$Uri,
        [object]$Body
    )
    if (!$script:AzureSessionContext -or !$script:AzureSessionContext.Verified) {
        throw 'Initialize-CachedAzureSession must verify the configured administrator before any Azure request.'
    }
    $resource = switch ($Uri.Host) {
        'graph.microsoft.com' { 'https://graph.microsoft.com/' }
        'management.azure.com' { 'https://management.azure.com/' }
        { $_.EndsWith('.vault.azure.net') } { 'https://vault.azure.net' }
        default { throw "Refusing to send an Azure bearer token to $($Uri.Host)." }
    }
    if ($Uri.Scheme -ne 'https' -or $Uri.UserInfo) { throw 'Azure requests require HTTPS without embedded credentials.' }
    $headers = @{ Authorization = "Bearer $(Get-CachedAzureToken -Resource $resource)"; 'OData-Version' = '4.0' }
    $parameters = @{ Method=$Method; Uri=$Uri; Headers=$headers; TimeoutSec=90; MaximumRedirection=0 }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 40 -Compress
    }

    Invoke-RestMethod @parameters
}

function Assert-HttpsOrigin {
    param([Parameter(Mandatory)][uri]$Uri)
    if (!$Uri.IsAbsoluteUri -or $Uri.Scheme -ne 'https' -or $Uri.UserInfo -or $Uri.Query -or
        $Uri.Fragment -or $Uri.AbsolutePath -ne '/') {
        throw 'Supply an absolute HTTPS origin without credentials, paths, query strings, or fragments.'
    }
    return $Uri.AbsoluteUri.TrimEnd('/')
}

function Assert-LocalStatePath {
    param([Parameter(Mandatory)][string]$Path)
    $root = Split-Path $PSScriptRoot
    $fullPath = [IO.Path]::GetFullPath($Path)
    $relative = [IO.Path]::GetRelativePath($root,$fullPath)
    if ($relative -eq '..' -or $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)") -or [IO.Path]::IsPathRooted($relative)) {
        throw 'Local state must stay inside the sample checkout and outside source control.'
    }
    if (Test-Path -LiteralPath (Join-Path $root '.git')) {
        & git -C $root check-ignore --quiet -- $fullPath
        if ($LASTEXITCODE -ne 0) { throw 'The local state path must be ignored by Git; tracked or unignored output is refused.' }
    } elseif (!$relative.StartsWith("artifacts$([IO.Path]::DirectorySeparatorChar)",[StringComparison]::OrdinalIgnoreCase) -and
        $relative -ne (Join-Path 'infra' 'entra-state.json')) {
        throw 'Use the ignored artifacts directory or infra\entra-state.json for local state.'
    }
    return $fullPath
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Path)
    $uri = [uri]("https://graph.microsoft.com/" + $Path.TrimStart('/'))
    $items = [System.Collections.Generic.List[object]]::new()
    do {
        $page = Invoke-CachedAzureRequest -Method GET -Uri $uri
        foreach ($item in $page.value) { $items.Add($item) }
        $next = $page.PSObject.Properties['@odata.nextLink']
        $uri = if ($null -ne $next -and $next.Value) { [uri]$next.Value } else { $null }
        if ($uri -and $uri.Host -ne 'graph.microsoft.com') { throw 'Invalid Graph pagination host.' }
    } while ($uri)
    return $items.ToArray()
}
