Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'AzureSession.ps1')
$script:VaultControlPlanes = @{}

function Connect-VaultControlPlane {
    param([string]$VaultUri, [string]$ResourceId)
    $uri = [uri]$VaultUri
    $name = $uri.Host.Split('.')[0]
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne "$name.vault.azure.net" -or
        $ResourceId -notmatch ("^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/" + [regex]::Escape($name) + '$')) {
        throw 'The private-vault control-plane scope does not match its HTTPS vault endpoint.'
    }
    $script:VaultControlPlanes[$VaultUri.TrimEnd('/')]=$ResourceId
}

function Get-OptionalProperty {
    param([AllowNull()][object]$Object, [string]$Name, [object]$Default = $null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Assert-ExplicitSubscription {
    param([string]$SubscriptionId, [string]$TenantId)
    return Assert-CachedAzureSubscription -SubscriptionId $SubscriptionId -TenantId $TenantId
}

function Invoke-InfraRequest {
    param(
        [ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
        [uri]$Uri,
        [AllowNull()][object]$Body = $null
    )
    for ($attempt=0; $attempt -lt 2; $attempt++) {
        try {
            return Invoke-CachedAzureRequest -Method $Method -Uri $Uri -Body $Body
        } catch {
            $response = Get-OptionalProperty $_.Exception 'Response'
            $code = Get-OptionalProperty $response 'StatusCode' 0
            if ([int]$code -eq 401 -and $attempt -eq 0) {
                $script:TokenCache.Clear()
                continue
            }
            throw "Azure $Method request failed at $($Uri.Host) (HTTP $code). Sensitive response content was suppressed."
        }
    }
}

function Get-AvailableModels {
    param([string]$SubscriptionId, [string]$Location)
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.CognitiveServices/locations/$Location/models?api-version=2025-06-01"
    $models = [System.Collections.Generic.List[object]]::new()
    do {
        $page = Invoke-InfraRequest -Method GET -Uri $uri
        foreach ($item in $page.value) { $models.Add($item) }
        $uri = Get-OptionalProperty $page 'nextLink'
        if ($uri -and ([uri]$uri).Host -ne 'management.azure.com') { throw 'Invalid model catalog continuation host.' }
    } while ($uri)
    return $models.ToArray()
}

function Assert-AvailableModel {
    param([object[]]$Catalog, [string]$Name, [string]$Version, [string]$Sku, [switch]$RequireChat)
    if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($Version)) {
        throw 'Model name and version must be selected explicitly from the current regional catalog. Use -Mode Models.'
    }
    $matches = @($Catalog | Where-Object {
        $model = Get-OptionalProperty $_ 'model' $_
        $model.name -eq $Name -and $model.version -eq $Version -and $model.format -eq 'OpenAI'
    })
    if (!$matches.Count) { throw "The exact model/version $Name/$Version is not currently offered in this region." }
    $compatible = @($matches | Where-Object {
        $model = Get-OptionalProperty $_ 'model' $_
        $skus = @(Get-OptionalProperty $model 'skus' (Get-OptionalProperty $_ 'skus' @()))
        $skus.Count -gt 0 -and @($skus | Where-Object { $_.name -eq $Sku }).Count -gt 0
    })
    if (!$compatible.Count) { throw "The regional catalog does not advertise SKU $Sku for $Name/$Version." }
    foreach ($item in $compatible) {
        $model = Get-OptionalProperty $item 'model' $item
        $retirement = Get-OptionalProperty (Get-OptionalProperty $model 'deprecation') 'inference'
        if ($retirement -and [DateTimeOffset]::Parse($retirement) -le [DateTimeOffset]::UtcNow) {
            throw "The selected model/version $Name/$Version has passed its advertised inference retirement date."
        }
    }
    if ($RequireChat) {
        $chat = @($compatible | Where-Object {
            $model = Get-OptionalProperty $_ 'model' $_
            [string](Get-OptionalProperty (Get-OptionalProperty $model 'capabilities') 'chatCompletion') -eq 'true'
        })
        if (!$chat.Count) { throw 'The selected model does not advertise chat-completion capability.' }
    }
}

function Enable-HarnessChatModel {
    param(
        [string]$SubscriptionId, [string]$Location, [string]$AccountResourceId, [string]$SiteResourceId,
        [object[]]$Catalog, [string]$PreferredName, [string]$PreferredVersion,
        [string]$Sku, [int]$Capacity, [string]$DeploymentName
    )
    $pending = @{status='Pending';deployment='';reason='No verified model deployment';verifiedAt=[DateTimeOffset]::UtcNow.ToString('o')}
    try {
        $usages = Invoke-InfraRequest GET "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.CognitiveServices/locations/$Location/usages?api-version=2025-06-01"
        $names = @($PreferredName,'gpt-4.1-mini','gpt-4o-mini','gpt-4.1-nano') | Where-Object { $_ } | Select-Object -Unique
        foreach ($name in $names) {
            $versions = @($Catalog | ForEach-Object { Get-OptionalProperty $_ 'model' $_ } | Where-Object {
                $_.name -eq $name -and $_.format -eq 'OpenAI' -and (!$PreferredVersion -or $name -ne $PreferredName -or $_.version -eq $PreferredVersion)
            } | Sort-Object version -Descending -Unique)
            foreach ($model in $versions) {
                try { Assert-AvailableModel -Catalog $Catalog -Name $model.name -Version $model.version -Sku $Sku -RequireChat }
                catch { continue }
                $skus = @($model.skus | Where-Object { $_.name -eq $Sku -and $_.usageName -notmatch 'finetune' })
                $quota = @($usages.value | Where-Object { $_.name.value -in @($skus.usageName) -and ($_.limit - $_.currentValue) -ge $Capacity })
                if (!$quota.Count) { Write-Warning "No verified free quota for $name/$Sku in $Location; trying another advertised model."; continue }
                $uri = "https://management.azure.com$AccountResourceId/deployments/$DeploymentName`?api-version=2025-06-01"
                try {
                    Write-Host "Deploying verified $($model.name)/$($model.version), $Sku capacity $Capacity; quota $($quota[0].currentValue)/$($quota[0].limit)."
                    Invoke-InfraRequest PUT $uri @{
                        sku=@{name=$Sku;capacity=$Capacity}
                        properties=@{model=@{format='OpenAI';name=$model.name;version=$model.version};versionUpgradeOption='NoAutoUpgrade'}
                    } | Out-Null
                    $ready = $false
                    for ($attempt=0; $attempt -lt 24; $attempt++) {
                        $actual = Invoke-InfraRequest GET $uri
                        if ($actual.properties.provisioningState -eq 'Succeeded') { $ready=$true; break }
                        if ($actual.properties.provisioningState -in @('Failed','Canceled')) { break }
                        Start-Sleep -Seconds 5
                    }
                    if (!$ready) { Write-Warning 'Model deployment did not reach Succeeded; the already-published harness remains available.'; continue }
                    $settingsUri = "https://management.azure.com$SiteResourceId/config/appsettings"
                    $settings = Invoke-InfraRequest POST "$settingsUri/list?api-version=2024-11-01"
                    $properties = @{}
                    foreach ($property in $settings.properties.PSObject.Properties) { $properties[$property.Name]=$property.Value }
                    $properties['AzureOpenAI__Deployment']=$DeploymentName
                    $properties['Harness__ModelStatus']='Ready'
                    Invoke-InfraRequest PUT "$settingsUri`?api-version=2024-11-01" @{properties=$properties} | Out-Null
                    return @{status='Ready';deployment=$DeploymentName;name=$actual.properties.model.name;version=$actual.properties.model.version;sku=$actual.sku.name;capacity=$actual.sku.capacity;quotaLimit=$quota[0].limit;quotaUsedBefore=$quota[0].currentValue;verifiedAt=[DateTimeOffset]::UtcNow.ToString('o')}
                } catch { Write-Warning "Model $name could not be provisioned; keeping login live and trying the next verified model." }
            }
        }
    } catch { Write-Warning 'Model catalog/quota or deployment checks failed; the login/admin shell remains live with model Pending.' }
    return $pending
}

function Enable-VerifiedDefenderAI {
    param([string]$SubscriptionId, [switch]$AcknowledgeSubscriptionScope)
    if (!$AcknowledgeSubscriptionScope) {
        throw 'Defender AI is subscription-scoped. Explicit -AcknowledgeSubscriptionDefenderAI is required before any deployment.'
    }
    $root = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings"
    $catalog = Invoke-InfraRequest -Method GET -Uri "${root}?api-version=2024-01-01"
    $ai = @($catalog.value | Where-Object { $_.name -eq 'AI' })
    if ($ai.Count -ne 1) { throw 'The current subscription pricing catalog does not expose the documented AI plan. Refusing to guess a plan name.' }
    $uri = "$root/AI`?api-version=2024-01-01"
    if ($ai[0].properties.pricingTier -ne 'Standard') {
        $properties = @{ pricingTier = 'Standard' }
        foreach ($field in @('extensions','subPlan','enforce')) {
            $value = Get-OptionalProperty $ai[0].properties $field
            if ($null -ne $value) { $properties[$field] = $value }
        }
        Invoke-InfraRequest -Method PUT -Uri $uri -Body @{properties=$properties} | Out-Null
    }
    $verified = Invoke-InfraRequest -Method GET -Uri $uri
    if ($verified.properties.pricingTier -ne 'Standard') { throw 'Defender for AI Services did not read back as Standard.' }
    foreach ($extension in @(Get-OptionalProperty $verified.properties 'extensions' @())) {
        $status = Get-OptionalProperty (Get-OptionalProperty $extension 'operationStatus') 'code'
        if ($status -and $status -notin @('Succeeded','Success')) { throw 'A Defender AI extension reports unsuccessful enablement.' }
    }
    return @{
        resourceId = "/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings/AI"
        scope = 'subscription'
        pricingTier = $verified.properties.pricingTier
        verifiedAt = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

function New-RandomSecret {
    param([int]$Bytes = 32)
    return 'AgentHarness!9' + [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes($Bytes)).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Get-VaultSecretOrNull {
    param([string]$VaultUri, [string]$Name)
    try {
        if ($script:VaultControlPlanes.ContainsKey($VaultUri.TrimEnd('/'))) {
            $scope = $script:VaultControlPlanes[$VaultUri.TrimEnd('/')]
            $secret = Invoke-CachedAzureRequest -Method GET -Uri "https://management.azure.com$scope/secrets/$Name`?api-version=2024-11-01"
            return [pscustomobject]@{tags=(Get-OptionalProperty $secret 'tags' ([pscustomobject]@{}));attributes=$secret.properties.attributes;id=$secret.id}
        }
        return Invoke-CachedAzureRequest -Method GET -Uri "$($VaultUri.TrimEnd('/'))/secrets/$Name`?api-version=7.4"
    } catch {
        $response = Get-OptionalProperty $_.Exception 'Response'
        if ([int](Get-OptionalProperty $response 'StatusCode' 0) -eq 404) { return $null }
        throw 'Key Vault is not readable by the deployment identity. Sensitive response content was suppressed.'
    }
}

function Wait-VaultAccess {
    param([string]$VaultUri)
    if ($script:VaultControlPlanes.ContainsKey($VaultUri.TrimEnd('/'))) {
        $scope = $script:VaultControlPlanes[$VaultUri.TrimEnd('/')]
        Invoke-InfraRequest GET "https://management.azure.com$scope/secrets?api-version=2024-11-01" | Out-Null
        return
    }
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try {
            Invoke-CachedAzureRequest -Method GET -Uri "$($VaultUri.TrimEnd('/'))/secrets?api-version=7.4&maxresults=1" | Out-Null
            return
        } catch {
            if ($attempt -eq 39) { throw 'Timed out waiting for Key Vault Secrets Officer RBAC propagation.' }
            Start-Sleep -Seconds 5
        }
    }
}

function Set-VaultSecret {
    param([string]$VaultUri, [string]$Name, [string]$Value, [hashtable]$Tags = @{}, [Nullable[long]]$Expires = $null)
    $body = @{value=$Value;contentType='text/plain';tags=$Tags;attributes=@{enabled=$true}}
    if ($null -ne $Expires) { $body.attributes.exp = [long]$Expires }
    if ($script:VaultControlPlanes.ContainsKey($VaultUri.TrimEnd('/'))) {
        $scope = $script:VaultControlPlanes[$VaultUri.TrimEnd('/')]
        Invoke-InfraRequest PUT "https://management.azure.com$scope/secrets/$Name`?api-version=2024-11-01" @{
            properties=@{value=$Value;contentType='text/plain';attributes=$body.attributes}
            tags=$Tags
        } | Out-Null
        return
    }
    Invoke-InfraRequest -Method PUT -Uri "$($VaultUri.TrimEnd('/'))/secrets/$Name`?api-version=7.4" -Body $body | Out-Null
}

function Ensure-RandomVaultSecret {
    param([string]$VaultUri, [string]$Name, [int]$Bytes = 32)
    if ($null -eq (Get-VaultSecretOrNull -VaultUri $VaultUri -Name $Name)) {
        $value = New-RandomSecret -Bytes $Bytes
        try { Set-VaultSecret -VaultUri $VaultUri -Name $Name -Value $value } finally { $value = $null }
    }
}

function Assert-OwnedApplication {
    param([string]$ObjectId, [string]$ClientId)
    $app = Invoke-InfraRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$ObjectId`?`$select=id,appId,signInAudience,web,requiredResourceAccess,passwordCredentials"
    if ($app.appId -ne $ClientId -or $app.signInAudience -ne 'AzureADMyOrg') {
        throw 'The application does not match the explicitly owned single-tenant app registration.'
    }
    return $app
}

function Ensure-AppSecret {
    param([string]$VaultUri, [string]$Name, [string]$ObjectId, [string]$ClientId)
    $app = Assert-OwnedApplication -ObjectId $ObjectId -ClientId $ClientId
    $existing = Get-VaultSecretOrNull -VaultUri $VaultUri -Name $Name
    if ($existing) {
        $tags = Get-OptionalProperty $existing 'tags'
        if ((Get-OptionalProperty $tags 'app-object-id') -ne $ObjectId) { throw "The stored credential $Name belongs to a different app." }
        $expiration = [long](Get-OptionalProperty $existing.attributes 'exp' 0)
        $keyId = Get-OptionalProperty $tags 'credential-key-id'
        $active = @($app.passwordCredentials | Where-Object {
            $_.keyId -eq $keyId -and [DateTimeOffset]::Parse($_.endDateTime) -gt [DateTimeOffset]::UtcNow.AddDays(30)
        })
        if ($active.Count -eq 1 -and $expiration -gt [DateTimeOffset]::UtcNow.AddDays(30).ToUnixTimeSeconds()) { return }
    }
    $expires = [DateTimeOffset]::UtcNow.AddDays(180)
    $credential = Invoke-InfraRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$ObjectId/addPassword" -Body @{
        passwordCredential=@{displayName="AgentHarness deployment: $Name";endDateTime=$expires.ToString('o')}
    }
    try {
        Set-VaultSecret -VaultUri $VaultUri -Name $Name -Value $credential.secretText -Expires $expires.ToUnixTimeSeconds() -Tags @{
            'app-object-id'=$ObjectId
            'credential-key-id'=$credential.keyId
        }
    } catch {
        Invoke-InfraRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$ObjectId/removePassword" -Body @{keyId=$credential.keyId} | Out-Null
        throw 'The newly created application credential could not be stored in Key Vault and was removed.'
    } finally { $credential = $null; $existing = $null }
}

function Ensure-AppRedirect {
    param([string]$ObjectId, [string]$ClientId, [uri]$RedirectUri)
    if ($RedirectUri.Scheme -ne 'https') { throw 'An HTTPS redirect URI is required.' }
    $app = Assert-OwnedApplication -ObjectId $ObjectId -ClientId $ClientId
    $redirects = @($app.web.redirectUris)
    if (@($redirects | Where-Object { $_.TrimEnd('/') -eq $RedirectUri.AbsoluteUri.TrimEnd('/') }).Count -eq 0) {
        Invoke-InfraRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$ObjectId" -Body @{
            web=@{redirectUris=@($redirects + $RedirectUri.AbsoluteUri)}
        } | Out-Null
    }
}

function Ensure-GraviteeOidcConsent {
    param([string]$ObjectId, [string]$ClientId, [string]$ServicePrincipalId)
    $app = Assert-OwnedApplication -ObjectId $ObjectId -ClientId $ClientId
    $principal = Invoke-InfraRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId`?`$select=appId"
    if ($principal.appId -ne $ClientId) { throw 'The Gravitee service principal is not the owned client.' }
    $graph = @(Get-GraphCollection -Path "v1.0/servicePrincipals?`$filter=appId%20eq%20'00000003-0000-0000-c000-000000000000'&`$select=id,oauth2PermissionScopes")[0]
    $scopeNames = @('openid','profile','email')
    $scopeIds = foreach ($scope in $scopeNames) {
        $match = @($graph.oauth2PermissionScopes | Where-Object { $_.value -eq $scope -and $_.isEnabled })
        if ($match.Count -ne 1) { throw 'An expected Microsoft Graph OIDC scope is unavailable.' }
        @{id=$match[0].id;type='Scope'}
    }
    $access = @($app.requiredResourceAccess | Where-Object { $_.resourceAppId -ne '00000003-0000-0000-c000-000000000000' })
    $existingGraph = @($app.requiredResourceAccess | Where-Object { $_.resourceAppId -eq '00000003-0000-0000-c000-000000000000' })
    $graphAccess = @($scopeIds)
    if ($existingGraph.Count) { $graphAccess += @($existingGraph[0].resourceAccess) }
    $graphAccess = @($graphAccess | Sort-Object id,type -Unique)
    $access += @{resourceAppId='00000003-0000-0000-c000-000000000000';resourceAccess=$graphAccess}
    Invoke-InfraRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$ObjectId" -Body @{requiredResourceAccess=$access} | Out-Null
    $grants = @(Get-GraphCollection -Path ("v1.0/oauth2PermissionGrants?`$filter=" + [uri]::EscapeDataString("clientId eq '$ServicePrincipalId' and resourceId eq '$($graph.id)'")))
    $grant = @($grants | Where-Object { $_.consentType -eq 'AllPrincipals' })
    if ($grant.Count -gt 1) { throw 'Ambiguous existing Gravitee OIDC grants.' }
    if ($grant.Count) {
        $scopes = @((($grant[0].scope -split ' ') + $scopeNames) | Where-Object { $_ } | Sort-Object -Unique)
        Invoke-InfraRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($grant[0].id)" -Body @{scope=$scopes -join ' '} | Out-Null
    } else {
        Invoke-InfraRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body @{
            clientId=$ServicePrincipalId;resourceId=$graph.id;consentType='AllPrincipals';scope=$scopeNames -join ' '
        } | Out-Null
    }
}

function New-PublicOnlySshKey {
    $rsa = [Security.Cryptography.RSA]::Create(3072)
    $stream = [IO.MemoryStream]::new()
    try {
        $key = $rsa.ExportParameters($false)
        $parts = [Collections.Generic.List[byte[]]]::new()
        $parts.Add([Text.Encoding]::ASCII.GetBytes('ssh-rsa'))
        $parts.Add($key.Exponent)
        $parts.Add($key.Modulus)
        for ($index=0; $index -lt $parts.Count; $index++) {
            $bytes = $parts[$index]
            if ($index -gt 0 -and ($bytes[0] -band 0x80)) { $bytes = [byte[]](@(0) + $bytes) }
            $length = [BitConverter]::GetBytes([int]$bytes.Length)
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($length) }
            $stream.Write($length)
            $stream.Write($bytes)
        }
        return 'ssh-rsa ' + [Convert]::ToBase64String($stream.ToArray()) + ' agentharness-run-command-only'
    } finally { $rsa.Dispose(); $stream.Dispose() }
}

function Publish-PrivateBundle {
    param([string]$SubscriptionId, [uri]$ContainerUrl, [string]$Path)
    if (!$script:AzureSessionContext -or !$script:AzureSessionContext.Verified -or
        $SubscriptionId -ne $script:AzureSessionContext.SubscriptionId) {
        throw 'Bundle upload requires the explicitly initialized subscription and administrator.'
    }
    if ($ContainerUrl.Scheme -ne 'https' -or $ContainerUrl.Host -notmatch '^[a-z0-9]+\.blob\.core\.windows\.net$') {
        throw 'Invalid deployment storage endpoint.'
    }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $uri = "$($ContainerUrl.AbsoluteUri.TrimEnd('/'))/gravitee-$hash.zip"
    $token = Get-CachedAzureToken -Resource 'https://storage.azure.com/'
    try {
        for ($attempt=0; $attempt -lt 40; $attempt++) {
            try {
                Invoke-WebRequest -Method PUT -Uri $uri -InFile $Path -ContentType 'application/zip' -TimeoutSec 180 -Headers @{
                    Authorization="Bearer $($token.Trim())";'x-ms-version'='2023-11-03';'x-ms-blob-type'='BlockBlob'
                    'x-ms-date'=[DateTime]::UtcNow.ToString('R',[Globalization.CultureInfo]::InvariantCulture)
                } | Out-Null
                return @{uri=$uri;sha256=$hash}
            } catch {
                if ($attempt -eq 39) { throw 'Private bundle upload failed. Check Storage Blob Data Contributor propagation.' }
                Start-Sleep -Seconds 5
            }
        }
    } finally { $token=$null }
}

function Invoke-VmBundle {
    param([string]$VmResourceId, [string]$BundleUri, [string]$Sha256, [string]$Location, [string]$InlineBundlePath)
    if ($Sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Invalid VM deployment-bundle checksum.' }
    $downloadBlock = @'
metadata = 'http://169.254.169.254/metadata/identity/oauth2/token?' + urllib.parse.urlencode({'api-version':'2018-02-01','resource':'https://storage.azure.com/'})
with opener.open(urllib.request.Request(metadata, headers={'Metadata':'true'}), timeout=30) as r:
    token = json.load(r)['access_token']
request = urllib.request.Request('__BUNDLE_URI__', headers={'Authorization':'Bearer '+token,'x-ms-version':'2023-11-03','x-ms-date':email.utils.format_datetime(datetime.datetime.now(datetime.timezone.utc),usegmt=True)})
for attempt in range(40):
    try:
        with opener.open(request, timeout=120) as r:
            payload = r.read()
        break
    except urllib.error.HTTPError:
        if attempt == 39:
            raise RuntimeError('Private deployment bundle access failed.')
        time.sleep(5)
'@
    if ($InlineBundlePath) {
        $file = Get-Item -LiteralPath $InlineBundlePath
        if ($file.Length -gt 2500000 -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Sha256) {
            throw 'The non-secret inline deployment bundle must match its checksum and fit the ARM request budget.'
        }
        $encoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))
        $downloadBlock = "payload = base64.b64decode('$encoded')"
    } else {
        $uri = [uri]$BundleUri
        if ($uri.Scheme -ne 'https' -or $uri.Host -notmatch '^[a-z0-9]+\.blob\.core\.windows\.net$') {
            throw 'Invalid VM deployment-bundle endpoint.'
        }
    }
    $script = @'
set -eu
umask 077
mkdir -p /opt/agentharness
cd /opt/agentharness
python3 - <<'PY'
import base64, datetime, email.utils, hashlib, io, json, pathlib, time, urllib.error, urllib.parse, urllib.request, zipfile
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
__DOWNLOAD_BLOCK__
if hashlib.sha256(payload).hexdigest() != '__SHA256__':
    raise RuntimeError('Bundle integrity verification failed.')
root = pathlib.Path.cwd().resolve()
with zipfile.ZipFile(io.BytesIO(payload)) as archive:
    for item in archive.infolist():
        if pathlib.Path(item.filename).is_absolute() or not (root / item.filename).resolve().is_relative_to(root):
            raise RuntimeError('Unsafe deployment archive path.')
    archive.extractall(root)
for path in root.rglob('*'):
    if path.is_file() and (path.suffix in ('.sh', '.py', '.json') or path.name in ('Dockerfile', 'Caddyfile')):
        content = path.read_bytes()
        if content.startswith(b'\xef\xbb\xbf'):
            content = content[3:]
        path.write_bytes(content.replace(b'\r\n', b'\n'))
PY
bash /opt/agentharness/bootstrap.sh
'@
    $script = $script.Replace('__DOWNLOAD_BLOCK__',$downloadBlock).Replace('__BUNDLE_URI__',[string]$BundleUri).Replace('__SHA256__',$Sha256).Replace("`r`n","`n")
    $script += "`n# Deployment invocation: $([guid]::NewGuid().ToString())`n"
    $commandUri = "https://management.azure.com$VmResourceId/runCommands/agentharness-bootstrap?api-version=2024-11-01"
    $previousStart = $null
    try {
        $existing = Invoke-CachedAzureRequest -Method GET -Uri "$commandUri&`$expand=instanceView"
        $previousView = Get-OptionalProperty $existing.properties 'instanceView'
        $previousStart = Get-OptionalProperty $previousView 'startTime'
        if ((Get-OptionalProperty $previousView 'executionState') -in @('Running','Pending')) {
            throw 'A VM bootstrap is already executing; refusing an overlapping deployment.'
        }
    } catch {
        $response = Get-OptionalProperty $_.Exception 'Response'
        if ([int](Get-OptionalProperty $response 'StatusCode' 0) -ne 404) {
            throw 'Cannot safely start VM bootstrap: an existing command is running or its status could not be read.'
        }
    }
    Invoke-InfraRequest -Method PUT -Uri $commandUri -Body @{
        location=$Location
        properties=@{source=@{script=$script};timeoutInSeconds=3600;asyncExecution=$true}
    } | Out-Null
    for ($attempt=0; $attempt -lt 240; $attempt++) {
        Start-Sleep -Seconds 15
        $status = Invoke-InfraRequest -Method GET -Uri "$commandUri&`$expand=instanceView"
        $view = Get-OptionalProperty $status.properties 'instanceView'
        $execution = Get-OptionalProperty $view 'executionState'
        $started = Get-OptionalProperty $view 'startTime'
        if (!$started -or ($previousStart -and $started -eq $previousStart)) { continue }
        if ($execution -eq 'Succeeded') {
            if ([int](Get-OptionalProperty $view 'exitCode' -1) -ne 0) { throw 'VM bootstrap returned a nonzero exit code; inspect root-only VM logs.' }
            return
        }
        if ($execution -in @('Failed','TimedOut','Canceled')) { throw "VM bootstrap $execution. Run-command output is suppressed to avoid disclosing secrets." }
    }
    throw 'Timed out waiting for the VM bootstrap. Inspect the existing managed run command; do not start overlapping bootstraps.'
}

function Publish-HarnessZip {
    param([string]$ResourceId, [string]$ZipPath)
    $site = Invoke-InfraRequest -Method GET -Uri "https://management.azure.com$ResourceId`?api-version=2024-11-01"
    $scmHosts = @($site.properties.enabledHostNames | Where-Object { $_ -match '\.scm\..*azurewebsites\.net$|\.scm\.azurewebsites\.net$' })
    if ($scmHosts.Count -ne 1) { throw 'ARM did not return exactly one trusted App Service SCM hostname.' }
    $hostName = $scmHosts[0]
    $token = Get-CachedAzureToken -Resource 'https://management.azure.com/'
    $headers = @{Authorization="Bearer $token"}
    try {
        $response = Invoke-WebRequest -Method POST -Uri "https://$hostName/api/zipdeploy?isAsync=true" -Headers $headers -InFile $ZipPath -ContentType 'application/zip' -TimeoutSec 180
        $statusUri = [uri]($response.Headers.Location | Select-Object -First 1)
        if (!$statusUri.IsAbsoluteUri) { $statusUri = [uri]::new([uri]"https://$hostName", $statusUri) }
        if ($statusUri.Scheme -ne 'https' -or $statusUri.Host -ne $hostName) { throw 'Unexpected zip-deployment status endpoint.' }
        for ($attempt=0; $attempt -lt 120; $attempt++) {
            Start-Sleep -Seconds 10
            $status = Invoke-RestMethod -Method GET -Uri $statusUri -Headers $headers -TimeoutSec 60
            if ($status.status -eq 4) {
                Invoke-InfraRequest POST "https://management.azure.com$ResourceId/restart?api-version=2024-11-01" | Out-Null
                return
            }
            if ($status.status -eq 3) { throw 'App Service zip deployment failed.' }
        }

        throw 'App Service zip deployment timed out.'
    } catch { throw 'App Service deployment did not complete. Check publish RBAC and SCM deployment logs; basic publishing authentication remains disabled.' }
    finally { $token=$null; $headers=$null }
}

function Refresh-AppVaultReferences {
    param([string]$ResourceId)
    for ($attempt=0; $attempt -lt 5; $attempt++) {
        try {
            Invoke-InfraRequest POST "https://management.azure.com$ResourceId/config/configreferences/appsettings/refresh?api-version=2024-11-01" | Out-Null
            return
        } catch {
            if ($attempt -eq 4 -or $_.Exception.Message -notmatch 'Conflict|409|429|TooMany|503|ServiceUnavailable') { throw }
            Write-Host 'App Service is finishing a configuration/reference update; retrying the authenticated refresh.'
            Start-Sleep -Seconds 10
        }
    }
}
