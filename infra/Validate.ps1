#Requires -Version 7.2
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-CustomerConfiguration {
    param([Parameter(Mandatory)][string]$InfraPath)
    . (Join-Path $InfraPath 'AzureSession.ps1')
    $script:ContractTenantId = '11111111-1111-4111-8111-111111111111'
    $script:ContractSubscriptionId = '22222222-2222-4222-8222-222222222222'
    $script:ContractAdministratorId = '33333333-3333-4333-8333-333333333333'
    $script:ContractUpn = 'administrator@example.invalid'
    $script:ContractAzCalls = [Collections.Generic.List[object]]::new()
    $script:ContractHttpCalls = 0

    function Assert-ContractFailure {
        param([scriptblock]$Action)
        $failed = $false
        try { & $Action | Out-Null } catch { $failed=$true }
        if (!$failed) { throw 'A customer-configuration boundary regression accepted an invalid operation.' }
    }

    function New-ContractToken {
        param([hashtable]$Overrides = @{})
        $claims = @{
            tid=$script:ContractTenantId;oid=$script:ContractAdministratorId
            aud='00000003-0000-0000-c000-000000000000';exp=[DateTimeOffset]::UtcNow.AddMinutes(5).ToUnixTimeSeconds()
        }
        foreach ($key in $Overrides.Keys) { $claims[$key]=$Overrides[$key] }
        $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($claims | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_')
        return "offline.$payload.unsigned"
    }

    function az {
        $arguments = @($args)
        $script:ContractAzCalls.Add($arguments)
        $global:LASTEXITCODE = 0
        if (($arguments[0..1] -join ' ') -eq 'account list') {
            return @(@{id=$script:ContractSubscriptionId;tenantId=$script:ContractTenantId;state='Enabled'}) | ConvertTo-Json -AsArray
        }
        if (($arguments[0..1] -join ' ') -eq 'account get-access-token') {
            return New-ContractToken
        }
        throw 'Unexpected offline Azure CLI call.'
    }

    function Invoke-RestMethod {
        param($Method,$Uri,$Headers,$TimeoutSec,$MaximumRedirection)
        $script:ContractHttpCalls++
        if ($Method -ne 'GET' -or [string]$Uri -ne 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName') {
            throw 'Unexpected offline HTTP call.'
        }
        return [pscustomobject]@{id=$script:ContractAdministratorId;userPrincipalName=$script:ContractUpn}
    }

    $target = @{
        TenantId=$script:ContractTenantId;SubscriptionId=$script:ContractSubscriptionId
        AdministratorObjectId=$script:ContractAdministratorId;AdministratorUpn=$script:ContractUpn
    }
    Assert-ContractFailure { Invoke-CachedAzureRequest GET 'https://graph.microsoft.com/v1.0/me' }
    if ($script:ContractAzCalls.Count -or $script:ContractHttpCalls) { throw 'An uninitialized request reached Azure.' }
    $wrongTarget = @{TenantId=$target.TenantId;SubscriptionId='44444444-4444-4444-8444-444444444444';AdministratorObjectId=$target.AdministratorObjectId}
    Assert-ContractFailure { Initialize-CachedAzureSession @wrongTarget }
    if ($script:ContractHttpCalls) { throw 'An unselected subscription reached Graph.' }
    $script:ContractAzCalls.Clear()
    Initialize-CachedAzureSession @target | Out-Null
    $tokenCall = @($script:ContractAzCalls | Where-Object { $_[1] -eq 'get-access-token' })
    if ($tokenCall.Count -ne 1 -or $tokenCall[0][[array]::IndexOf($tokenCall[0],'--subscription') + 1] -ne $target.SubscriptionId -or
        $tokenCall[0][[array]::IndexOf($tokenCall[0],'--tenant') + 1] -ne $target.TenantId) {
        throw 'Token acquisition did not use the explicitly verified subscription and tenant.'
    }
    Assert-ContractFailure { Invoke-CachedAzureRequest GET 'https://graph.microsoft.com.example.invalid/v1.0/me' }
    Assert-ContractFailure { Invoke-CachedAzureRequest GET 'http://graph.microsoft.com/v1.0/me' }
    if ($script:ContractHttpCalls -ne 1) { throw 'An untrusted bearer-token endpoint reached HTTP.' }
    $script:TokenCache['https://graph.microsoft.com/'] = New-ContractToken -Overrides @{exp=[DateTimeOffset]::UtcNow.AddMinutes(-5).ToUnixTimeSeconds()}
    $script:ContractAzCalls.Clear()
    Get-CachedAzureToken -Resource 'https://graph.microsoft.com/' | Out-Null
    if (@($script:ContractAzCalls | Where-Object { $_[1] -eq 'get-access-token' }).Count -ne 1) {
        throw 'An expired token in a verified session did not refresh once from the explicit CLI account.'
    }
    foreach ($override in @(
        @{tid='44444444-4444-4444-8444-444444444444'},
        @{oid='44444444-4444-4444-8444-444444444444'},
        @{aud='https://example.invalid'},
        @{exp=[DateTimeOffset]::UtcNow.AddMinutes(-5).ToUnixTimeSeconds()}
    )) {
        $script:AzureSessionContext=$null
        $script:TokenCache=@{'https://graph.microsoft.com/'=(New-ContractToken -Overrides $override)}
        $script:ContractHttpCalls=0
        Assert-ContractFailure { Initialize-CachedAzureSession @target }
        if ($script:ContractHttpCalls -or $script:AzureSessionContext) { throw 'An invalid preseeded token reached Graph or left an active session.' }
    }
    $script:AzureSessionContext=$null
    $script:TokenCache=@{'https://graph.microsoft.com/'=(New-ContractToken)}
    $script:ContractAzCalls.Clear()
    Initialize-CachedAzureSession @target | Out-Null
    if (@($script:ContractAzCalls | Where-Object { $_[1] -eq 'get-access-token' }).Count) {
        throw 'A valid explicitly supplied Graph token was replaced by the CLI cache.'
    }
    $script:ContractUpn='another-administrator@example.invalid'
    Assert-ContractFailure { Initialize-CachedAzureSession @target }
    if ($script:AzureSessionContext) { throw 'An administrator UPN mismatch left an active session.' }
    foreach ($origin in @('http://harness.example.invalid','https://user@harness.example.invalid','https://harness.example.invalid/path','https://harness.example.invalid/?value=1','https://harness.example.invalid/#fragment')) {
        Assert-ContractFailure { Assert-HttpsOrigin -Uri $origin }
    }
    if ((Assert-HttpsOrigin -Uri 'https://harness.example.invalid/') -ne 'https://harness.example.invalid') { throw 'HTTPS origin normalization failed.' }
    $script:AzureSessionContext=$null
    $script:TokenCache.Clear()
}

$root = Split-Path $PSScriptRoot
Set-Location $root
$output = Join-Path $root 'artifacts\infra-validation'
New-Item -Path $output -ItemType Directory -Force | Out-Null
$count = 0
$scripts = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter *.ps1 -Recurse)
foreach ($file in $scripts) {
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$null,[ref]$errors) | Out-Null
    if ($errors.Count) { throw "PowerShell syntax errors in $($file.Name): $($errors -join '; ')" }
    $count++
}
Test-CustomerConfiguration -InfraPath $PSScriptRoot
& az bicep build --file (Join-Path $PSScriptRoot 'subscription.bicep') --outfile (Join-Path $output 'subscription.json') --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'Bicep compilation failed. If missing, install the official compiler with az bicep install, then rerun.' }
$compose = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'gravitee\compose.json') -Raw | ConvertFrom-Json
foreach ($service in $compose.services.PSObject.Properties) {
    if ($service.Name -ne 'internal-api' -and $service.Value.image -notmatch '@sha256:[0-9a-f]{64}$') { throw "An upstream image is not digest-pinned: $($service.Name)" }
    $ports = $service.Value.PSObject.Properties['ports']
    if ($service.Name -ne 'caddy' -and $ports) { throw "A non-proxy container publishes a host port: $($service.Name)" }
    if ($service.Value.restart -ne 'unless-stopped') { throw 'Every service must restart after a Docker/VM reboot.' }
}
if (($compose.services.caddy.ports -join ',') -ne '80:80,443:443') { throw 'Caddy must be the only public listener, on 80 and 443.' }
if ($compose.networks.backend.internal -ne $true -or $compose.networks.storage.internal -ne $true) { throw 'Data and backend networks must be private.' }
if (($compose.services.'internal-api'.networks -join ',') -ne 'backend') { throw 'The intentionally unauthenticated backend must be attached only to the isolated backend network.' }

$azDirectory = Split-Path (Get-Command az -ErrorAction Stop).Source
$python = Join-Path $azDirectory '..\python.exe'
if (!(Test-Path -LiteralPath $python)) {
    $command = Get-Command python3,python -ErrorAction SilentlyContinue | Select-Object -First 1
    if (!$command) { throw 'Python is required for VM-script validation; the Azure CLI bundled Python was not found.' }
    $python=$command.Source
}
& $python -c "import ast,pathlib; ast.parse(pathlib.Path(r'infra\gravitee\provision.py').read_text(encoding='utf-8-sig')); print('VM Python AST validated.')"
if ($LASTEXITCODE -ne 0) { throw 'VM Python syntax validation failed.' }
& $python 'infra\Validate-Gravitee.py'
if ($LASTEXITCODE -ne 0) { throw 'Offline Gravitee provisioning regressions failed.' }
$bash = Get-Command bash -ErrorAction SilentlyContinue | Select-Object -First 1
if ($bash) { $bashPath=$bash.Source } else {
    $gitDirectory = Split-Path (Split-Path (Get-Command git -ErrorAction Stop).Source)
    $bashPath = Join-Path $gitDirectory 'bin\bash.exe'
}
if (!(Test-Path -LiteralPath $bashPath)) { throw 'Bash syntax validation needs bash; Git for Windows normally supplies it.' }
& $bashPath -n 'infra\gravitee\bootstrap.sh'
if ($LASTEXITCODE -ne 0) { throw 'VM Bash syntax validation failed.' }
. (Join-Path $PSScriptRoot 'Deployment.Common.ps1')
$key = New-PublicOnlySshKey
$keyPath = Join-Path $output 'public-only-key.pub'
$key | Set-Content -LiteralPath $keyPath -Encoding ascii
try {
    & ssh-keygen -lf $keyPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The generated VM public-only SSH key is invalid.' }
} finally { Remove-Item -LiteralPath $keyPath -Force }
$report = @{
    validatedAt=[DateTimeOffset]::UtcNow.ToString('o')
    powershellFiles=$count
    customerConfiguration='Offline explicit-subscription, token boundary, administrator, preseeded-token, and HTTPS-origin regressions passed'
    bicep='Compiled'
    python='Parsed'
    bash='Parsed'
    compose='JSON parsed; pinned images and private-network invariants checked'
    graviteeProvisioning='Offline console-mode, CSRF, idempotency, collision, read-back, and alternative-plan regressions passed'
    azureDeployment='Not attempted'
    liveAuthorization='Not attempted; explicit subscription, valid OIDC license, and real delegated user tokens required'
}
$report | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'validation.json') -Encoding utf8NoBOM
Write-Host "Validated $count PowerShell files, Bicep, Python/Bash syntax, compose network/image invariants, and public-only SSH key."
Write-Host 'No Azure deployment, subscription selection, credential creation, or live authorization test was performed.'
