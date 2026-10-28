#requires -Version 7.2
<#
.SYNOPSIS
Registers or validates samples using the explicitly configured customer application.
.DESCRIPTION
Reads ignored Entra state, verifies the cached tenant/subscription/administrator,
and removes its temporary application credential in finally. Never signs in.
#>
[CmdletBinding()]
param(
    [switch]$ValidateOnly,
    [string]$StatePath = (Join-Path $PSScriptRoot '..\infra\entra-state.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'HarnessConfiguration.ps1')
$state = Read-HarnessConfiguration -StatePath $StatePath `
    -GuidFields @('TenantId', 'SubscriptionId', 'AdministratorObjectId', 'ApplicationObjectId', 'ClientId') `
    -DomainFields @('TenantDomain') -UpnFields @('AdministratorUpn')
& dotnet build (Join-Path $root 'src\AgentHarness\AgentHarness.csproj') --nologo
if ($LASTEXITCODE -ne 0) { throw 'Fix the harness build before creating any temporary registration credential.' }
. (Join-Path $root 'infra\AzureSession.ps1')
Initialize-CachedAzureSession -TenantId $state.TenantId -SubscriptionId $state.SubscriptionId `
    -AdministratorObjectId $state.AdministratorObjectId -AdministratorUpn $state.AdministratorUpn | Out-Null
$application = Invoke-CachedAzureRequest -Method GET -Uri (
    "https://graph.microsoft.com/v1.0/applications/$($state.ApplicationObjectId)?`$select=id,appId,signInAudience"
)
if ($application.id -ine $state.ApplicationObjectId -or $application.appId -ine $state.ClientId -or
    $application.signInAudience -ne 'AzureADMyOrg') {
    throw 'The target is not the configured single-tenant harness application. No temporary credential was created.'
}
$credential = $null
$environment = @{}
foreach ($name in @('AzureAd__TenantId', 'AzureAd__ClientId', 'AzureAd__Domain', 'AzureAd__ClientSecret', 'Data__Path')) {
    $environment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$exitCode = 1
try {
    $credential = Invoke-CachedAzureRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$($state.ApplicationObjectId)/addPassword" -Body @{
        passwordCredential=@{
            displayName="AgentHarness temporary registration verification $([datetime]::UtcNow.ToString('yyyyMMddHHmmss'))"
            endDateTime=[datetimeoffset]::UtcNow.AddHours(1).ToString('O')
        }
    }
    if ([string]::IsNullOrWhiteSpace($credential.secretText) -or [string]::IsNullOrWhiteSpace($credential.keyId)) {
        throw 'Microsoft Graph did not return a usable temporary application credential.'
    }
    $env:AzureAd__TenantId = $state.TenantId
    $env:AzureAd__ClientId = $state.ClientId
    $env:AzureAd__Domain = $state.TenantDomain
    $env:AzureAd__ClientSecret = $credential.secretText
    $env:Data__Path = Join-Path $root 'data'
    for ($attempt = 0; ; $attempt++) {
        try {
            $preflight = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($state.TenantId)/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 30 -Body @{
                client_id=$state.ClientId;client_secret=$credential.secretText;scope='https://graph.microsoft.com/.default';grant_type='client_credentials'
            }
            if ([string]::IsNullOrWhiteSpace($preflight.access_token)) { throw 'No application token was returned.' }
            $preflight = $null
            break
        } catch {
            $detail = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            if ($attempt -ge 4 -or $detail -notmatch 'invalid_client|AADSTS7000215') { throw }
            Start-Sleep -Seconds (2 -shl $attempt)
        }
    }
    Push-Location (Join-Path $root 'src\AgentHarness')
    try {
        [string[]]$actions = if ($ValidateOnly) { @('--validate-samples') } else { @('--register-samples', '--validate-samples') }
        & dotnet run --project (Join-Path $root 'src\AgentHarness\AgentHarness.csproj') --no-build --no-launch-profile -- @actions
        $exitCode = $LASTEXITCODE
    } finally { Pop-Location }
} finally {
    foreach ($name in $environment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $environment[$name], 'Process')
    }
    if ($null -ne $credential) {
        Invoke-CachedAzureRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$($state.ApplicationObjectId)/removePassword" -Body @{keyId=$credential.keyId} | Out-Null
    }
}
if ($exitCode -ne 0) { throw 'Registration is incomplete. Check the per-agent evidence and saved checkpoints in data; the temporary credential was revoked.' }
Write-Output 'Registered sample catalog saved under data\agent-catalog.json. The temporary registration credential was revoked.'
