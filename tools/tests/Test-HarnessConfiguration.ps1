#requires -Version 7.2
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Offline checks use synthetic in-memory state, never the ignored deployment files.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tools = Split-Path $PSScriptRoot -Parent
$testStatePath = 'memory-customer-state.json'
$testConfiguration = @{
    TenantId = [guid]::NewGuid().ToString()
    SubscriptionId = [guid]::NewGuid().ToString()
    AdministratorObjectId = [guid]::NewGuid().ToString()
    ClientId = [guid]::NewGuid().ToString()
    TenantDomain = 'sample.onmicrosoft.com'
    AdministratorUpn = 'operator@example.test'
}

function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath, [string]$PathType)
    if ($LiteralPath -eq $testStatePath) { return $true }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}

function Get-Content {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Raw)
    if ($LiteralPath -eq $testStatePath) { return $testConfiguration | ConvertTo-Json -Depth 20 -Compress }
    Microsoft.PowerShell.Management\Get-Content @PSBoundParameters
}

function az { throw 'An offline test attempted authentication.' }
function Invoke-RestMethod { throw 'An offline test attempted a remote request.' }
function Connect-IPPSSession { throw 'An offline test attempted an SCC connection.' }
function Import-Module { throw 'An offline test attempted to load an authentication module.' }

function Assert-Throws {
    param([scriptblock]$Operation)
    $threw = $false
    try { & $Operation | Out-Null }
    catch { $threw = $true }
    if (-not $threw) { throw 'Expected the invalid configuration or scope to be rejected.' }
}

. (Join-Path $tools 'HarnessConfiguration.ps1')
$loaded = Read-HarnessConfiguration -StatePath $testStatePath -DomainFields TenantDomain -UpnFields AdministratorUpn
if ($loaded.TenantId -ne $testConfiguration.TenantId) { throw 'Configured tenant was not retained.' }
$originalTenant = $testConfiguration.TenantId
try {
    $testConfiguration.TenantId = ''
    Assert-Throws { Read-HarnessConfiguration -StatePath $testStatePath }
    $testConfiguration.TenantId = [guid]::Empty.ToString()
    Assert-Throws { Read-HarnessConfiguration -StatePath $testStatePath }
}
finally { $testConfiguration.TenantId = $originalTenant }
Assert-Throws { Read-HarnessConfiguration -StatePath 'missing-customer-state.json' }

$purviewPath = Join-Path $tools 'Configure-Purview.ps1'
$preview = & $purviewPath -Action Preview -StatePath $testStatePath
if ($preview.TenantId -ne $testConfiguration.TenantId -or
    $preview.ApplicationId -ne $testConfiguration.ClientId -or
    $preview.DlpPolicy.Locations.Count -ne 1 -or
    $preview.DlpPolicy.Locations[0].Location -ne $testConfiguration.ClientId -or
    $preview.DlpRule.NotifyUser[0] -ne $testConfiguration.AdministratorUpn) {
    throw 'Preview did not remain scoped to the explicit customer configuration.'
}
$dlpOnly = & $purviewPath -Action Preview -PolicySet DlpOnly -StatePath $testStatePath
if ($null -ne $dlpOnly.CollectionPolicy) { throw 'DlpOnly must not configure collection.' }

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($purviewPath, [ref]$tokens, [ref]$parseErrors)
foreach ($name in @('Get-PolicyField', 'ConvertFrom-PolicyValue', 'Assert-OnlyHarnessLocation', 'Get-SccTokenBinding')) {
    $function = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $function) { throw "Required guard '$name' was not found." }
    . ([scriptblock]::Create($function.Extent.Text))
}
$applicationId = $testConfiguration.ClientId
$administratorObjectId = $testConfiguration.AdministratorObjectId
$administratorUpn = $testConfiguration.AdministratorUpn
$organization = $testConfiguration.TenantDomain
Assert-OnlyHarnessLocation $preview.DlpPolicy 'Customer DLP policy'
$broad = @{ Locations = @(@{ Workload = 'Applications'; Location = 'All'; LocationSource = 'Entra'; LocationType = 'Individual' }) }
Assert-Throws { Assert-OnlyHarnessLocation $broad 'Broad policy' }
$additional = @{ Locations = @($preview.DlpPolicy.Locations[0], $preview.DlpPolicy.Locations[0]) }
Assert-Throws { Assert-OnlyHarnessLocation $additional 'Additional app scope' }
Assert-Throws { Get-SccTokenBinding @{ scp = 'user_impersonation'; oid = [guid]::NewGuid().ToString(); upn = $administratorUpn } }
$binding = Get-SccTokenBinding @{ scp = 'user_impersonation'; oid = $administratorObjectId; upn = $administratorUpn }
if ($binding.UserPrincipalName -ne $administratorUpn) { throw 'Configured administrator binding was not retained.' }

Write-Output 'Offline configuration, Purview preview, and fail-closed scope checks passed.'
