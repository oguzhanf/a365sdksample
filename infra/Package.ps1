#Requires -Version 7.2
[CmdletBinding()]
param(
    [switch]$HarnessOnly,
    [string]$AgentCatalogPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
Set-Location $root
$catalogSource = $null
if ($AgentCatalogPath) {
    if (!(Test-Path -LiteralPath $AgentCatalogPath -PathType Leaf)) { throw 'The explicitly selected agent catalog file does not exist.' }
    $catalogSource = (Resolve-Path -LiteralPath $AgentCatalogPath).Path
    Get-Content -LiteralPath $catalogSource -Raw | ConvertFrom-Json -ErrorAction Stop | Out-Null
}
$output = Join-Path $root 'artifacts\agentharness'
$publish = Join-Path $output 'publish'
$backend = Join-Path $output 'backend'
New-Item -Path $output -ItemType Directory -Force | Out-Null
foreach ($directory in @($publish,$backend)) {
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
}

& dotnet publish 'src\AgentHarness\AgentHarness.csproj' -c Release --no-restore -o $publish | Write-Host
if ($LASTEXITCODE -ne 0) { throw 'Harness publish failed. Resolve the reported build/dependency error before attempting any deployment.' }
if (!$HarnessOnly) {
    & dotnet publish 'src\AgentHarness.InternalApi\AgentHarness.InternalApi.csproj' -c Release --no-restore -o $backend | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'Internal API publish failed. Resolve the reported build/dependency error before attempting any deployment.' }
}
foreach ($artifact in @('AgentHarness.dll','AgentHarness.deps.json','AgentHarness.runtimeconfig.json')) {
    if (!(Test-Path -LiteralPath (Join-Path $publish $artifact))) { throw 'The harness publish output is incomplete.' }
}
if (!$HarnessOnly) {
    foreach ($artifact in @('AgentHarness.InternalApi.dll','AgentHarness.InternalApi.deps.json','AgentHarness.InternalApi.runtimeconfig.json')) {
        if (!(Test-Path -LiteralPath (Join-Path $backend $artifact))) { throw 'The backend publish output is incomplete.' }
    }
}
$seedDirectory = Join-Path $publish 'seed'
if (Test-Path -LiteralPath $seedDirectory) { Remove-Item -LiteralPath $seedDirectory -Recurse -Force }
if ($catalogSource) {
    New-Item -Path $seedDirectory -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $catalogSource -Destination (Join-Path $seedDirectory 'agents.json') -Force
}
$directories = @($publish)
if (!$HarnessOnly) { $directories += $backend }
foreach ($directory in $directories) {
    $unsafe = @(Get-ChildItem -LiteralPath $directory -Recurse -File | Where-Object {
        $_.Name -in @('appsettings.Local.json','entra-state.json','deployment-state.json','agent-catalog.json') -or
        ($_.Name -like '.env*' -and $_.Name -ne '.env.example') -or
        $_.Extension -in @('.db','.sqlite','.sqlite3','.pfx','.p12','.pem','.key') -or $_.Name -match '\.(db|sqlite|sqlite3)-(wal|shm)$'
    })
    if ($unsafe.Count) { throw 'Publish output contains local configuration/state, credentials, or raw SQLite data. Refusing to package private operational inputs.' }
}
$zip = Join-Path $output 'harness.zip'
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
[IO.Compression.ZipFile]::CreateFromDirectory($publish, $zip)
[pscustomobject]@{HarnessZip=$zip;HarnessPublish=$publish;BackendPublish=$backend}
