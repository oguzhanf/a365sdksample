[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$manifest = Get-Content -LiteralPath (Join-Path $root 'external\sources.json') -Raw | ConvertFrom-Json
$repository = $manifest.samples.repository
$commit = $manifest.samples.commit
if ($repository -ne 'https://github.com/microsoft/Agent365-Samples' -or $commit -notmatch '^[a-f0-9]{40}$') {
    throw 'The source manifest must identify the official Microsoft samples repository and an exact commit.'
}
$target = Join-Path $root 'external\Agent365-Samples'
if (!(Test-Path -LiteralPath $target)) {
    & git clone --depth 1 --filter=blob:none --sparse "$repository.git" $target
    if ($LASTEXITCODE -ne 0) { throw 'The Microsoft samples clone failed.' }
    & git -C $target sparse-checkout set dotnet
    if ($LASTEXITCODE -ne 0) { throw 'The .NET sparse checkout failed.' }
} elseif (!(Test-Path -LiteralPath (Join-Path $target '.git'))) {
    throw 'The samples directory exists without Git metadata. It was not overwritten.'
}
$head = & git -C $target rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'The sample checkout could not be inspected.' }
if ($head.Trim() -ne $commit) {
    $dirty = & git -C $target status --porcelain
    if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'Refusing to replace a modified samples checkout.' }
    & git -C $target fetch --depth 1 origin $commit
    if ($LASTEXITCODE -ne 0) { throw 'The pinned Microsoft commit could not be fetched.' }
    & git -C $target checkout --detach $commit
    if ($LASTEXITCODE -ne 0) { throw 'The pinned Microsoft commit could not be checked out.' }
}
if (!(Test-Path -LiteralPath (Join-Path $target 'LICENSE.md'))) { throw 'The Microsoft MIT license is missing.' }
Write-Output "Official Microsoft .NET samples are pinned to $commit."
