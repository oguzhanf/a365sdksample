# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Read-HarnessConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StatePath,
        [string[]]$GuidFields = @('TenantId', 'SubscriptionId', 'AdministratorObjectId', 'ClientId'),
        [string[]]$DomainFields = @(),
        [string[]]$UpnFields = @()
    )

    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        throw 'Customer configuration is missing. Run infra\Initialize-Entra.ps1 with explicit customer inputs first.'
    }
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    if ($state -isnot [System.Collections.IDictionary]) { throw 'The customer configuration must be a JSON object.' }
    foreach ($field in $GuidFields) {
        $parsed = [guid]::Empty
        if ($state[$field] -isnot [string] -or
            -not [guid]::TryParseExact($state[$field], 'D', [ref]$parsed) -or $parsed -eq [guid]::Empty) {
            throw "Configure a nonempty GUID for '$field' in the ignored Entra state before continuing."
        }
        $state[$field] = $parsed.ToString()
    }
    foreach ($field in $DomainFields) {
        $value = $state[$field]
        if ($value -isnot [string] -or $value.Length -gt 253 -or
            $value -notmatch '^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$') {
            throw "Configure a valid DNS domain for '$field' in the ignored Entra state."
        }
        $state[$field] = $value.ToLowerInvariant()
    }
    foreach ($field in $UpnFields) {
        $value = $state[$field]
        $address = $null
        if ($value -isnot [string] -or
            -not [System.Net.Mail.MailAddress]::TryCreate($value, [ref]$address) -or
            $address.Address -ine $value -or $value -match '[\s<>]') {
            throw "Configure an explicit administrator UPN for '$field' in the ignored Entra state."
        }
    }
    return $state
}
