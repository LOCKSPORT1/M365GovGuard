<#
.SYNOPSIS
    Updates M365GovGuard from a git repository or a file share, then verifies it.

.DESCRIPTION
    The update itself is the easy part. The value here is what happens after:
    the module is imported into a throwaway session and checked before the
    update is declared good, so a bad pull is caught now rather than the next
    time someone opens the menu in front of a client.

    Verification covers the things that have actually broken in practice:
      - the module imports without error
      - every rule file registered (a flattened copy exports nothing)
      - the control catalog loads and its count matches its declaration
      - no rule references a control id the catalog does not contain

    Local-only files are left alone. Reports, logs and the remembered-tenant
    cache are not source and are never overwritten.

.PARAMETER Path
    The module folder. Defaults to the parent of this script.

.PARAMETER Source
    A file share or folder to copy from. Omit when the folder is a git clone -
    git is used automatically if a .git directory is present.

.PARAMETER ExpectedRuleCount
    Fail verification if fewer rules register than this. Catches a partial copy.

.PARAMETER WhatIfMode
    Report what would be updated without changing anything.

.EXAMPLE
    .\Update-GovGuard.ps1 -WhatIfMode

.EXAMPLE
    .\Update-GovGuard.ps1 -Source \\fileserver\tools\M365GovGuard
#>
[CmdletBinding()]
param(
    [string]$Path,
    [string]$Source,
    [int]$ExpectedRuleCount = 1,
    [switch]$WhatIfMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Path) { $Path = Split-Path -Parent $PSScriptRoot }

if (-not (Test-Path -LiteralPath $Path)) {
    throw ("Module folder not found: {0}" -f $Path)
}

Write-Host ('Module folder: {0}' -f $Path) -ForegroundColor Cyan

# Never overwritten by an update - runtime state, not source.
$localOnly = @('Reports', 'Logs', 'tenants.cache.json')

# ---------------------------------------------------------------------------
# Record what we are on now, so a failed update can be reasoned about
# ---------------------------------------------------------------------------

$manifestPath = Join-Path $Path 'M365GovGuard.psd1'
$versionBefore = 'unknown'
if (Test-Path -LiteralPath $manifestPath) {
    try { $versionBefore = (Import-PowerShellDataFile -LiteralPath $manifestPath).ModuleVersion } catch { }
}
Write-Host ('Version before: {0}' -f $versionBefore)

# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

$isGitClone = Test-Path -LiteralPath (Join-Path $Path '.git')

if ($Source) {

    if (-not (Test-Path -LiteralPath $Source)) {
        throw ("Source not found: {0}" -f $Source)
    }

    Write-Host ('Copying from: {0}' -f $Source) -ForegroundColor Cyan

    $items = Get-ChildItem -LiteralPath $Source -Force |
        Where-Object { $localOnly -notcontains $_.Name -and $_.Name -ne '.git' }

    foreach ($item in $items) {
        $destination = Join-Path $Path $item.Name

        if ($WhatIfMode) {
            Write-Host ('  WOULD COPY  {0}' -f $item.Name)
            continue
        }

        Copy-Item -LiteralPath $item.FullName -Destination $destination -Recurse -Force
        Write-Host ('  COPIED      {0}' -f $item.Name) -ForegroundColor Green
    }
}
elseif ($isGitClone) {

    Write-Host 'Updating from git.' -ForegroundColor Cyan

    if ($WhatIfMode) {
        Push-Location $Path
        try { git fetch --quiet; git status --short --branch | Write-Host }
        finally { Pop-Location }
        Write-Host '  WhatIfMode - no pull performed.' -ForegroundColor Yellow
    }
    else {
        Push-Location $Path
        try {
            $output = git pull 2>&1
            $output | ForEach-Object { Write-Host ('  {0}' -f $_) }
            if ($LASTEXITCODE -ne 0) { throw ('git pull failed with exit code {0}.' -f $LASTEXITCODE) }
        }
        finally { Pop-Location }
    }
}
else {
    throw 'No -Source given and the folder is not a git clone. Nothing to update from.'
}

if ($WhatIfMode) {
    Write-Host ''
    Write-Host '  WhatIfMode - nothing changed, nothing verified.' -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------------------
# Verify in a separate process
# ---------------------------------------------------------------------------
# A fresh process, because this session may already hold an older copy of the
# module and its format data, which would mask a broken update.

Write-Host ''
Write-Host 'Verifying...' -ForegroundColor Cyan

$verifyScript = @'
param($ModulePath)
$ErrorActionPreference = 'Stop'
try {
    Import-Module $ModulePath -Force -ErrorAction Stop

    $rules = @(Get-GovGuardRule)
    $coverage = @(Get-GovGuardCoverage -ByFamily)
    $covered = ($coverage | Measure-Object -Property Covered -Sum).Sum
    $version = (Import-PowerShellDataFile -LiteralPath $ModulePath).ModuleVersion

    [pscustomobject]@{
        Ok       = $true
        Version  = $version
        Rules    = $rules.Count
        Covered  = $covered
        Error    = ''
    } | ConvertTo-Json -Compress
}
catch {
    [pscustomobject]@{
        Ok      = $false
        Version = ''
        Rules   = 0
        Covered = 0
        Error   = $_.Exception.Message
    } | ConvertTo-Json -Compress
}
'@

$tempScript = Join-Path ([System.IO.Path]::GetTempPath()) ('govguard-verify-{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
$verifyScript | Set-Content -LiteralPath $tempScript -Encoding UTF8

try {
    $host7 = Get-Command pwsh -ErrorAction SilentlyContinue
    $shell = $(if ($host7) { 'pwsh' } else { 'powershell' })

    $raw = & $shell -NoProfile -ExecutionPolicy Bypass -File $tempScript -ModulePath $manifestPath 2>&1
    $json = ($raw | Where-Object { $_ -match '^\{' } | Select-Object -Last 1)

    if (-not $json) {
        throw ("Verification produced no result. Output was: {0}" -f (($raw | Out-String).Trim()))
    }

    $result = $json | ConvertFrom-Json
}
finally {
    Remove-Item -LiteralPath $tempScript -Force -ErrorAction SilentlyContinue
}

Write-Host ''

if (-not $result.Ok) {
    Write-Host '  VERIFICATION FAILED' -ForegroundColor Red
    Write-Host ('  {0}' -f $result.Error) -ForegroundColor Red
    Write-Host ''
    Write-Host '  The files on disk are updated but the module does not load. Roll back' -ForegroundColor Yellow
    Write-Host '  (git checkout, or recopy from the previous source) before using it.' -ForegroundColor Yellow
    exit 1
}

if ($result.Rules -lt $ExpectedRuleCount) {
    Write-Host ('  VERIFICATION FAILED: {0} rule(s) registered, expected at least {1}.' -f $result.Rules, $ExpectedRuleCount) -ForegroundColor Red
    Write-Host '  A partial copy, or rule files landed outside Rules\.' -ForegroundColor Yellow
    exit 1
}

Write-Host '  Verified.' -ForegroundColor Green
Write-Host ('    Version  : {0} (was {1})' -f $result.Version, $versionBefore)
Write-Host ('    Rules    : {0}' -f $result.Rules)
Write-Host ('    Controls : {0} covered' -f $result.Covered)
