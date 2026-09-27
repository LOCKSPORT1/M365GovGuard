<#
.SYNOPSIS
    Sorts a flat M365GovGuard download into the folder layout the module expects.

.DESCRIPTION
    Downloading the module file by file lands everything in one directory. The
    .psm1 dot-sources Private\, Public\ and Rules\ relative to itself, so a flat
    copy imports cleanly and exports nothing.

    This moves each file into its folder by name, leaves anything it does not
    recognise alone, and verifies the import afterwards. Safe to re-run.

.PARAMETER Path
    The folder holding the flat files.

.PARAMETER WhatIfMode
    Show what would move without moving anything.

.EXAMPLE
    .\Repair-GovGuardLayout.ps1 -Path D:\m365gov -WhatIfMode

.EXAMPLE
    .\Repair-GovGuardLayout.ps1 -Path D:\m365gov
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [switch]$WhatIfMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) {
    throw ("Path not found: {0}" -f $Path)
}

$layout = [ordered]@{
    'Private' = @(
        'GovGuardObjects.ps1'
        'Invoke-GovGuardGraph.ps1'
        'Resolve-GovCloud.ps1'
    )
    'Public'  = @(
        'Connect-GovGuard.ps1'
        'Export-GovGuardReport.ps1'
        'Get-GovGuardRule.ps1'
        'Invoke-GovGuardAudit.ps1'
    )
}

# Rules are matched by pattern so new rule files are picked up automatically.
$rulePattern = 'GOV-*.ps1'

$moved   = 0
$skipped = 0
$missing = @()

foreach ($folder in $layout.Keys) {
    $target = Join-Path $Path $folder

    foreach ($fileName in $layout[$folder]) {
        $source = Join-Path $Path $fileName

        if (-not (Test-Path -LiteralPath $source)) {
            if (Test-Path -LiteralPath (Join-Path $target $fileName)) {
                $skipped++   # already in place
            }
            else {
                $missing += $fileName
            }
            continue
        }

        if ($WhatIfMode) {
            Write-Host ("  WOULD MOVE  {0,-32} -> {1}\" -f $fileName, $folder)
            $moved++
            continue
        }

        if (-not (Test-Path -LiteralPath $target)) {
            New-Item -Path $target -ItemType Directory -Force | Out-Null
        }

        Move-Item -LiteralPath $source -Destination (Join-Path $target $fileName) -Force
        Write-Host ("  MOVED       {0,-32} -> {1}\" -f $fileName, $folder) -ForegroundColor Green
        $moved++
    }
}

# Rules
$ruleTarget = Join-Path $Path 'Rules'
$ruleFiles = @(Get-ChildItem -LiteralPath $Path -Filter $rulePattern -File -ErrorAction SilentlyContinue)

foreach ($ruleFile in $ruleFiles) {
    if ($WhatIfMode) {
        Write-Host ("  WOULD MOVE  {0,-32} -> Rules\" -f $ruleFile.Name)
        $moved++
        continue
    }

    if (-not (Test-Path -LiteralPath $ruleTarget)) {
        New-Item -Path $ruleTarget -ItemType Directory -Force | Out-Null
    }

    Move-Item -LiteralPath $ruleFile.FullName -Destination (Join-Path $ruleTarget $ruleFile.Name) -Force
    Write-Host ("  MOVED       {0,-32} -> Rules\" -f $ruleFile.Name) -ForegroundColor Green
    $moved++
}

$existingRules = @(Get-ChildItem -LiteralPath $ruleTarget -Filter $rulePattern -File -ErrorAction SilentlyContinue).Count

Write-Host ''
Write-Host ("  Moved: {0}   Already in place: {1}   Rules present: {2}" -f $moved, $skipped, $existingRules)

if ($missing.Count -gt 0) {
    Write-Host ''
    Write-Host '  Not found anywhere - download these again:' -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host ("    {0}" -f $_) -ForegroundColor Yellow }
}

if ($WhatIfMode) {
    Write-Host ''
    Write-Host '  WhatIfMode - nothing was moved.' -ForegroundColor Yellow
    return
}

# --- verify -----------------------------------------------------------------
$manifest = Join-Path $Path 'M365GovGuard.psd1'
if (-not (Test-Path -LiteralPath $manifest)) {
    Write-Host ''
    Write-Host ("  M365GovGuard.psd1 is not in {0} - cannot verify." -f $Path) -ForegroundColor Yellow
    return
}

Write-Host ''
try {
    $module = Import-Module -Name $manifest -Force -PassThru -ErrorAction Stop
    $count = $module.ExportedFunctions.Count

    if ($count -gt 0) {
        Write-Host ("  Import OK - {0} function(s) exported:" -f $count) -ForegroundColor Green
        $module.ExportedFunctions.Keys | Sort-Object | ForEach-Object { Write-Host ("    {0}" -f $_) }
        Write-Host ''
        Write-Host '  Launch-GovGuard.cmd should work now.' -ForegroundColor Green
    }
    else {
        Write-Host '  Import succeeded but still exports nothing.' -ForegroundColor Red
        Write-Host '  Run: Import-Module ''{0}'' -Force -PassThru -Verbose' -ForegroundColor Red
        Write-Host '  and look for a file that failed to load.' -ForegroundColor Red
    }
}
catch {
    Write-Host ('  Import failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    if ($_.Exception.Message -match 'Microsoft\.Graph\.Authentication') {
        Write-Host '  Fix: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' -ForegroundColor Yellow
    }
}
