<#
.SYNOPSIS
    Builds a GovGuard control catalog from a published source.

.DESCRIPTION
    A build-time tool, not a runtime dependency. Run it once when you adopt or
    update a standard; the module reads only the generated .psd1.

    That separation is deliberate. A GCC High tenant is frequently administered
    from a network with no route to GitHub, so a tool that fetches its control
    catalog at startup is a tool that fails in the environment it was built for.
    The catalog ships with the module; this script regenerates it.

    Two input shapes:

    OSCAL   NIST's Open Security Controls Assessment Language JSON. Structure is
            catalog.groups[].controls[], each control carrying an id, a title, a
            'label' prop and statement text under parts[name=statement]. Groups
            nest, so the walk is recursive.

    CSV     A flat crosswalk table - the shape the CMMC assessment guide
            material and most community extracts use. Column names are
            parameters because every publisher names them differently.

    Whatever the source, the output records where it came from: URL or path,
    SHA-256 of the input, the date retrieved, and this script's version. When
    an assessor asks why your control text should be trusted, that block is the
    answer.

.PARAMETER OscalPath
    Path to an OSCAL catalog JSON file.

.PARAMETER CsvPath
    Path to a flat CSV of controls.

.PARAMETER OutputPath
    Where to write the .psd1. Defaults to Controls\ beside this script's module.

.PARAMETER Framework
    Framework name recorded in the catalog. Default 'NIST SP 800-171'.

.PARAMETER Revision
    Revision recorded in the catalog. Default 'Rev 2'.

.PARAMETER SourceUrl
    The URL the input came from, recorded for provenance. Strongly recommended.

.PARAMETER ExpectedControlCount
    Fail if the parsed control count does not match. 110 for 800-171.
    A silent miscount makes every coverage percentage wrong.

.PARAMETER IdColumn
    CSV only. Column holding the control id (e.g. 3.1.1). Default 'id'.

.PARAMETER FamilyColumn
    CSV only. Column holding the family name. Default 'family'.

.PARAMETER TitleColumn
    CSV only. Column holding a short title. Default 'title'.

.PARAMETER StatementColumn
    CSV only. Column holding the requirement statement. Default 'description'.

.PARAMETER WhatIfMode
    Parse and report without writing the output file.

.EXAMPLE
    .\Convert-ControlCatalog.ps1 -OscalPath .\NIST_SP-800-171_rev2_catalog.json `
        -SourceUrl 'https://.../NIST_SP-800-171_rev2_catalog.json' `
        -ExpectedControlCount 110 -WhatIfMode

.EXAMPLE
    .\Convert-ControlCatalog.ps1 -CsvPath .\cmmc-crosswalk.csv `
        -IdColumn 'NIST 800-171 Rev2' -FamilyColumn 'Domain' `
        -StatementColumn 'Requirement Statement' -ExpectedControlCount 110

.NOTES
    Written against the real OSCAL structure as published in usnistgov/oscal-content.
    Verify the source file you feed it: an 800-171 OSCAL catalog was not present
    in that repository at the paths commonly cited, so confirm what you have is
    actually 800-171 and actually the revision you intend.
#>
[CmdletBinding(DefaultParameterSetName = 'Oscal')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Oscal')]
    [string]$OscalPath,

    [Parameter(Mandatory, ParameterSetName = 'Csv')]
    [string]$CsvPath,

    [string]$OutputPath,

    [string]$Framework = 'NIST SP 800-171',
    [string]$Revision  = 'Rev 2',
    [string]$SourceUrl = '',

    [int]$ExpectedControlCount = 0,

    [Parameter(ParameterSetName = 'Csv')][string]$IdColumn        = 'id',
    [Parameter(ParameterSetName = 'Csv')][string]$FamilyColumn    = 'family',
    [Parameter(ParameterSetName = 'Csv')][string]$TitleColumn     = 'title',
    [Parameter(ParameterSetName = 'Csv')][string]$StatementColumn = 'description',

    [switch]$WhatIfMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptVersion = '1.0'

# Family abbreviations for 800-171. CMMC Level 2 practice codes are the family
# abbreviation, '.L2-', and the control id, so these are all that is needed to
# derive practice codes rather than storing them twice.
$familyAbbreviations = @{
    '3.1'  = @{ Abbr = 'AC'; Name = 'Access Control' }
    '3.2'  = @{ Abbr = 'AT'; Name = 'Awareness and Training' }
    '3.3'  = @{ Abbr = 'AU'; Name = 'Audit and Accountability' }
    '3.4'  = @{ Abbr = 'CM'; Name = 'Configuration Management' }
    '3.5'  = @{ Abbr = 'IA'; Name = 'Identification and Authentication' }
    '3.6'  = @{ Abbr = 'IR'; Name = 'Incident Response' }
    '3.7'  = @{ Abbr = 'MA'; Name = 'Maintenance' }
    '3.8'  = @{ Abbr = 'MP'; Name = 'Media Protection' }
    '3.9'  = @{ Abbr = 'PS'; Name = 'Personnel Security' }
    '3.10' = @{ Abbr = 'PE'; Name = 'Physical Protection' }
    '3.11' = @{ Abbr = 'RA'; Name = 'Risk Assessment' }
    '3.12' = @{ Abbr = 'CA'; Name = 'Security Assessment' }
    '3.13' = @{ Abbr = 'SC'; Name = 'System and Communications Protection' }
    '3.14' = @{ Abbr = 'SI'; Name = 'System and Information Integrity' }
}

function Get-FamilyIdFromControlId {
    # 3.1.20 -> 3.1   Everything before the last dot.
    param([string]$ControlId)
    $lastDot = $ControlId.LastIndexOf('.')
    if ($lastDot -lt 1) { return $null }
    return $ControlId.Substring(0, $lastDot)
}

function Get-OscalPropValue {
    param($Node, [string]$Name)
    if (-not $Node) { return $null }
    if (@($Node.PSObject.Properties.Name) -notcontains 'props') { return $null }
    foreach ($prop in @($Node.props)) {
        if ($prop.name -eq $Name) { return $prop.value }
    }
    return $null
}

function Get-OscalStatement {
    <#
        Statement text lives under parts[name=statement], often as nested item
        parts rather than a single prose string. Flatten what is there.
    #>
    param($Control)

    if (@($Control.PSObject.Properties.Name) -notcontains 'parts') { return '' }

    $collected = @()

    foreach ($part in @($Control.parts)) {
        if ($part.name -ne 'statement') { continue }

        if (@($part.PSObject.Properties.Name) -contains 'prose' -and $part.prose) {
            $collected += $part.prose
        }

        foreach ($sub in @($part.parts)) {
            if (@($sub.PSObject.Properties.Name) -contains 'prose' -and $sub.prose) {
                $collected += $sub.prose
            }
        }
    }

    $text = ($collected -join ' ').Trim()

    # OSCAL parameter placeholders are noise in a catalog used for labelling.
    $text = $text -replace '\{\{\s*insert:[^}]*\}\}', '[assignment]'
    $text = $text -replace '\s+', ' '
    return $text.Trim()
}

function Get-OscalControlsRecursive {
    # Groups nest in OSCAL; controls can appear at any depth.
    param($Node)

    $found = @()

    if (@($Node.PSObject.Properties.Name) -contains 'controls') {
        foreach ($control in @($Node.controls)) {
            $found += $control
            $found += Get-OscalControlsRecursive -Node $control
        }
    }

    if (@($Node.PSObject.Properties.Name) -contains 'groups') {
        foreach ($group in @($Node.groups)) {
            $found += Get-OscalControlsRecursive -Node $group
        }
    }

    return $found
}

# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

$sourcePath = if ($PSCmdlet.ParameterSetName -eq 'Oscal') { $OscalPath } else { $CsvPath }

if (-not (Test-Path -LiteralPath $sourcePath)) {
    throw ("Source file not found: {0}" -f $sourcePath)
}

$sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash

# id -> @{ Title; Statement; FamilyName }
$parsed = [ordered]@{}

if ($PSCmdlet.ParameterSetName -eq 'Oscal') {

    Write-Host ("Parsing OSCAL catalog: {0}" -f $sourcePath) -ForegroundColor Cyan
    $document = Get-Content -LiteralPath $sourcePath -Raw | ConvertFrom-Json

    if (@($document.PSObject.Properties.Name) -notcontains 'catalog') {
        throw 'Not an OSCAL catalog: no top-level "catalog" property.'
    }

    $catalog = $document.catalog

    foreach ($group in @($catalog.groups)) {
        $groupTitle = $group.title

        foreach ($control in (Get-OscalControlsRecursive -Node $group)) {

            # The label prop carries the human-facing identifier (3.1.1);
            # control.id is the OSCAL slug and may be normalised differently.
            $label = Get-OscalPropValue -Node $control -Name 'label'
            $id = if ($label) { $label } else { $control.id }
            if (-not $id) { continue }

            $id = ([string]$id).Trim()

            $parsed[$id] = @{
                Title      = [string]$control.title
                Statement  = Get-OscalStatement -Control $control
                FamilyName = [string]$groupTitle
            }
        }
    }
}
else {

    Write-Host ("Parsing CSV: {0}" -f $sourcePath) -ForegroundColor Cyan

    # UTF-8 BOM is common on published CSVs; PowerShell 5.1 would otherwise
    # fold it into the first column name.
    $rows = @(Import-Csv -LiteralPath $sourcePath -Encoding UTF8)

    if ($rows.Count -eq 0) { throw 'CSV contained no rows.' }

    $columns = @($rows[0].PSObject.Properties.Name)

    # Publishers ship untidy headers - NIST's own 800-171 CSV names its
    # requirement column with a leading space. Match on the trimmed,
    # case-insensitive name and resolve back to the real one, so the caller
    # never has to reproduce whitespace they cannot see.
    function Resolve-Column {
        param([string]$Wanted, [string[]]$Available)
        if (-not $Wanted) { return $null }
        foreach ($actual in $Available) {
            if ($actual.Trim() -eq $Wanted.Trim()) { return $actual }
            if ($actual.Trim().ToLowerInvariant() -eq $Wanted.Trim().ToLowerInvariant()) { return $actual }
        }
        return $null
    }

    $idCol        = Resolve-Column -Wanted $IdColumn        -Available $columns
    $titleCol     = Resolve-Column -Wanted $TitleColumn     -Available $columns
    $statementCol = Resolve-Column -Wanted $StatementColumn -Available $columns
    $familyCol    = Resolve-Column -Wanted $FamilyColumn    -Available $columns

    if (-not $idCol) {
        throw ("CSV has no column matching '{0}'. Columns present: {1}" -f $IdColumn, (($columns | ForEach-Object { "'$_'" }) -join ', '))
    }

    if (-not $statementCol) {
        Write-Warning ("No column matching '{0}' - control text will fall back to the title column or be empty." -f $StatementColumn)
    }

    foreach ($row in $rows) {
        $id = ([string]$row.$idCol).Trim()
        if (-not $id) { continue }

        $title = ''
        if ($titleCol) { $title = [string]$row.$titleCol }

        $statement = ''
        if ($statementCol) { $statement = [string]$row.$statementCol }

        $familyName = ''
        if ($familyCol) { $familyName = [string]$row.$familyCol }

        $parsed[$id] = @{
            Title      = $title.Trim()
            Statement  = ($statement -replace '\s+', ' ').Trim()
            FamilyName = $familyName.Trim()
        }
    }
}

Write-Host ("Parsed {0} control(s)." -f $parsed.Keys.Count)

if ($ExpectedControlCount -gt 0 -and $parsed.Keys.Count -ne $ExpectedControlCount) {
    throw ("Expected {0} controls, parsed {1}. Refusing to write a catalog that would make every coverage figure wrong. Check the source file is the right standard and revision." -f `
        $ExpectedControlCount, $parsed.Keys.Count)
}

# ---------------------------------------------------------------------------
# Group by family
# ---------------------------------------------------------------------------

$byFamily = [ordered]@{}
$unknownFamilies = @()

foreach ($id in $parsed.Keys) {
    $familyId = Get-FamilyIdFromControlId -ControlId $id
    if (-not $familyId) {
        $unknownFamilies += $id
        continue
    }

    if (-not $byFamily.Contains($familyId)) {
        $byFamily[$familyId] = @()
    }
    $byFamily[$familyId] += $id
}

if ($unknownFamilies.Count -gt 0) {
    Write-Warning ("{0} control id(s) did not parse into a family and were skipped: {1}" -f `
        $unknownFamilies.Count, ($unknownFamilies -join ', '))
}

# Sort families and controls numerically, not as strings - 3.10 must not sort
# before 3.2.
function Get-SortKey {
    param([string]$Id)
    $parts = $Id -split '\.'
    $padded = foreach ($part in $parts) { '{0:D4}' -f [int]$part }
    return ($padded -join '.')
}

$sortedFamilyIds = @($byFamily.Keys | Sort-Object { Get-SortKey -Id $_ })

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

if (-not $OutputPath) {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    $slug = ('{0}-{1}' -f $Framework, $Revision).ToLowerInvariant() -replace '[^a-z0-9]+', '-'
    $slug = $slug.Trim('-')
    $OutputPath = Join-Path $moduleRoot ('Controls\{0}.psd1' -f $slug)
}

$builder = [System.Text.StringBuilder]::new()
$null = $builder.AppendLine('<#')
$null = $builder.AppendLine('    GENERATED FILE - do not edit by hand.')
$null = $builder.AppendLine('')
$null = $builder.AppendLine('    Produced by Tools\Convert-ControlCatalog.ps1. Regenerate rather than')
$null = $builder.AppendLine('    editing; hand edits are lost on the next build and break provenance.')
$null = $builder.AppendLine('#>')
$null = $builder.AppendLine('@{')
$null = $builder.AppendLine('')
$null = $builder.AppendLine(("    Framework    = '{0}'" -f ($Framework -replace "'", "''")))
$null = $builder.AppendLine(("    Revision     = '{0}'" -f ($Revision -replace "'", "''")))
$null = $builder.AppendLine(("    ControlCount = {0}" -f $parsed.Keys.Count))
$null = $builder.AppendLine('')
$null = $builder.AppendLine('    Provenance = @{')
$null = $builder.AppendLine(("        SourceUrl    = '{0}'" -f ($SourceUrl -replace "'", "''")))
$null = $builder.AppendLine(("        SourceFile   = '{0}'" -f ((Split-Path -Leaf $sourcePath) -replace "'", "''")))
$null = $builder.AppendLine(("        SourceSha256 = '{0}'" -f $sourceHash))
$null = $builder.AppendLine(("        Retrieved    = '{0}'" -f (Get-Date -Format 'yyyy-MM-dd')))
$null = $builder.AppendLine(("        Generator    = 'Convert-ControlCatalog.ps1 v{0}'" -f $scriptVersion))
$null = $builder.AppendLine(("        InputFormat  = '{0}'" -f $PSCmdlet.ParameterSetName))
$null = $builder.AppendLine('    }')
$null = $builder.AppendLine('')
$null = $builder.AppendLine('    Families = @(')

foreach ($familyId in $sortedFamilyIds) {

    $abbr = ''
    $name = ''
    if ($familyAbbreviations.ContainsKey($familyId)) {
        $abbr = $familyAbbreviations[$familyId].Abbr
        $name = $familyAbbreviations[$familyId].Name
    }
    else {
        # Fall back to whatever the source called it.
        $firstId = @($byFamily[$familyId])[0]
        $name = $parsed[$firstId].FamilyName
        Write-Warning ("No abbreviation known for family '{0}'; CMMC practice codes for it will be blank." -f $familyId)
    }

    $controlIds = @($byFamily[$familyId] | Sort-Object { Get-SortKey -Id $_ })

    $null = $builder.AppendLine('        @{')
    $null = $builder.AppendLine(("            Id           = '{0}'" -f $familyId))
    $null = $builder.AppendLine(("            Abbreviation = '{0}'" -f $abbr))
    $null = $builder.AppendLine(("            Name         = '{0}'" -f ($name -replace "'", "''")))
    $null = $builder.AppendLine(("            ControlCount = {0}" -f $controlIds.Count))
    $null = $builder.AppendLine('            Controls     = @(')

    foreach ($controlId in $controlIds) {
        $entry = $parsed[$controlId]

        # Prefer the requirement statement; fall back to the short title.
        $text = if ($entry.Statement) { $entry.Statement } else { $entry.Title }
        $text = $text -replace "'", "''"

        $null = $builder.AppendLine(("                @{{ Id = '{0}'; Title = '{1}' }}" -f $controlId, $text))
    }

    $null = $builder.AppendLine('            )')
    $null = $builder.AppendLine('        }')
    $null = $builder.AppendLine('')
}

$null = $builder.AppendLine('    )')
$null = $builder.AppendLine('}')

Write-Host ''
Write-Host ('  Families : {0}' -f $sortedFamilyIds.Count)
Write-Host ('  Controls : {0}' -f $parsed.Keys.Count)
Write-Host ('  Source   : {0}' -f $sourceHash.Substring(0, 16) + '...')
Write-Host ('  Output   : {0}' -f $OutputPath)

if ($WhatIfMode) {
    Write-Host ''
    Write-Host '  WhatIfMode - nothing written. First three families:' -ForegroundColor Yellow
    foreach ($familyId in ($sortedFamilyIds | Select-Object -First 3)) {
        Write-Host ('    {0}  {1} control(s)' -f $familyId, @($byFamily[$familyId]).Count)
    }
    return
}

$outputDir = Split-Path -Parent $OutputPath
if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
}

$builder.ToString() | Set-Content -LiteralPath $OutputPath -Encoding UTF8

# Round-trip it, because a catalog that will not parse is worse than none.
try {
    $check = Import-PowerShellDataFile -LiteralPath $OutputPath
    $written = @($check.Families | ForEach-Object { $_.Controls }).Count
    Write-Host ''
    Write-Host ('  Written and verified: {0} control(s) parse back cleanly.' -f $written) -ForegroundColor Green
}
catch {
    throw ("Catalog was written but does not parse: {0}" -f $_.Exception.Message)
}
