function Get-GovGuardControlCatalog {
    <#
    .SYNOPSIS
        Loads the control catalog and caches it for the session.

    .DESCRIPTION
        Rules reference control ids; this catalog owns what those ids mean.
        Keeping the standard in one data file means a revision is a new file
        plus a crosswalk rather than an edit to every rule, and it makes
        coverage answerable - you cannot say "9 of 110" without knowing that
        110 exist.

    .PARAMETER Name
        Catalog file name under Controls\, without the extension.
        Defaults to the Rev 2 catalog, which is what CMMC Level 2 assesses against.

    .PARAMETER Refresh
        Reload from disk rather than using the cached copy.
    #>
    [CmdletBinding()]
    param(
        [string]$Name = 'nist-800-171-r2',
        [switch]$Refresh
    )

    # Set-StrictMode makes reading an undeclared script variable a hard error,
    # so probe for it rather than testing its value. The module declares it at
    # import; this keeps the function usable if it is dot-sourced on its own.
    if (-not (Get-Variable -Name 'GovGuardCatalogCache' -Scope Script -ErrorAction SilentlyContinue)) {
        $script:GovGuardCatalogCache = @{}
    }

    if (-not $Refresh -and $script:GovGuardCatalogCache.ContainsKey($Name)) {
        return $script:GovGuardCatalogCache[$Name]
    }

    $path = Join-Path -Path $script:ModuleRoot -ChildPath ('Controls\{0}.psd1' -f $Name)
    if (-not (Test-Path -LiteralPath $path)) {
        throw ("Control catalog not found: {0}" -f $path)
    }

    $data = Import-PowerShellDataFile -LiteralPath $path

    # Flatten to an id-keyed index, and verify the declared count matches what
    # is actually in the file. A catalog that silently lost a control would make
    # every coverage percentage wrong.
    $index = @{}
    $families = @{}

    foreach ($family in @($data.Families)) {
        $families[$family.Id] = [pscustomobject]@{
            Id           = $family.Id
            Abbreviation = $family.Abbreviation
            Name         = $family.Name
            ControlCount = $family.ControlCount
            ControlIds   = @($family.Controls | ForEach-Object { $_.Id })
        }

        foreach ($control in @($family.Controls)) {
            $index[$control.Id] = [pscustomobject]@{
                Id           = $control.Id
                Title        = $control.Title
                FamilyId     = $family.Id
                FamilyName   = $family.Name
                Abbreviation = $family.Abbreviation
                # CMMC L2 practice codes are one-to-one with 800-171 Rev 2
                # controls, so they are derived rather than stored twice.
                CmmcPractice = '{0}.L2-{1}' -f $family.Abbreviation, $control.Id
            }
        }
    }

    if ($index.Keys.Count -ne $data.ControlCount) {
        Write-Warning -Message ("Catalog '{0}' declares {1} controls but contains {2}." -f `
            $Name, $data.ControlCount, $index.Keys.Count)
    }

    $catalog = [pscustomobject]@{
        Name         = $Name
        Framework    = $data.Framework
        Revision     = $data.Revision
        ControlCount = $data.ControlCount
        Families     = $families
        Controls     = $index
        Note         = $(if ($data.ContainsKey('Note')) { $data.Note } else { '' })
        # Where this catalog came from. A hand-maintained file has none, which
        # is itself worth knowing when the numbers land in front of an assessor.
        Provenance   = $(if ($data.ContainsKey('Provenance')) { [pscustomobject]$data.Provenance } else { $null })
    }

    $script:GovGuardCatalogCache[$Name] = $catalog
    return $catalog
}

function Resolve-GovGuardControl {
    <#
    .SYNOPSIS
        Turns control ids into catalog entries, warning on anything unknown.

    .DESCRIPTION
        An unknown control id is a typo that would otherwise sit in an
        assessor-facing report looking authoritative. Resolution happens when a
        rule is registered, so a mistake surfaces at import rather than in a
        deliverable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$ControlId,

        [string]$RuleId = '(unknown rule)'
    )

    if ($ControlId.Count -eq 0) { return @() }

    $catalog = Get-GovGuardControlCatalog
    $resolved = @()

    foreach ($id in $ControlId) {
        if ($catalog.Controls.ContainsKey($id)) {
            $resolved += $catalog.Controls[$id]
        }
        else {
            Write-Warning -Message ("Rule {0} references control '{1}', which is not in the {2} {3} catalog." -f `
                $RuleId, $id, $catalog.Framework, $catalog.Revision)
        }
    }

    return $resolved
}

function Format-GovGuardControlLabel {
    <#
    .SYNOPSIS
        Display strings for a set of resolved controls, for reports and output.

    .EXAMPLE
        Format-GovGuardControlLabel -Control $resolved
        # NIST 800-171 3.1.5, CMMC AC.L2-3.1.5
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Control
    )

    $labels = @()
    foreach ($item in $Control) {
        $labels += ('NIST 800-171 {0}' -f $item.Id)
        $labels += ('CMMC {0}' -f $item.CmmcPractice)
    }
    return $labels
}
