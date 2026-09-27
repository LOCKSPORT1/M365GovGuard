function New-GovGuardRule {
    <#
    .SYNOPSIS
        Builds a rule object. This is the contract every rule file implements.

    .PARAMETER Clouds
        Which clouds the rule applies to. A rule that targets a GCC High-only
        concern lists only USGov/USGovDoD and is reported NotApplicable elsewhere,
        instead of producing a false failure.

    .PARAMETER Test
        param($Context) -> hashtable with keys:
            Status   'Pass' | 'Fail' | 'NotApplicable'
            Message  one-line human summary
            Evidence object captured for the report / assessor package

    .PARAMETER Remediate
        param($Context, $Finding, [bool]$WhatIfMode) -> hashtable with keys:
            Status   'Remediated' | 'WouldRemediate' | 'Skipped' | 'Failed'
            Message  what changed, or what would change
            Changes  array of change descriptors

        Must be idempotent and must honour $WhatIfMode by making no write calls.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Global', 'USGov', 'USGovDoD')][string[]]$Clouds,
        [Parameter(Mandatory)][scriptblock]$Test,

        [hashtable]$SeverityByCloud = @{},
        [string[]]$Controls     = @(),
        [string[]]$Frameworks   = @(),
        [string[]]$Scopes       = @(),
        [string[]]$WriteScopes  = @(),
        [scriptblock]$Remediate,
        [string]$Rationale      = '',
        [string]$ManualFix      = '',
        [string]$Reference      = ''
    )

    # Controls are resolved against the catalog now, not when a report is
    # written, so a typo fails loudly at import instead of appearing in a
    # deliverable. Frameworks stays for mappings the catalog does not own -
    # CIS benchmarks, ITAR citations, anything non-NIST.
    $resolvedControls = @()
    if ($Controls.Count -gt 0) {
        $resolvedControls = @(Resolve-GovGuardControl -ControlId $Controls -RuleId $Id)
        $Frameworks = @(@(Format-GovGuardControlLabel -Control $resolvedControls) + $Frameworks)
    }

    $rule = [pscustomobject]@{
        Id          = $Id
        Title       = $Title
        Severity    = $Severity
        # Same finding, different weight depending on the obligation. A missing
        # country restriction is Critical where ITAR applies and advisory where
        # it does not; one severity for both trains people to ignore the rule.
        SeverityByCloud = $SeverityByCloud
        Category    = $Category
        Clouds      = $Clouds
        Controls    = @($resolvedControls | ForEach-Object { $_.Id })
        ControlDetail = $resolvedControls
        Frameworks  = $Frameworks
        Scopes      = $Scopes
        WriteScopes = $WriteScopes
        Remediable  = ($null -ne $Remediate)
        Test        = $Test
        Remediate   = $Remediate
        Rationale   = $Rationale
        ManualFix   = $ManualFix
        Reference   = $Reference
    }

    $rule.PSObject.TypeNames.Insert(0, 'GovGuard.Rule')
    return $rule
}

function New-GovGuardResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Rule,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'NotApplicable', 'Error')][string]$Status,
        [string]$Message = '',
        [object]$Evidence,
        [object]$Context,
        [string]$Severity
    )

    $effectiveSeverity = $Rule.Severity
    if ($Severity) { $effectiveSeverity = $Severity }

    $result = [pscustomobject]@{
        RuleId            = $Rule.Id
        Title             = $Rule.Title
        Severity          = $effectiveSeverity
        BaseSeverity      = $Rule.Severity
        Category          = $Rule.Category
        Status            = $Status
        Message           = $Message
        Evidence          = $Evidence
        Frameworks        = $Rule.Frameworks
        Controls          = $Rule.Controls
        Rationale         = $Rule.Rationale
        Remediable        = $Rule.Remediable
        RemediationStatus = 'NotAttempted'
        RemediationMessage= ''
        Changes           = @()
        ManualFix         = $Rule.ManualFix
        TenantId          = $(if ($Context) { $Context.TenantId } else { $null })
        TenantName        = $(if ($Context) { $Context.TenantName } else { $null })
        Cloud             = $(if ($Context) { $Context.Cloud } else { $null })
        Timestamp         = (Get-Date).ToUniversalTime().ToString('o')
    }

    $result.PSObject.TypeNames.Insert(0, 'GovGuard.Result')

    # No DefaultDisplayPropertySet here on purpose. A property set overrides view
    # selection from the format file, and the default formatter then chooses list
    # or table on its own width heuristic - which is how the table view ends up
    # being ignored. Display belongs to M365GovGuard.format.ps1xml alone.

    return $result
}

function ConvertTo-GovGuardHtmlText {
    <#
    .SYNOPSIS
        Minimal HTML encoder. Avoids a System.Web dependency so the module
        behaves the same on Windows PowerShell 5.1 and PowerShell 7.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [object]$Text
    )

    if ($null -eq $Text) { return '' }

    $value = [string]$Text
    $value = $value -replace '&', '&amp;'
    $value = $value -replace '<', '&lt;'
    $value = $value -replace '>', '&gt;'
    $value = $value -replace '"', '&quot;'
    return $value
}
