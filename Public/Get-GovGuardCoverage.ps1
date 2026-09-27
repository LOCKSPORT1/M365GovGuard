function Get-GovGuardCoverage {
    <#
    .SYNOPSIS
        Which controls the rule set addresses, and which it does not.

    .DESCRIPTION
        The question a client facing an assessment asks is not "how many rules
        do you run" but "how much of the standard does this cover". Without a
        control catalog that question is unanswerable; with one it is
        arithmetic.

        Two things this deliberately does not claim. Coverage means a rule
        tests something relevant to the control, not that the control is
        satisfied - a rule can fail. And an automated check rarely covers a
        control in full, since most controls include policy and process
        elements no tool can see. Treat the output as scope, not as an
        assessment result.

    .PARAMETER Catalog
        Catalog name under Controls\. Defaults to the Rev 2 catalog.

    .PARAMETER Result
        Optional audit results. When supplied, each covered control also shows
        the pass and fail counts behind it.

    .PARAMETER ByFamily
        Summarise per control family instead of listing individual controls.

    .EXAMPLE
        Get-GovGuardCoverage -ByFamily

    .EXAMPLE
        $r = Invoke-GovGuardAudit
        Get-GovGuardCoverage -Result $r
    #>
    [CmdletBinding()]
    param(
        [string]$Catalog = 'nist-800-171-r2',
        [object[]]$Result,
        [switch]$ByFamily
    )

    $controlCatalog = Get-GovGuardControlCatalog -Name $Catalog
    $rules = @(Get-GovGuardRule)

    # control id -> rules touching it
    $rulesByControl = @{}
    foreach ($rule in $rules) {
        foreach ($controlId in @($rule.Controls)) {
            if (-not $rulesByControl.ContainsKey($controlId)) {
                $rulesByControl[$controlId] = @()
            }
            $rulesByControl[$controlId] += $rule.Id
        }
    }

    $statusByRule = @{}
    foreach ($item in @($Result)) {
        if ($null -eq $item) { continue }
        $names = @($item.PSObject.Properties.Name)
        if ($names -notcontains 'RuleId' -or $names -notcontains 'Status') { continue }
        $statusByRule[$item.RuleId] = $item.Status
    }

    if ($ByFamily) {
        $rows = foreach ($familyId in ($controlCatalog.Families.Keys | Sort-Object { [version]($_ -replace '^3\.', '3.') })) {
            $family = $controlCatalog.Families[$familyId]
            $covered = @($family.ControlIds | Where-Object { $rulesByControl.ContainsKey($_) })

            [pscustomobject]@{
                Family     = '{0} {1}' -f $family.Id, $family.Name
                Controls   = $family.ControlCount
                Covered    = $covered.Count
                Percent    = [math]::Round(($covered.Count / [double]$family.ControlCount) * 100, 0)
                CoveredIds = ($covered -join ', ')
            }
        }
        return @($rows)
    }

    $rows = foreach ($controlId in ($rulesByControl.Keys | Sort-Object)) {
        if (-not $controlCatalog.Controls.ContainsKey($controlId)) { continue }
        $control = $controlCatalog.Controls[$controlId]
        $ruleIds = @($rulesByControl[$controlId])

        $statuses = @($ruleIds | ForEach-Object { if ($statusByRule.ContainsKey($_)) { $statusByRule[$_] } })

        [pscustomobject]@{
            Control      = $control.Id
            CmmcPractice = $control.CmmcPractice
            Family       = $control.FamilyName
            Title        = $(if ($control.Title) { $control.Title } else { '(title not yet transcribed)' })
            Rules        = ($ruleIds -join ', ')
            Failing      = @($statuses | Where-Object { $_ -eq 'Fail' }).Count
            Passing      = @($statuses | Where-Object { $_ -eq 'Pass' }).Count
        }
    }

    $totalCovered = $rulesByControl.Keys.Count
    Write-Verbose -Message ('{0} of {1} {2} {3} controls addressed by {4} rule(s).' -f `
        $totalCovered, $controlCatalog.ControlCount, $controlCatalog.Framework, $controlCatalog.Revision, $rules.Count)

    return @($rows)
}
