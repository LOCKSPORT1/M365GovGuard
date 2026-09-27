function Invoke-GovGuardAudit {
    <#
    .SYNOPSIS
        Runs the rule set against the connected tenant and optionally remediates.

    .DESCRIPTION
        Rules that do not apply to the connected cloud are reported
        NotApplicable rather than Failed - a GCC High tenant should not show
        forty failures for workloads Microsoft has not shipped there.

        Remediation is opt-in and dry-run by default:

            -Remediate                 nothing is written, every fix is previewed
            -Remediate -WhatIfMode:$false -Force   writes are executed

    .PARAMETER Id
        Run only these rule ids. Example: GOV-IAM-018, GOV-CA-012.

    .PARAMETER Category
        Run only rules in these categories: Identity, ConditionalAccess,
        Authentication, ExternalCollaboration.

    .PARAMETER Severity
        Run only rules at these severities.

    .PARAMETER Framework
        Run only rules whose control mapping contains this text. Example: CMMC,
        or 800-171, or a specific control like 3.1.20.

    .PARAMETER Remediate
        Attempt remediation of failed, remediable rules.

    .PARAMETER WhatIfMode
        Defaults to $true. Set to $false to actually write. Kept as an explicit
        parameter rather than relying on -WhatIf so the mode is visible in
        scheduled-task command lines and in the report output.

    .PARAMETER Force
        Required alongside -WhatIfMode:$false. Guards against a scheduled audit
        job mutating a client tenant because someone fat-fingered a switch.

    .PARAMETER ReportPath
        Write a JSON evidence bundle and an HTML report to this folder when the
        run finishes. A relative path resolves against the module folder, so
        'Reports' lands beside the module wherever it is installed.

    .PARAMETER ClientName
        Name for the report header and file name. Defaults to the tenant name.

    .PARAMETER IncludeEvidence
        Embed evidence payloads in the HTML report. Useful internally, usually
        noise in a client read-out.

    .PARAMETER IncludeNotApplicable
        Also report rules that do not apply to this cloud, instead of omitting
        them. Worth turning on for an evidence export: a rule that was evaluated
        and found not applicable is a different statement to an assessor than
        a rule that is simply absent from the report.

    .EXAMPLE
        Invoke-GovGuardAudit | Format-Table RuleId, Status, Severity, Title

    .EXAMPLE
        Invoke-GovGuardAudit -Severity Critical, High -Remediate

    .EXAMPLE
        Invoke-GovGuardAudit -Id GOV-AUTH-008 -Remediate -WhatIfMode:$false -Force
    #>
    [CmdletBinding()]
    param(
        [string[]]$Id,
        [string[]]$Category,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string[]]$Severity,
        [string]$Framework,

        [switch]$Remediate,
        [bool]$WhatIfMode = $true,
        [switch]$Force,

        [switch]$IncludeNotApplicable,

        [string]$ReportPath,
        [string]$ClientName,
        [switch]$IncludeEvidence
    )

    $context = Get-GovGuardContext

    if ($Remediate -and -not $WhatIfMode -and -not $Force) {
        throw 'Live remediation requires -Force alongside -WhatIfMode:$false.'
    }
    if ($Remediate -and -not $WhatIfMode -and -not $context.HasWriteScopes) {
        throw 'Connected session has no ReadWrite scopes. Reconnect with -IncludeWriteScopes.'
    }

    # Deliberately not filtered by cloud here: out-of-scope rules are reported
    # as NotApplicable rather than vanishing from the evidence package.
    $candidateFilter = @{}
    if ($Id)        { $candidateFilter['Id'] = $Id }
    if ($Category)  { $candidateFilter['Category'] = $Category }
    if ($Severity)  { $candidateFilter['Severity'] = $Severity }
    if ($Framework) { $candidateFilter['Framework'] = $Framework }

    $rules = @(Get-GovGuardRule @candidateFilter)

    if ($rules.Count -eq 0) {
        Write-Warning -Message 'No rules matched the filter.'
        return @()
    }

    Write-Verbose -Message ("Running {0} rule(s) against {1} [{2}]." -f $rules.Count, $context.TenantName, $context.Cloud)

    $results = [System.Collections.Generic.List[object]]::new()
    $ruleIndex = 0

    foreach ($rule in $rules) {
        $ruleIndex++
        Write-Progress -Activity 'GovGuard audit' -Status $rule.Id -PercentComplete (($ruleIndex / $rules.Count) * 100)

        # --- applicability -------------------------------------------------
        if ($rule.Clouds -notcontains $context.Cloud) {
            if ($IncludeNotApplicable) {
                $results.Add((New-GovGuardResult -Rule $rule -Status 'NotApplicable' -Context $context `
                    -Message ("Rule targets {0}; tenant is {1}." -f ($rule.Clouds -join '/'), $context.Cloud)))
            }
            continue
        }

        # --- test ----------------------------------------------------------
        $result = $null
        try {
            $outcome = & $rule.Test $context

            if ($null -eq $outcome -or -not $outcome.ContainsKey('Status')) {
                throw 'Test scriptblock returned no Status.'
            }

            $evidence = $null
            if ($outcome.ContainsKey('Evidence')) { $evidence = $outcome['Evidence'] }
            $message = ''
            if ($outcome.ContainsKey('Message')) { $message = [string]$outcome['Message'] }

            # Effective severity: the rule's per-cloud table, or an override the
            # Test itself returned, or the declared default.
            $effectiveSeverity = $rule.Severity
            if ($rule.SeverityByCloud -and $rule.SeverityByCloud.ContainsKey($context.Cloud)) {
                $effectiveSeverity = $rule.SeverityByCloud[$context.Cloud]
            }
            if ($outcome.ContainsKey('Severity') -and $outcome['Severity']) {
                $effectiveSeverity = $outcome['Severity']
            }

            $result = New-GovGuardResult -Rule $rule -Status $outcome['Status'] -Message $message `
                -Evidence $evidence -Context $context -Severity $effectiveSeverity
        }
        catch {
            $result = New-GovGuardResult -Rule $rule -Status 'Error' -Context $context `
                -Message ("Test failed: {0}" -f $_.Exception.Message)
        }

        # --- remediate -----------------------------------------------------
        if ($Remediate -and $result.Status -eq 'Fail') {
            if (-not $rule.Remediable) {
                $result.RemediationStatus = 'NotSupported'
                $result.RemediationMessage = 'Rule is detect-only by design. See ManualFix.'
            }
            else {
                try {
                    $fix = & $rule.Remediate $context $result $WhatIfMode

                    if ($null -eq $fix -or -not $fix.ContainsKey('Status')) {
                        throw 'Remediate scriptblock returned no Status.'
                    }

                    $result.RemediationStatus = $fix['Status']
                    if ($fix.ContainsKey('Message')) { $result.RemediationMessage = [string]$fix['Message'] }
                    if ($fix.ContainsKey('Changes')) { $result.Changes = @($fix['Changes']) }
                }
                catch {
                    $result.RemediationStatus = 'Failed'
                    $result.RemediationMessage = $_.Exception.Message
                }
            }
        }

        $results.Add($result)
    }

    Write-Progress -Activity 'GovGuard audit' -Completed

    $summary = $results | Group-Object -Property Status | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }
    Write-Verbose -Message ("Audit complete: {0}" -f ($summary -join ' '))

    if ($Remediate -and $WhatIfMode) {
        Write-Host 'WhatIfMode is on - no changes were written.' -ForegroundColor Yellow
    }

    $final = $results.ToArray()

    # Reporting here as well as on the pipeline, because a menu cannot pipe.
    if ($ReportPath) {
        $target = $ReportPath
        if (-not [System.IO.Path]::IsPathRooted($target)) {
            $target = Join-Path -Path $script:ModuleRoot -ChildPath $target
        }

        try {
            $exportParams = @{ Result = $final; Path = $target }
            if ($ClientName) { $exportParams['ClientName'] = $ClientName }
            if ($IncludeEvidence) { $exportParams['IncludeEvidence'] = $true }
            Export-GovGuardReport @exportParams | Out-Null
        }
        catch {
            Write-Warning -Message ("Report export failed: {0}" -f $_.Exception.Message)
        }
    }

    return $final
}
