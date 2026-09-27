function Export-GovGuardReport {
    <#
    .SYNOPSIS
        Writes an audit run to a JSON evidence bundle and an HTML report.

    .DESCRIPTION
        Two artifacts from one run, for two different readers.

        The JSON is for the assessor and for machines: every finding with its
        full evidence payload, control mapping and timestamp, which is what a
        C3PAO can work from and what a drift comparison needs.

        The HTML is for the client read-out. Findings ordered by severity, each
        with why it matters and what to do about it, plus a section for the
        checks that produced neither a pass nor a fail - a rule that could not
        run is a gap in coverage, and omitting it would overstate what was
        actually checked.

    .PARAMETER Result
        Results from Invoke-GovGuardAudit.

    .PARAMETER Path
        Folder to write into. Created if missing.

    .PARAMETER ClientName
        Name for the report header and file name. Defaults to the tenant name.

    .PARAMETER Format
        Json, Html or Both. Defaults to Both.

    .PARAMETER IncludeEvidence
        Embed each finding's evidence payload in the HTML, collapsed. Useful for
        an internal review, usually noise in a client read-out.

    .EXAMPLE
        $r = Invoke-GovGuardAudit
        Export-GovGuardReport -Result $r -Path C:\Reports -ClientName 'Contoso Defense'

    .EXAMPLE
        Invoke-GovGuardAudit | Export-GovGuardReport -Path C:\Reports -IncludeEvidence
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Result,

        [Parameter(Mandatory)]
        [string]$Path,

        [string]$ClientName,

        [ValidateSet('Json', 'Html', 'Both')]
        [string]$Format = 'Both',

        [switch]$IncludeEvidence
    )

    begin {
        $collected = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($item in $Result) { $collected.Add($item) }
    }

    end {
        if ($collected.Count -eq 0) {
            Write-Warning -Message 'No results to export.'
            return
        }

        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        $context = $null
        try { $context = Get-GovGuardContext } catch { }

        $tenantLabel = if ($ClientName) { $ClientName }
                       elseif ($context) { $context.TenantName }
                       else { 'tenant' }

        $cloudLabel = if ($context) { $context.CloudProfile.DisplayName } else { 'unknown cloud' }
        $safeLabel = ($tenantLabel -replace '[^\w\-\.]', '_')
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $baseName = '{0}-GovGuard-{1}' -f $safeLabel, $stamp

        $severityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }

        $failed = @($collected | Where-Object { $_.Status -eq 'Fail' } |
                    Sort-Object -Property @{Expression = { $severityRank[$_.Severity] }}, RuleId)
        $passed = @($collected | Where-Object { $_.Status -eq 'Pass' } | Sort-Object RuleId)
        $unanswered = @($collected | Where-Object { @('Error', 'NotApplicable') -contains $_.Status } | Sort-Object RuleId)

        # Rules that never reached the report at all. An audit run without
        # -IncludeNotApplicable drops them silently, and a filtered run drops
        # more - either way the report would imply coverage it does not have.
        # The rule set is known here, so the gap can be stated rather than left
        # to the reader to notice.
        $notEvaluated = @()
        try {
            $evaluatedIds = @($collected | ForEach-Object { $_.RuleId })
            $notEvaluated = @(Get-GovGuardRule | Where-Object { $evaluatedIds -notcontains $_.Id } | Sort-Object Id)
        }
        catch {
            Write-Verbose -Message ("Could not enumerate the rule set: {0}" -f $_.Exception.Message)
        }

        $counts = @{
            Fail          = $failed.Count
            Pass          = $passed.Count
            Error         = @($collected | Where-Object { $_.Status -eq 'Error' }).Count
            NotApplicable = @($collected | Where-Object { $_.Status -eq 'NotApplicable' }).Count
            NotEvaluated  = $notEvaluated.Count
            RulesTotal    = ($collected.Count + $notEvaluated.Count)
            Critical      = @($failed | Where-Object { $_.Severity -eq 'Critical' }).Count
            High          = @($failed | Where-Object { $_.Severity -eq 'High' }).Count
        }

        $bundle = [pscustomobject]@{
            GeneratedUtc  = (Get-Date).ToUniversalTime().ToString('o')
            ClientName    = $tenantLabel
            TenantId      = $(if ($context) { $context.TenantId } else { $null })
            Cloud         = $cloudLabel
            ModuleVersion = $script:ModuleVersion
            Summary       = [pscustomobject]$counts
            Results       = @($collected)
        }

        $written = @()

        # --- JSON ------------------------------------------------------------
        if (@('Json', 'Both') -contains $Format) {
            $jsonPath = Join-Path -Path $Path -ChildPath ("{0}.json" -f $baseName)
            $bundle | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            $written += $jsonPath
        }

        if (@('Html', 'Both') -notcontains $Format) {
            Write-Host ("Report written: {0}" -f ($written -join ', ')) -ForegroundColor Green
            return $written
        }

        # --- HTML ------------------------------------------------------------
        $htmlPath = Join-Path -Path $Path -ChildPath ("{0}.html" -f $baseName)
        $showEvidence = $IncludeEvidence.IsPresent

        $findingBlocks = foreach ($finding in $failed) {

            $severityClass = 'sev-' + ([string]$finding.Severity).ToLowerInvariant()

            $frameworks = (@($finding.Frameworks) |
                ForEach-Object { '<span class="ctl">{0}</span>' -f (ConvertTo-GovGuardHtmlText -Text $_) }) -join ' '

            $rationale = ''
            if ($finding.Rationale) {
                $rationale = '<div class="why"><strong>Why it matters.</strong> {0}</div>' -f `
                    (ConvertTo-GovGuardHtmlText -Text $finding.Rationale)
            }

            $fix = ''
            if ($finding.ManualFix) {
                $fix = '<div class="fix"><strong>Fix.</strong> {0}</div>' -f `
                    (ConvertTo-GovGuardHtmlText -Text $finding.ManualFix)
            }

            $auto = ''
            if ($finding.Remediable) {
                $auto = '<div class="auto">This rule can remediate itself. Preview the change before applying it.</div>'
            }

            $remediation = ''
            if ($finding.RemediationStatus -and $finding.RemediationStatus -ne 'NotAttempted') {
                $remediation = '<div class="rem"><strong>{0}.</strong> {1}</div>' -f `
                    (ConvertTo-GovGuardHtmlText -Text $finding.RemediationStatus), `
                    (ConvertTo-GovGuardHtmlText -Text $finding.RemediationMessage)
            }

            $evidence = ''
            if ($showEvidence -and $null -ne $finding.Evidence) {
                $json = $finding.Evidence | ConvertTo-Json -Depth 8
                $evidence = '<details><summary>Evidence</summary><pre>{0}</pre></details>' -f `
                    (ConvertTo-GovGuardHtmlText -Text $json)
            }

@"
<div class="finding $severityClass">
  <div class="head">
    <span class="badge">$(ConvertTo-GovGuardHtmlText -Text $finding.Severity)</span>
    <span class="rid">$(ConvertTo-GovGuardHtmlText -Text $finding.RuleId)</span>
    <span class="ttl">$(ConvertTo-GovGuardHtmlText -Text $finding.Title)</span>
  </div>
  <div class="msg">$(ConvertTo-GovGuardHtmlText -Text $finding.Message)</div>
  $rationale
  $fix
  $auto
  $remediation
  <div class="ctls">$frameworks</div>
  $evidence
</div>
"@
        }

        $failedHtml = if ($failed.Count -gt 0) { ($findingBlocks -join "`n") }
                      else { '<p class="lead">No failed checks in this run.</p>' }

        $unansweredHtml = ''
        if ($unanswered.Count -gt 0 -or $notEvaluated.Count -gt 0) {

            $rows = foreach ($item in $unanswered) {
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f `
                    (ConvertTo-GovGuardHtmlText -Text $item.RuleId),
                    (ConvertTo-GovGuardHtmlText -Text $item.Status),
                    (ConvertTo-GovGuardHtmlText -Text $item.Title),
                    (ConvertTo-GovGuardHtmlText -Text $item.Message)
            }

            $tenantCloud = $(if ($context) { $context.Cloud } else { $null })

            $rows += foreach ($rule in $notEvaluated) {

                # Two very different reasons a rule is absent, and an evidence
                # report should not blur them: the rule does not apply to this
                # cloud at all, or the operator narrowed the run.
                $reason = if ($tenantCloud -and @($rule.Clouds) -notcontains $tenantCloud) {
                    'Does not apply to this tenant. Rule targets {0}.' -f (@($rule.Clouds) -join ', ')
                }
                else {
                    'Not run. Excluded by the filters used for this audit.'
                }

                '<tr><td>{0}</td><td>Not evaluated</td><td>{1}</td><td>{2}</td></tr>' -f `
                    (ConvertTo-GovGuardHtmlText -Text $rule.Id),
                    (ConvertTo-GovGuardHtmlText -Text $rule.Title),
                    (ConvertTo-GovGuardHtmlText -Text $reason)
            }

            $unansweredRows = ($rows -join "`n")

            $unansweredHtml = @"
<h2>Worth looking into</h2>
<p class="lead">These checks produced neither a pass nor a fail. A rule that did not run is a gap in coverage, not a clean result.</p>
<table><thead><tr><th>Rule</th><th>Outcome</th><th>Check</th><th>Reason</th></tr></thead>
<tbody>
$unansweredRows
</tbody></table>
"@
        }

        $passedHtml = ''
        if ($passed.Count -gt 0) {
            $rows = foreach ($item in $passed) {
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f `
                    (ConvertTo-GovGuardHtmlText -Text $item.RuleId),
                    (ConvertTo-GovGuardHtmlText -Text $item.Title),
                    (ConvertTo-GovGuardHtmlText -Text $item.Message)
            }
            $passedHtml = @"
<h2>Passed</h2>
<table><thead><tr><th>Rule</th><th>Check</th><th>Detail</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>
"@
        }

        # --- coverage --------------------------------------------------------
        $coverageHtml = ''
        try {
            $catalog = Get-GovGuardControlCatalog
            $coverage = @(Get-GovGuardCoverage -ByFamily)
            $coveredTotal = ($coverage | Measure-Object -Property Covered -Sum).Sum

            $covRows = foreach ($row in ($coverage | Where-Object { $_.Covered -gt 0 })) {
                '<tr><td>{0}</td><td>{1} of {2}</td><td>{3}</td></tr>' -f `
                    (ConvertTo-GovGuardHtmlText -Text $row.Family),
                    $row.Covered, $row.Controls,
                    (ConvertTo-GovGuardHtmlText -Text $row.CoveredIds)
            }

            $uncovered = @($coverage | Where-Object { $_.Covered -eq 0 } | ForEach-Object { $_.Family })
            $uncoveredHtml = ''
            if ($uncovered.Count -gt 0) {
                $uncoveredHtml = '<p class="lead">No automated coverage at all in: {0}.</p>' -f `
                    (ConvertTo-GovGuardHtmlText -Text ($uncovered -join '; '))
            }

            $covBody = ($covRows -join "`n")

            $provenanceHtml = ''
            if ($catalog.Provenance) {
                $p = $catalog.Provenance
                $provenanceHtml = '<p class="lead">Catalog source: {0} retrieved {1}, SHA-256 {2}, built by {3}.</p>' -f `
                    (ConvertTo-GovGuardHtmlText -Text $(if ($p.SourceUrl) { $p.SourceUrl } else { $p.SourceFile })),
                    (ConvertTo-GovGuardHtmlText -Text $p.Retrieved),
                    (ConvertTo-GovGuardHtmlText -Text ([string]$p.SourceSha256).Substring(0, [math]::Min(16, ([string]$p.SourceSha256).Length))),
                    (ConvertTo-GovGuardHtmlText -Text $p.Generator)
            }
            else {
                $provenanceHtml = '<p class="lead">Catalog is hand-maintained and carries no source provenance. Control identifiers are complete; some control text is not yet transcribed from the published standard.</p>'
            }

            $coverageHtml = @"
<h2>Control coverage</h2>
<p class="lead">This run exercised checks touching $coveredTotal of $($catalog.ControlCount) $($catalog.Framework) $($catalog.Revision) controls. Coverage means a check tests something relevant to the control, not that the control is satisfied, and an automated check rarely addresses a control in full - most include policy and process elements no tool can observe.</p>
<table><thead><tr><th>Family</th><th>Covered</th><th>Controls</th></tr></thead>
<tbody>
$covBody
</tbody></table>
$uncoveredHtml
$provenanceHtml
"@
        }
        catch {
            Write-Verbose -Message ("Coverage section skipped: {0}" -f $_.Exception.Message)
        }

        $headline = if ($counts.Critical -gt 0) {
            '{0} critical and {1} high-severity finding(s) need attention.' -f $counts.Critical, $counts.High
        }
        elseif ($counts.High -gt 0) {
            '{0} high-severity finding(s) need attention. No critical findings.' -f $counts.High
        }
        elseif ($counts.Fail -gt 0) {
            '{0} finding(s), none critical or high.' -f $counts.Fail
        }
        else {
            'No failed checks in this run.'
        }

        $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GovGuard - $(ConvertTo-GovGuardHtmlText -Text $tenantLabel)</title>
<style>
 :root{--bd:#e3e3e3;--mut:#5c5c5c}
 body{font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:2rem;color:#1a1a1a;max-width:60rem}
 h1{font-size:1.5rem;margin:0 0 .25rem}
 h2{font-size:1.1rem;margin:2rem 0 .75rem;padding-bottom:.3rem;border-bottom:1px solid var(--bd)}
 .meta{color:var(--mut);font-size:.85rem;margin-bottom:1.25rem}
 .headline{font-size:1rem;padding:.75rem 1rem;background:#f7f7f7;border-left:4px solid #888;margin-bottom:1.5rem}
 .cards{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1rem}
 .card{border:1px solid var(--bd);border-radius:6px;padding:.6rem 1rem;min-width:92px}
 .card .n{font-size:1.5rem;font-weight:600;line-height:1.1}
 .card .l{font-size:.78rem;color:var(--mut)}
 .lead{color:var(--mut);font-size:.88rem;margin:-.25rem 0 1rem}
 .finding{border:1px solid var(--bd);border-left-width:5px;border-radius:5px;padding:.85rem 1rem;margin-bottom:.85rem}
 .finding .head{display:flex;gap:.6rem;align-items:baseline;flex-wrap:wrap;margin-bottom:.4rem}
 .badge{font-size:.7rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:.1rem .45rem;border-radius:3px;background:#eee}
 .rid{font-family:Consolas,monospace;font-size:.82rem;color:var(--mut)}
 .ttl{font-weight:600}
 .msg{margin:.35rem 0 .5rem}
 .why,.fix,.auto,.rem{font-size:.88rem;margin:.35rem 0;line-height:1.45}
 .fix{background:#f6f9f6;padding:.5rem .65rem;border-radius:4px}
 .auto{color:var(--mut);font-size:.82rem}
 .rem{font-style:italic;color:#444}
 .ctls{margin-top:.6rem}
 .ctl{display:inline-block;font-size:.72rem;background:#f0f0f0;color:#444;padding:.1rem .4rem;border-radius:3px;margin-right:.3rem}
 .sev-critical{border-left-color:#b30000}.sev-critical .badge{background:#fde2e2;color:#8a0000}
 .sev-high{border-left-color:#d9730d}.sev-high .badge{background:#fdecd9;color:#8a4500}
 .sev-medium{border-left-color:#c9a227}.sev-medium .badge{background:#fbf3d5;color:#6f5a00}
 .sev-low{border-left-color:#999}.sev-low .badge{background:#eee;color:#555}
 .sev-informational{border-left-color:#999}
 table{border-collapse:collapse;width:100%;font-size:.86rem}
 th,td{border-bottom:1px solid #ececec;padding:.45rem .55rem;text-align:left;vertical-align:top}
 th{background:#f7f7f7;font-weight:600}
 details{margin-top:.6rem}
 summary{cursor:pointer;font-size:.82rem;color:var(--mut)}
 pre{background:#fafafa;border:1px solid var(--bd);border-radius:4px;padding:.6rem;overflow-x:auto;font-size:.76rem}
 .foot{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--bd);color:var(--mut);font-size:.8rem}
</style></head><body>

<h1>Microsoft 365 posture assessment</h1>
<div class="meta">$(ConvertTo-GovGuardHtmlText -Text $tenantLabel) &middot; $(ConvertTo-GovGuardHtmlText -Text $cloudLabel) &middot; generated $($bundle.GeneratedUtc) UTC</div>

<div class="headline">$(ConvertTo-GovGuardHtmlText -Text $headline)</div>

<div class="cards">
 <div class="card"><div class="n">$($counts.Fail)</div><div class="l">Failed</div></div>
 <div class="card"><div class="n">$($counts.Critical)</div><div class="l">Critical</div></div>
 <div class="card"><div class="n">$($counts.High)</div><div class="l">High</div></div>
 <div class="card"><div class="n">$($counts.Pass)</div><div class="l">Passed</div></div>
 <div class="card"><div class="n">$($counts.NotApplicable + $counts.Error + $counts.NotEvaluated)</div><div class="l">Unanswered</div></div>
</div>

<h2>Findings</h2>
<p class="lead">Ordered by severity. Severity reflects the obligation that applies to this tenant's cloud. $($counts.Fail + $counts.Pass) of $($counts.RulesTotal) rule(s) produced a pass or fail.</p>
$failedHtml

$unansweredHtml

$passedHtml

$coverageHtml

<div class="foot">
Generated by M365GovGuard. Full evidence for every finding is in the JSON bundle written alongside this file.
Severity is advisory and reflects the control mapping shown on each finding; this is not a formal assessment.
</div>

</body></html>
"@

        $html | Set-Content -LiteralPath $htmlPath -Encoding UTF8
        $written += $htmlPath

        Write-Host ("Report written: {0}" -f ($written -join ', ')) -ForegroundColor Green
        return $written
    }
}
