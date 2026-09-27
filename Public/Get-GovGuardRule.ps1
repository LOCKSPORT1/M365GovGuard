function Get-GovGuardRule {
    <#
    .SYNOPSIS
        Lists the registered rules, optionally filtered.

    .EXAMPLE
        Get-GovGuardRule -Framework 'CMMC' | Format-Table Id, Severity, Title

    .EXAMPLE
        Get-GovGuardRule -Cloud USGov -Remediable
    #>
    [CmdletBinding()]
    param(
        [string[]]$Id,
        [string[]]$Category,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string[]]$Severity,
        [ValidateSet('Global', 'USGov', 'USGovDoD')]
        [string]$Cloud,
        [string]$Framework,
        [switch]$Remediable
    )

    $rules = @($script:GovGuardRules)

    if ($Id)        { $rules = @($rules | Where-Object { $Id -contains $_.Id }) }
    if ($Category)  { $rules = @($rules | Where-Object { $Category -contains $_.Category }) }
    if ($Severity)  { $rules = @($rules | Where-Object { $Severity -contains $_.Severity }) }
    if ($Cloud)     { $rules = @($rules | Where-Object { $_.Clouds -contains $Cloud }) }
    if ($Framework) { $rules = @($rules | Where-Object { @($_.Frameworks) -match [regex]::Escape($Framework) }) }
    if ($Remediable){ $rules = @($rules | Where-Object { $_.Remediable }) }

    return $rules
}
