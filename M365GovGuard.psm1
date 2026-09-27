#Requires -Version 5.1
Set-StrictMode -Version Latest

$script:ModuleRoot      = $PSScriptRoot
$script:GovGuardContext = $null
$script:GovGuardRules   = [System.Collections.Generic.List[object]]::new()
$script:GovGuardCatalogCache = @{}

# Read the version from the manifest rather than repeating it in code. A report
# that hardcodes a version will claim it forever.
$script:ModuleVersion = '0.0.0'
try {
    $manifestPath = Join-Path $script:ModuleRoot 'M365GovGuard.psd1'
    if (Test-Path -LiteralPath $manifestPath) {
        $script:ModuleVersion = (Import-PowerShellDataFile -LiteralPath $manifestPath).ModuleVersion
    }
}
catch {
    Write-Verbose -Message ("Could not read module version: {0}" -f $_.Exception.Message)
}

# ---------------------------------------------------------------------------
# Load Private then Public. Dot-sourcing (not '&') so everything lands in the
# module scope and rule scriptblocks can see the private helpers.
# ---------------------------------------------------------------------------
foreach ($folder in @('Private', 'Public')) {
    $folderPath = Join-Path -Path $script:ModuleRoot -ChildPath $folder
    if (-not (Test-Path -LiteralPath $folderPath)) { continue }

    Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' -Recurse |
        Sort-Object -Property FullName |
        ForEach-Object {
            $sourceFile = $_.FullName
            try {
                . $sourceFile
            }
            catch {
                Write-Error -Message ("Failed to load '{0}': {1}" -f $sourceFile, $_.Exception.Message)
            }
        }
}

# ---------------------------------------------------------------------------
# Rule registration. Each file under Rules\ emits exactly one rule object
# built by New-GovGuardRule. Drop a new .ps1 in and it is picked up on import.
# ---------------------------------------------------------------------------
$rulesPath = Join-Path -Path $script:ModuleRoot -ChildPath 'Rules'
if (Test-Path -LiteralPath $rulesPath) {
    Get-ChildItem -LiteralPath $rulesPath -Filter '*.ps1' -Recurse |
        Sort-Object -Property Name |
        ForEach-Object {
            $ruleFile = $_.FullName
            try {
                $rule = . $ruleFile
                foreach ($r in @($rule)) {
                    if ($null -eq $r) { continue }
                    if ($r.PSObject.TypeNames -notcontains 'GovGuard.Rule') {
                        Write-Warning -Message ("Skipped '{0}': did not return a GovGuard.Rule object." -f $ruleFile)
                        continue
                    }
                    $existing = @($script:GovGuardRules | Where-Object { $_.Id -eq $r.Id })
                    if ($existing.Count -gt 0) {
                        Write-Warning -Message ("Duplicate rule id '{0}' in '{1}' - skipped." -f $r.Id, $ruleFile)
                        continue
                    }
                    $r | Add-Member -NotePropertyName 'SourceFile' -NotePropertyValue $ruleFile -Force
                    $script:GovGuardRules.Add($r)
                }
            }
            catch {
                Write-Warning -Message ("Rule file '{0}' failed to load: {1}" -f $ruleFile, $_.Exception.Message)
            }
        }
}

Write-Verbose -Message ("M365GovGuard loaded {0} rule(s)." -f $script:GovGuardRules.Count)
