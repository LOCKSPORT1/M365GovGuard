New-GovGuardRule -Id 'GOV-CA-012' `
    -Title 'No Conditional Access policy restricts sign-in to permitted countries' `
    -Severity 'Critical' `
    -SeverityByCloud @{ Global = 'Medium'; USGov = 'Critical'; USGovDoD = 'Critical' } `
    -Category 'ConditionalAccess' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.1.20') `
    -Frameworks @('ITAR 22 CFR 120.54') `
    -Scopes @('Policy.Read.All') `
    -WriteScopes @('Policy.ReadWrite.ConditionalAccess') `
    -Rationale 'ITAR treats access by a foreign person as an export. Technical data held in the tenant must be unreachable from outside the permitted country set, and location-based Conditional Access is the control an assessor will ask to see. In a commercial tenant with no export-control obligation this is sensible hardening rather than a requirement, which is why the severity drops outside the sovereign clouds.' `
    -ManualFix 'Create a country named location containing the permitted countries, then a Conditional Access policy: All users (excluding break-glass) > All cloud apps > Locations: include Any location, exclude the named location > Grant: Block. Run in report-only first.' `
    -Test {
        param($Context)

        $policies = @(Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/policies' -All)
        $namedLocations = @(Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/namedLocations' -All)

        $countryLocationIds = @($namedLocations | Where-Object {
            [string](Get-GovGuardProperty -InputObject $_ -Path '@odata.type') -match 'countryNamedLocation'
        } | ForEach-Object { [string](Get-GovGuardProperty -InputObject $_ -Path 'id') })

        $matching = @()
        foreach ($policy in $policies) {
            $state = [string](Get-GovGuardProperty -InputObject $policy -Path 'state')
            if ($state -eq 'disabled') { continue }

            $controls = @(Get-GovGuardProperty -InputObject $policy -Path 'grantControls','builtInControls')
            if ($controls -notcontains 'block') { continue }

            $include = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','locations','includeLocations')
            $exclude = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','locations','excludeLocations')

            $usesCountryExclusion = ($include -contains 'All') -and
                                    (@($exclude | Where-Object { $countryLocationIds -contains $_ }).Count -gt 0)

            if ($usesCountryExclusion) {
                $matching += [pscustomobject]@{
                    Id          = [string](Get-GovGuardProperty -InputObject $policy -Path 'id')
                    DisplayName = [string](Get-GovGuardProperty -InputObject $policy -Path 'displayName')
                    State       = $state
                }
            }
        }

        $evidence = [pscustomobject]@{
            MatchingPolicies      = $matching
            CountryNamedLocations = @($namedLocations | Where-Object {
                $countryLocationIds -contains [string](Get-GovGuardProperty -InputObject $_ -Path 'id')
            } | ForEach-Object {
                [pscustomobject]@{
                    Id          = [string](Get-GovGuardProperty -InputObject $_ -Path 'id')
                    DisplayName = [string](Get-GovGuardProperty -InputObject $_ -Path 'displayName')
                    Countries   = @(Get-GovGuardProperty -InputObject $_ -Path 'countriesAndRegions')
                }
            })
            TotalPoliciesEvaluated = $policies.Count
        }

        # Say which it is. A commercial client reading "ITAR" on their report
        # stops reading the reports.
        $framing = $(if ($Context.IsSovereign) {
            'Required where export-controlled data is in scope.'
        }
        else {
            'Recommended hardening; no export-control obligation applies to a commercial tenant.'
        })

        if ($matching.Count -eq 0) {
            return @{
                Status   = 'Fail'
                Message  = ('No enabled block-on-location policy found across {0} Conditional Access policies. {1}' -f $policies.Count, $framing)
                Evidence = $evidence
            }
        }

        $enforced = @($matching | Where-Object { $_.State -eq 'enabled' })
        if ($enforced.Count -eq 0) {
            return @{
                Status   = 'Fail'
                Message  = ('Location block policy exists but is report-only: {0}' -f (($matching.DisplayName) -join ', '))
                Evidence = $evidence
            }
        }

        return @{
            Status   = 'Pass'
            Message  = ('Enforced by: {0}' -f (($enforced.DisplayName) -join ', '))
            Evidence = $evidence
        }
    } `
    -Remediate {
        param($Context, $Finding, $WhatIfMode)

        $permittedCountries = @('US')
        $locationName = 'GovGuard - Permitted countries'
        $policyName = 'GovGuard - Block sign-in outside permitted countries'
        $changes = @()

        # Reuse an existing GovGuard named location if one is already present.
        $existing = @($Finding.Evidence.CountryNamedLocations | Where-Object { $_.DisplayName -eq $locationName })
        $locationId = $null
        if ($existing.Count -gt 0) {
            $locationId = $existing[0].Id
            $changes += ('REUSED named location {0}' -f $locationId)
        }

        if ($WhatIfMode) {
            if (-not $locationId) {
                $changes += ('WOULD POST v1.0/identity/conditionalAccess/namedLocations -> countryNamedLocation "{0}" [{1}]' -f $locationName, ($permittedCountries -join ','))
            }
            $changes += ('WOULD POST v1.0/identity/conditionalAccess/policies -> "{0}" state=enabledForReportingButNotEnforced' -f $policyName)

            return @{
                Status  = 'WouldRemediate'
                Message = 'Would create the named location and a report-only block policy. Promote to enabled manually after reviewing report-only impact.'
                Changes = $changes
            }
        }

        if (-not $locationId) {
            $locationBody = @{
                '@odata.type'                      = '#microsoft.graph.countryNamedLocation'
                'displayName'                      = $locationName
                'countriesAndRegions'              = $permittedCountries
                'includeUnknownCountriesAndRegions' = $false
            }
            $created = Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/namedLocations' -Method POST -Body $locationBody -Raw
            $locationId = [string](Get-GovGuardProperty -InputObject $created -Path 'id')
            $changes += ('CREATED named location {0} [{1}]' -f $locationId, ($permittedCountries -join ','))
        }

        # Break-glass accounts must be excluded or the policy can lock the tenant.
        $excludeUsers = @()
        $breakGlass = @(Invoke-GovGuardGraph -Uri "v1.0/users?`$filter=startswith(displayName,'Break Glass')&`$select=id,displayName" -All)
        foreach ($user in $breakGlass) {
            $excludeUsers += [string](Get-GovGuardProperty -InputObject $user -Path 'id')
        }

        $policyBody = @{
            'displayName' = $policyName
            'state'       = 'enabledForReportingButNotEnforced'   # never auto-enforce a lockout-capable policy
            'conditions'  = @{
                'users'        = @{ 'includeUsers' = @('All'); 'excludeUsers' = $excludeUsers }
                'applications' = @{ 'includeApplications' = @('All') }
                'locations'    = @{ 'includeLocations' = @('All'); 'excludeLocations' = @($locationId) }
            }
            'grantControls' = @{
                'operator'        = 'OR'
                'builtInControls' = @('block')
            }
        }

        $policy = Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/policies' -Method POST -Body $policyBody -Raw
        $changes += ('CREATED CA policy {0} in report-only ({1} break-glass exclusion(s))' -f `
                     [string](Get-GovGuardProperty -InputObject $policy -Path 'id'), $excludeUsers.Count)

        return @{
            Status  = 'Remediated'
            Message = 'Created in report-only. Review sign-in impact, confirm break-glass exclusions, then set state=enabled.'
            Changes = $changes
        }
    }
