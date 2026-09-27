New-GovGuardRule -Id 'GOV-CA-020' `
    -Title 'No Conditional Access policy requires MFA for all users' `
    -Severity 'Critical' `
    -Category 'ConditionalAccess' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.5.3') `
    -Frameworks @('CIS M365 1.1.1') `
    -Scopes @('Policy.Read.All') `
    -WriteScopes @('Policy.ReadWrite.ConditionalAccess') `
    -Rationale 'Password-only authentication is defeated by credential theft, and credential theft is the most common route into a tenant. A policy scoped to all users and all applications is the baseline; per-application or per-group MFA leaves whatever was missed reachable with a password alone.' `
    -ManualFix 'Conditional Access > New policy > All users (excluding break-glass) > All cloud apps > Grant: Require multifactor authentication. Run in report-only first, then enable. Prefer an authentication strength over the plain MFA control where phishing resistance is required.' `
    -Test {
        param($Context)

        $policies = @(Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/policies' -All)

        $matching = @()
        foreach ($policy in $policies) {
            $state = [string](Get-GovGuardProperty -InputObject $policy -Path 'state')
            if ($state -eq 'disabled') { continue }

            $includeUsers = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','users','includeUsers')
            if ($includeUsers -notcontains 'All') { continue }

            $includeApps = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','applications','includeApplications')
            if ($includeApps -notcontains 'All') { continue }

            # Either the built-in MFA control or an authentication strength counts.
            $controls = @(Get-GovGuardProperty -InputObject $policy -Path 'grantControls','builtInControls')
            $strength = Get-GovGuardProperty -InputObject $policy -Path 'grantControls','authenticationStrength'

            $requiresMfa = ($controls -contains 'mfa') -or ($null -ne $strength)
            if (-not $requiresMfa) { continue }

            $excludeUsers = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','users','excludeUsers')
            $excludeGroups = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','users','excludeGroups')

            $matching += [pscustomobject]@{
                Id             = [string](Get-GovGuardProperty -InputObject $policy -Path 'id')
                DisplayName    = [string](Get-GovGuardProperty -InputObject $policy -Path 'displayName')
                State          = $state
                UsesStrength   = ($null -ne $strength)
                StrengthName   = [string](Get-GovGuardProperty -InputObject $strength -Path 'displayName')
                ExcludedUsers  = $excludeUsers.Count
                ExcludedGroups = $excludeGroups.Count
            }
        }

        $evidence = [pscustomobject]@{
            MatchingPolicies       = $matching
            TotalPoliciesEvaluated = $policies.Count
        }

        if ($matching.Count -eq 0) {
            return @{
                Status   = 'Fail'
                Message  = ('No enabled policy requires MFA for all users and all applications across {0} Conditional Access policies.' -f $policies.Count)
                Evidence = $evidence
            }
        }

        $enforced = @($matching | Where-Object { $_.State -eq 'enabled' })
        if ($enforced.Count -eq 0) {
            return @{
                Status   = 'Fail'
                Message  = ('An all-users MFA policy exists but is report-only: {0}' -f (($matching.DisplayName) -join ', '))
                Evidence = $evidence
            }
        }

        # Exclusions are legitimate but they are also where coverage quietly
        # disappears, so the count goes in the message rather than the evidence.
        $totalExclusions = (($enforced | Measure-Object -Property ExcludedUsers -Sum).Sum +
                            ($enforced | Measure-Object -Property ExcludedGroups -Sum).Sum)

        return @{
            Status   = 'Pass'
            Message  = ('Enforced by: {0}. {1} exclusion(s) across those policies - confirm each is documented.' -f `
                        (($enforced.DisplayName) -join ', '), $totalExclusions)
            Evidence = $evidence
        }
    } `
    -Remediate {
        param($Context, $Finding, $WhatIfMode)

        $policyName = 'GovGuard - Require MFA for all users'
        $changes = @()

        $existing = @($Finding.Evidence.MatchingPolicies | Where-Object { $_.DisplayName -eq $policyName })
        if ($existing.Count -gt 0) {
            return @{
                Status  = 'Skipped'
                Message = ('"{0}" already exists in state {1}. Promote it rather than creating a duplicate.' -f $policyName, $existing[0].State)
                Changes = @()
            }
        }

        if ($WhatIfMode) {
            return @{
                Status  = 'WouldRemediate'
                Message = 'Would create a report-only all-users MFA policy. Report-only first so service accounts and unregistered users surface before enforcement.'
                Changes = @(('WOULD POST v1.0/identity/conditionalAccess/policies -> "{0}" grant=mfa state=enabledForReportingButNotEnforced' -f $policyName))
            }
        }

        $excludeUsers = @()
        $breakGlass = @(Invoke-GovGuardGraph -All -Uri "v1.0/users?`$filter=startswith(displayName,'Break Glass')&`$select=id,displayName")
        foreach ($user in $breakGlass) {
            $excludeUsers += [string](Get-GovGuardProperty -InputObject $user -Path 'id')
        }

        $body = @{
            'displayName' = $policyName
            'state'       = 'enabledForReportingButNotEnforced'
            'conditions'  = @{
                'users'        = @{ 'includeUsers' = @('All'); 'excludeUsers' = $excludeUsers }
                'applications' = @{ 'includeApplications' = @('All') }
                'clientAppTypes' = @('all')
            }
            'grantControls' = @{
                'operator'        = 'OR'
                'builtInControls' = @('mfa')
            }
        }

        $policy = Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/policies' -Method POST -Body $body -Raw
        $changes += ('CREATED CA policy {0} in report-only ({1} break-glass exclusion(s))' -f `
                     [string](Get-GovGuardProperty -InputObject $policy -Path 'id'), $excludeUsers.Count)

        return @{
            Status  = 'Remediated'
            Message = 'Created in report-only. Review the impact, confirm every account that would be blocked has a path to register MFA, then set state=enabled.'
            Changes = $changes
        }
    }
