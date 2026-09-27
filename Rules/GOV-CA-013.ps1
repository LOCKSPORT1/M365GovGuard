New-GovGuardRule -Id 'GOV-CA-013' `
    -Title 'Legacy authentication is not blocked by Conditional Access' `
    -Severity 'Critical' `
    -Category 'ConditionalAccess' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.5.3') `
    -Frameworks @('CIS M365 1.2.x') `
    -Scopes @('Policy.Read.All') `
    -WriteScopes @('Policy.ReadWrite.ConditionalAccess') `
    -Rationale 'Legacy authentication protocols cannot present an MFA challenge, so every other identity control is bypassable while they remain reachable. Basic auth is retired in Exchange Online but the client-app condition still catches SMTP AUTH, IMAP/POP clients, older Office builds and line-of-business integrations.' `
    -ManualFix 'Conditional Access > New policy > All users (excluding break-glass and any service accounts with a documented exception) > All cloud apps > Conditions > Client apps: Exchange ActiveSync clients + Other clients > Grant: Block.' `
    -Test {
        param($Context)

        $policies = @(Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/policies' -All)

        $legacyClientTypes = @('exchangeActiveSync', 'other')
        $matching = @()

        foreach ($policy in $policies) {
            $state = [string](Get-GovGuardProperty -InputObject $policy -Path 'state')
            if ($state -eq 'disabled') { continue }

            $controls = @(Get-GovGuardProperty -InputObject $policy -Path 'grantControls','builtInControls')
            if ($controls -notcontains 'block') { continue }

            $clientAppTypes = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','clientAppTypes')
            if ($clientAppTypes.Count -eq 0) { continue }

            # 'all' does not target legacy specifically; require the explicit pair.
            $covered = @($legacyClientTypes | Where-Object { $clientAppTypes -contains $_ })
            if ($covered.Count -ne $legacyClientTypes.Count) { continue }

            $includeUsers = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','users','includeUsers')
            $excludeUsers = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','users','excludeUsers')

            $matching += [pscustomobject]@{
                Id            = [string](Get-GovGuardProperty -InputObject $policy -Path 'id')
                DisplayName   = [string](Get-GovGuardProperty -InputObject $policy -Path 'displayName')
                State         = $state
                ScopedToAll   = ($includeUsers -contains 'All')
                ExcludedCount = $excludeUsers.Count
            }
        }

        $evidence = [pscustomobject]@{
            MatchingPolicies       = $matching
            TotalPoliciesEvaluated = $policies.Count
        }

        if ($matching.Count -eq 0) {
            return @{
                Status   = 'Fail'
                Message  = ('No enabled policy blocks the exchangeActiveSync + other client-app types across {0} policies.' -f $policies.Count)
                Evidence = $evidence
            }
        }

        $enforcedAllUsers = @($matching | Where-Object { $_.State -eq 'enabled' -and $_.ScopedToAll })
        if ($enforcedAllUsers.Count -eq 0) {
            return @{
                Status   = 'Fail'
                Message  = ('Legacy-auth policy present but not enforced for all users: {0}' -f (($matching.DisplayName) -join ', '))
                Evidence = $evidence
            }
        }

        $excluded = ($enforcedAllUsers | Measure-Object -Property ExcludedCount -Sum).Sum
        return @{
            Status   = 'Pass'
            Message  = ('Enforced by: {0} ({1} user exclusion(s) - confirm each is documented).' -f (($enforcedAllUsers.DisplayName) -join ', '), $excluded)
            Evidence = $evidence
        }
    } `
    -Remediate {
        param($Context, $Finding, $WhatIfMode)

        $policyName = 'GovGuard - Block legacy authentication'
        $changes = @()

        $alreadyThere = @($Finding.Evidence.MatchingPolicies | Where-Object { $_.DisplayName -eq $policyName })
        if ($alreadyThere.Count -gt 0) {
            return @{
                Status  = 'Skipped'
                Message = ('Policy "{0}" already exists in state {1}. Promote it manually rather than creating a duplicate.' -f $policyName, $alreadyThere[0].State)
                Changes = @()
            }
        }

        if ($WhatIfMode) {
            $changes += ('WOULD POST v1.0/identity/conditionalAccess/policies -> "{0}" clientAppTypes=exchangeActiveSync,other grant=block state=enabledForReportingButNotEnforced' -f $policyName)
            return @{
                Status  = 'WouldRemediate'
                Message = 'Would create a report-only legacy-auth block policy. Report-only first so SMTP AUTH devices and LOB apps surface before enforcement.'
                Changes = $changes
            }
        }

        $excludeUsers = @()
        $breakGlass = @(Invoke-GovGuardGraph -Uri "v1.0/users?`$filter=startswith(displayName,'Break Glass')&`$select=id,displayName" -All)
        foreach ($user in $breakGlass) {
            $excludeUsers += [string](Get-GovGuardProperty -InputObject $user -Path 'id')
        }

        $policyBody = @{
            'displayName' = $policyName
            'state'       = 'enabledForReportingButNotEnforced'
            'conditions'  = @{
                'users'          = @{ 'includeUsers' = @('All'); 'excludeUsers' = $excludeUsers }
                'applications'   = @{ 'includeApplications' = @('All') }
                'clientAppTypes' = @('exchangeActiveSync', 'other')
            }
            'grantControls' = @{
                'operator'        = 'OR'
                'builtInControls' = @('block')
            }
        }

        $policy = Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/policies' -Method POST -Body $policyBody -Raw
        $changes += ('CREATED CA policy {0} in report-only' -f [string](Get-GovGuardProperty -InputObject $policy -Path 'id'))

        return @{
            Status  = 'Remediated'
            Message = 'Created in report-only. Review report-only sign-ins for a full billing cycle to catch monthly batch jobs, then enable.'
            Changes = $changes
        }
    }
