New-GovGuardRule -Id 'GOV-CA-022' `
    -Title 'Access is not restricted to compliant or domain-joined devices' `
    -Severity 'High' `
    -Category 'ConditionalAccess' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.1.12', '3.1.18') `
    -Scopes @('Policy.Read.All') `
    -Rationale 'Without a device condition, a valid credential grants access from any machine anywhere - an unmanaged home computer, a personal phone, an attacker workstation. Requiring a managed, compliant device ties access to something the organization can attest to, and it is the control that turns endpoint management from an inventory exercise into an access control.' `
    -ManualFix 'Conditional Access > New policy > All users (excluding break-glass and any documented service accounts) > All cloud apps > Grant: Require device to be marked as compliant, or require Hybrid Azure AD joined device. Run in report-only for a full business cycle first - this is the policy most likely to surprise, because it blocks anyone whose device never enrolled.' `
    -Test {
        param($Context)

        $deviceControls = @('compliantDevice', 'domainJoinedDevice')

        $policies = @(Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/policies' -All)

        $matching = @()
        foreach ($policy in $policies) {
            $state = [string](Get-GovGuardProperty -InputObject $policy -Path 'state')
            if ($state -eq 'disabled') { continue }

            $controls = @(Get-GovGuardProperty -InputObject $policy -Path 'grantControls','builtInControls')
            $present = @($deviceControls | Where-Object { $controls -contains $_ })
            if ($present.Count -eq 0) { continue }

            $includeUsers = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','users','includeUsers')
            $includeApps = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','applications','includeApplications')
            $excludeUsers = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','users','excludeUsers')
            $platforms = @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','platforms','includePlatforms')

            $matching += [pscustomobject]@{
                Id            = [string](Get-GovGuardProperty -InputObject $policy -Path 'id')
                DisplayName   = [string](Get-GovGuardProperty -InputObject $policy -Path 'displayName')
                State         = $state
                DeviceControl = ($present -join ', ')
                ScopedToAllUsers = ($includeUsers -contains 'All')
                ScopedToAllApps  = ($includeApps -contains 'All')
                Platforms     = $(if ($platforms.Count -gt 0) { $platforms -join ', ' } else { 'all' })
                ExcludedUsers = $excludeUsers.Count
            }
        }

        $evidence = [pscustomobject]@{
            MatchingPolicies       = $matching
            TotalPoliciesEvaluated = $policies.Count
        }

        if ($matching.Count -eq 0) {
            return @{
                Status   = 'Fail'
                Message  = ('No enabled policy requires a compliant or domain-joined device across {0} Conditional Access policies.' -f $policies.Count)
                Evidence = $evidence
            }
        }

        $enforced = @($matching | Where-Object { $_.State -eq 'enabled' })
        if ($enforced.Count -eq 0) {
            return @{
                Status   = 'Fail'
                Message  = ('A device requirement exists but is report-only: {0}' -f (($matching.DisplayName) -join ', '))
                Evidence = $evidence
            }
        }

        # Narrow scope is the common shape here - a device requirement applied to
        # one app is worth noting rather than counting as full coverage.
        $broad = @($enforced | Where-Object { $_.ScopedToAllUsers -and $_.ScopedToAllApps })

        if ($broad.Count -eq 0) {
            return @{
                Status   = 'Fail'
                Message  = ('A device requirement is enforced but not across all users and all applications: {0}. Coverage has gaps.' -f `
                            (($enforced.DisplayName) -join ', '))
                Evidence = $evidence
            }
        }

        return @{
            Status   = 'Pass'
            Message  = ('Enforced across all users and applications by: {0}' -f (($broad.DisplayName) -join ', '))
            Evidence = $evidence
        }
    }
