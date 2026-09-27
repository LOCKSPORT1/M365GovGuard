New-GovGuardRule -Id 'GOV-IAM-010' `
    -Title 'Break-glass accounts are missing, synced, or not excluded from Conditional Access' `
    -Severity 'High' `
    -Category 'Identity' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.1.1') `
    -Scopes @('RoleManagement.Read.Directory', 'Directory.Read.All', 'Policy.Read.All') `
    -Rationale 'A Conditional Access misconfiguration, an expired federation certificate or an on-premises outage can lock every administrator out of a tenant at once. Two cloud-only Global Administrator accounts held outside sync scope and outside CA enforcement are the standard recovery path.' `
    -ManualFix 'Create two cloud-only accounts on an .onmicrosoft domain, assign permanent Global Administrator, exclude both from every Conditional Access policy, register FIDO2 keys held in separate physical custody, and alert on any sign-in.' `
    -Test {
        param($Context)

        $globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'

        $assignments = @(Invoke-GovGuardGraph -All `
            -Uri ("v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '{0}'&`$expand=principal" -f $globalAdminRoleId))

        $policies = @(Invoke-GovGuardGraph -Uri 'v1.0/identity/conditionalAccess/policies' -All)
        $enabledPolicies = @($policies | Where-Object {
            [string](Get-GovGuardProperty -InputObject $_ -Path 'state') -ne 'disabled'
        })

        # A user must be excluded from EVERY enabled policy to count as break-glass.
        $exclusionSets = @()
        foreach ($policy in $enabledPolicies) {
            $exclusionSets += , @(Get-GovGuardProperty -InputObject $policy -Path 'conditions','users','excludeUsers')
        }

        $candidates = @()
        foreach ($assignment in $assignments) {
            $principal = Get-GovGuardProperty -InputObject $assignment -Path 'principal'
            if ($null -eq $principal) { continue }

            $odataType = [string](Get-GovGuardProperty -InputObject $principal -Path '@odata.type')
            if ($odataType -notmatch 'user') { continue }

            $userId = [string](Get-GovGuardProperty -InputObject $principal -Path 'id')
            $upn = [string](Get-GovGuardProperty -InputObject $principal -Path 'userPrincipalName')

            $user = Invoke-GovGuardGraph -Raw `
                -Uri ("v1.0/users/{0}?`$select=id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled" -f $userId)

            $syncEnabled = Get-GovGuardProperty -InputObject $user -Path 'onPremisesSyncEnabled'
            $isCloudOnly = ($null -eq $syncEnabled -or $syncEnabled -eq $false)

            $excludedFromAll = $true
            foreach ($set in $exclusionSets) {
                if ($set -notcontains $userId) { $excludedFromAll = $false; break }
            }
            if ($enabledPolicies.Count -eq 0) { $excludedFromAll = $false }

            $candidates += [pscustomobject]@{
                UserPrincipalName   = $upn
                CloudOnly           = $isCloudOnly
                Enabled             = [bool](Get-GovGuardProperty -InputObject $user -Path 'accountEnabled')
                ExcludedFromAllCA   = $excludedFromAll
                QualifiesAsBreakGlass = ($isCloudOnly -and $excludedFromAll)
            }
        }

        $qualifying = @($candidates | Where-Object { $_.QualifiesAsBreakGlass })

        $evidence = [pscustomobject]@{
            GlobalAdminUsers      = $candidates
            QualifyingCount       = $qualifying.Count
            EnabledPolicyCount    = $enabledPolicies.Count
        }

        if ($qualifying.Count -ge 2) {
            return @{
                Status   = 'Pass'
                Message  = ('{0} cloud-only Global Admin account(s) excluded from all {1} enabled CA policies.' -f $qualifying.Count, $enabledPolicies.Count)
                Evidence = $evidence
            }
        }

        return @{
            Status   = 'Fail'
            Message  = ('Only {0} of {1} Global Admin account(s) qualify as break-glass (cloud-only and excluded from all {2} enabled CA policies). Two is the expected minimum.' -f `
                        $qualifying.Count, $candidates.Count, $enabledPolicies.Count)
            Evidence = $evidence
        }
    }
