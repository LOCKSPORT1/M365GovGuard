New-GovGuardRule -Id 'GOV-IAM-011' `
    -Title 'Standing Global Administrator assignments outside PIM' `
    -Severity 'High' `
    -Category 'Identity' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.1.5', '3.1.6') `
    -Scopes @('RoleManagement.Read.Directory', 'Directory.Read.All') `
    -Rationale 'Least privilege is not satisfied by permanent role holders. Eligible-only assignments through Privileged Identity Management, with approval and justification, shrink the window in which a compromised admin credential is useful and produce the activation record an assessor wants.' `
    -ManualFix 'Entra > Identity Governance > Privileged Identity Management > Microsoft Entra roles. Create eligible assignments for each admin, require justification and approval on activation, cap activation duration, then remove the permanent active assignment. Leave break-glass accounts permanently assigned by design.' `
    -Test {
        param($Context)

        $globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
        $breakGlassAllowance = 2

        $assignments = @(Invoke-GovGuardGraph -All `
            -Uri ("v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '{0}'&`$expand=principal" -f $globalAdminRoleId))

        $eligible = @()
        try {
            $eligible = @(Invoke-GovGuardGraph -All `
                -Uri ("v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '{0}'" -f $globalAdminRoleId))
        }
        catch {
            # PIM requires Entra ID P2. Absence is itself a finding, not an error.
            Write-Verbose -Message ("Role eligibility query failed (likely no P2 licensing): {0}" -f $_.Exception.Message)
        }

        $eligiblePrincipals = @($eligible | ForEach-Object {
            [string](Get-GovGuardProperty -InputObject $_ -Path 'principalId')
        })

        # Zero eligible assignments means one of two very different things:
        # nobody configured PIM, or PIM is not available in this tenant at all.
        # Recommending a feature the client is not licensed for is a bad look.
        $hasP2 = Test-GovGuardServicePlan -ServicePlanName 'AAD_PREMIUM_P2'

        $standing = @()
        foreach ($assignment in $assignments) {
            $principal = Get-GovGuardProperty -InputObject $assignment -Path 'principal'
            $principalId = [string](Get-GovGuardProperty -InputObject $assignment -Path 'principalId')

            $displayName = ''
            $upn = ''
            $principalType = 'unknown'
            if ($null -ne $principal) {
                $displayName = [string](Get-GovGuardProperty -InputObject $principal -Path 'displayName')
                $upn = [string](Get-GovGuardProperty -InputObject $principal -Path 'userPrincipalName')
                $principalType = [string](Get-GovGuardProperty -InputObject $principal -Path '@odata.type')
            }

            $standing += [pscustomobject]@{
                PrincipalId     = $principalId
                DisplayName     = $displayName
                UserPrincipalName = $upn
                PrincipalType   = $principalType
                AlsoEligible    = ($eligiblePrincipals -contains $principalId)
            }
        }

        $evidence = [pscustomobject]@{
            StandingAssignments   = $standing
            StandingCount         = $standing.Count
            EligibleCount         = $eligible.Count
            PimInUse              = ($eligible.Count -gt 0)
            PimLicensed           = $hasP2
            BreakGlassAllowance   = $breakGlassAllowance
        }

        if ($standing.Count -le $breakGlassAllowance) {
            return @{
                Status   = 'Pass'
                Message  = ('{0} standing Global Admin assignment(s), within the break-glass allowance of {1}. {2}' -f `
                            $standing.Count, $breakGlassAllowance, `
                            $(if ($hasP2) { ('{0} eligible assignment(s) in PIM.' -f $eligible.Count) } else { 'PIM unavailable (no Entra ID P2).' }))
                Evidence = $evidence
            }
        }

        $pimNote = $(if ($hasP2) {
            ('PIM eligible assignments: {0}.' -f $eligible.Count)
        }
        else {
            'Entra ID P2 is not present, so PIM is unavailable here - reduce the number of standing assignments, or license P2 to move them to eligible.'
        })

        return @{
            Status   = 'Fail'
            Message  = ('{0} standing Global Admin assignment(s) against a break-glass allowance of {1}. {2}' -f `
                        $standing.Count, $breakGlassAllowance, $pimNote)
            Evidence = $evidence
        }
    }
