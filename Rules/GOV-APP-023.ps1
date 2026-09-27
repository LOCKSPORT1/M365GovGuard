New-GovGuardRule -Id 'GOV-APP-023' `
    -Title 'Users can consent to applications without admin review' `
    -Severity 'High' `
    -Category 'Applications' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.1.5', '3.4.6') `
    -Scopes @('Policy.Read.All') `
    -WriteScopes @('Policy.ReadWrite.Authorization') `
    -Rationale 'Illicit consent is a route into a tenant that never touches a password and is unaffected by MFA: the user is phished into granting an attacker-controlled application access to their mail and files, and the resulting token survives a password reset. Restricting consent to low-impact permissions, with an admin approval path for anything more, closes it without stopping legitimate app adoption.' `
    -ManualFix 'Entra > Enterprise applications > Consent and permissions > User consent settings. Select "Allow user consent for apps from verified publishers, for selected permissions" or disable user consent entirely, then enable the admin consent request workflow under Admin consent settings so requests have somewhere to go.' `
    -Test {
        param($Context)

        # The legacy grant policy is the permissive one: any user, any app,
        # any delegated permission the app asks for.
        $legacyPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
        $lowImpactPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-low'

        $authPolicy = Invoke-GovGuardGraph -Uri 'v1.0/policies/authorizationPolicy' -Raw

        # Graph has returned this as both a single object and a collection.
        if ($null -ne $authPolicy -and (@($authPolicy.PSObject.Properties.Name) -contains 'value')) {
            $authPolicy = @($authPolicy.value)[0]
        }

        $assigned = @(Get-GovGuardProperty -InputObject $authPolicy -Path 'defaultUserRolePermissions','permissionGrantPoliciesAssigned')

        $adminConsentEnabled = $false
        try {
            $consentRequest = Invoke-GovGuardGraph -Uri 'v1.0/policies/adminConsentRequestPolicy' -Raw
            $adminConsentEnabled = [bool](Get-GovGuardProperty -InputObject $consentRequest -Path 'isEnabled')
        }
        catch {
            Write-Verbose -Message ("Admin consent request policy unreadable: {0}" -f $_.Exception.Message)
        }

        $unrestricted = ($assigned -contains $legacyPolicy)
        $lowImpactOnly = ($assigned -contains $lowImpactPolicy) -and -not $unrestricted
        $consentDisabled = ($assigned.Count -eq 0)

        $evidence = [pscustomobject]@{
            PermissionGrantPoliciesAssigned = $assigned
            UserConsentUnrestricted         = $unrestricted
            UserConsentLowImpactOnly        = $lowImpactOnly
            UserConsentDisabled             = $consentDisabled
            AdminConsentWorkflowEnabled     = $adminConsentEnabled
        }

        if ($consentDisabled) {
            $note = $(if ($adminConsentEnabled) {
                'Admin consent workflow is enabled, so requests have a path.'
            }
            else {
                'Admin consent workflow is NOT enabled - users have no way to request an app, which usually ends in shadow IT.'
            })

            return @{
                Status   = 'Pass'
                Message  = ('User consent to applications is disabled. {0}' -f $note)
                Evidence = $evidence
            }
        }

        if ($lowImpactOnly) {
            return @{
                Status   = 'Pass'
                Message  = ('User consent is limited to low-impact permissions from verified publishers. Admin consent workflow enabled: {0}.' -f $adminConsentEnabled)
                Evidence = $evidence
            }
        }

        return @{
            Status   = 'Fail'
            Message  = ('Users can consent to any application for any delegated permission (grant policy: {0}). Admin consent workflow enabled: {1}.' -f `
                        $(if ($assigned.Count -gt 0) { $assigned -join ', ' } else { 'none resolved' }), $adminConsentEnabled)
            Evidence = $evidence
        }
    } `
    -Remediate {
        param($Context, $Finding, $WhatIfMode)

        $lowImpactPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-low'

        if ($Finding.Evidence.UserConsentLowImpactOnly -or $Finding.Evidence.UserConsentDisabled) {
            return @{ Status = 'Skipped'; Message = 'Already restricted.'; Changes = @() }
        }

        # Restricting to low-impact rather than disabling outright. Disabling
        # every user consent path without an approval workflow in place moves
        # people to unmanaged tools instead of stopping them.
        $body = @{
            'defaultUserRolePermissions' = @{
                'permissionGrantPoliciesAssigned' = @($lowImpactPolicy)
            }
        }

        if ($WhatIfMode) {
            return @{
                Status  = 'WouldRemediate'
                Message = 'Would restrict user consent to low-impact permissions from verified publishers. Enable the admin consent request workflow alongside this, or app requests have nowhere to go.'
                Changes = @(('WOULD PATCH v1.0/policies/authorizationPolicy -> permissionGrantPoliciesAssigned={0}' -f $lowImpactPolicy))
            }
        }

        Invoke-GovGuardGraph -Uri 'v1.0/policies/authorizationPolicy' -Method PATCH -Body $body | Out-Null

        $followUp = ''
        if (-not $Finding.Evidence.AdminConsentWorkflowEnabled) {
            $followUp = ' The admin consent request workflow is still disabled - enable it so users can request apps that now need approval.'
        }

        return @{
            Status  = 'Remediated'
            Message = ('User consent restricted to low-impact permissions from verified publishers.{0}' -f $followUp)
            Changes = @(('PATCHED v1.0/policies/authorizationPolicy -> permissionGrantPoliciesAssigned={0}' -f $lowImpactPolicy))
        }
    }
