New-GovGuardRule -Id 'GOV-EXT-024' `
    -Title 'Guest invitation and guest directory permissions are unrestricted' `
    -Severity 'Medium' `
    -SeverityByCloud @{ Global = 'Medium'; USGov = 'High'; USGovDoD = 'High' } `
    -Category 'ExternalCollaboration' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.1.1', '3.1.20') `
    -Scopes @('Policy.Read.All') `
    -WriteScopes @('Policy.ReadWrite.Authorization') `
    -Rationale 'When any member can invite guests, external access to the tenant grows without anyone owning the decision, and in an environment holding CUI every guest is a person whose eligibility to see it nobody verified. The default guest role also reads more of the directory than most organizations intend - full user objects, group memberships, and other guests.' `
    -ManualFix 'Entra > External Identities > External collaboration settings. Set guest invite restrictions so only admins and users in the Guest Inviter role can invite, and set guest user access to the most restrictive level the business can work with. Pair it with a recurring access review over the guest population.' `
    -Reference 'Guest role template ids are stable but worth confirming against current documentation before relying on the mapping below.' `
    -Test {
        param($Context)

        # Directory role templates for guest access levels.
        $guestRoles = @{
            'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Same as member users (most permissive)'
            '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Guest user (default)'
            '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted guest user'
        }

        $authPolicy = Invoke-GovGuardGraph -Uri 'v1.0/policies/authorizationPolicy' -Raw
        if ($null -ne $authPolicy -and (@($authPolicy.PSObject.Properties.Name) -contains 'value')) {
            $authPolicy = @($authPolicy.value)[0]
        }

        $allowInvitesFrom = [string](Get-GovGuardProperty -InputObject $authPolicy -Path 'allowInvitesFrom')
        $guestRoleId = [string](Get-GovGuardProperty -InputObject $authPolicy -Path 'guestUserRoleId')

        $guestRoleName = $(if ($guestRoles.ContainsKey($guestRoleId)) { $guestRoles[$guestRoleId] } else { ('unrecognised role id {0}' -f $guestRoleId) })

        # 'everyone' means any member, and any guest, can invite.
        $inviteUnrestricted = ($allowInvitesFrom -eq 'everyone')
        $guestRoleTooBroad = ($guestRoleId -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970')

        $guestCount = $null
        try {
            $guests = Invoke-GovGuardGraph -Raw -Uri "v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$top=1"
            $guestCount = Get-GovGuardProperty -InputObject $guests -Path '@odata.count'
        }
        catch {
            Write-Verbose -Message ("Guest count unavailable: {0}" -f $_.Exception.Message)
        }

        $evidence = [pscustomobject]@{
            AllowInvitesFrom   = $allowInvitesFrom
            GuestUserRoleId    = $guestRoleId
            GuestUserRoleName  = $guestRoleName
            InviteUnrestricted = $inviteUnrestricted
            GuestRoleTooBroad  = $guestRoleTooBroad
            GuestCount         = $guestCount
        }

        $problems = @()
        if ($inviteUnrestricted) { $problems += 'any member or guest can invite external users' }
        if ($guestRoleTooBroad)  { $problems += 'guests have the same directory access as member users' }

        if ($problems.Count -eq 0) {
            return @{
                Status   = 'Pass'
                Message  = ('Invitations limited to "{0}"; guest role is "{1}".{2}' -f `
                            $allowInvitesFrom, $guestRoleName, `
                            $(if ($null -ne $guestCount) { " $guestCount guest(s) in the directory." } else { '' }))
                Evidence = $evidence
            }
        }

        return @{
            Status   = 'Fail'
            Message  = ('{0}.{1}' -f (($problems -join '; ')), `
                        $(if ($null -ne $guestCount) { " $guestCount guest(s) currently in the directory." } else { '' }))
            Evidence = $evidence
        }
    } `
    -Remediate {
        param($Context, $Finding, $WhatIfMode)

        if (-not $Finding.Evidence.InviteUnrestricted) {
            return @{
                Status  = 'Skipped'
                Message = 'Invitation restriction is already in place. The guest role level is left manual - tightening it can break access for guests who already have it.'
                Changes = @()
            }
        }

        # Only the invitation restriction is automated. Changing guestUserRoleId
        # takes access away from guests who already have it, which is a business
        # decision rather than a hygiene fix.
        $body = @{ 'allowInvitesFrom' = 'adminsAndGuestInviters' }

        if ($WhatIfMode) {
            return @{
                Status  = 'WouldRemediate'
                Message = 'Would limit invitations to administrators and the Guest Inviter role. The guest directory permission level is not changed automatically - see ManualFix.'
                Changes = @('WOULD PATCH v1.0/policies/authorizationPolicy -> allowInvitesFrom=adminsAndGuestInviters')
            }
        }

        Invoke-GovGuardGraph -Uri 'v1.0/policies/authorizationPolicy' -Method PATCH -Body $body | Out-Null

        $remaining = ''
        if ($Finding.Evidence.GuestRoleTooBroad) {
            $remaining = ' Guests still hold member-level directory access; change that manually once you have confirmed what it breaks.'
        }

        return @{
            Status  = 'Remediated'
            Message = ('Invitations limited to administrators and the Guest Inviter role.{0}' -f $remaining)
            Changes = @('PATCHED v1.0/policies/authorizationPolicy -> allowInvitesFrom=adminsAndGuestInviters')
        }
    }
