New-GovGuardRule -Id 'GOV-IAM-019' `
    -Title 'Privileged accounts are synchronized from on-premises Active Directory' `
    -Severity 'High' `
    -Category 'Identity' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.1.5', '3.1.7') `
    -Scopes @('RoleManagement.Read.Directory', 'Directory.Read.All') `
    -Rationale 'A synced account holding a cloud privileged role joins the two environments into one blast radius: compromise of on-premises Active Directory becomes compromise of the tenant, with no boundary in between. The standard control is cloud-only accounts for privileged roles, so that an on-premises incident cannot escalate into the cloud and an on-premises outage cannot lock administrators out of it.' `
    -ManualFix 'Create cloud-only administrative accounts on an .onmicrosoft domain for each person holding a privileged role, register phishing-resistant credentials on them, move the role assignments across, then remove the roles from the synced accounts. Daily-driver accounts keep syncing and hold no privilege.' `
    -Test {
        param($Context)

        $principals = @(Get-GovGuardPrivilegedPrincipal)

        if ($principals.Count -eq 0) {
            return @{
                Status  = 'Pass'
                Message = 'No users hold privileged directory roles.'
            }
        }

        # A cloud-only tenant cannot fail this; report it as not applicable so
        # the result is not mistaken for a control that was verified.
        $anySynced = @($principals | Where-Object { $_.OnPremisesSyncEnabled })
        $enabled = @($principals | Where-Object { $_.AccountEnabled })

        $evidence = [pscustomobject]@{
            SyncedPrivilegedAccounts = @($anySynced | ForEach-Object {
                [pscustomobject]@{
                    UserPrincipalName = $_.UserPrincipalName
                    Roles             = ($_.Roles -join ', ')
                    AccountEnabled    = $_.AccountEnabled
                }
            })
            CloudOnlyPrivilegedAccounts = @($principals | Where-Object { -not $_.OnPremisesSyncEnabled } | ForEach-Object {
                [pscustomobject]@{
                    UserPrincipalName = $_.UserPrincipalName
                    Roles             = ($_.Roles -join ', ')
                    AccountEnabled    = $_.AccountEnabled
                }
            })
            SyncedCount     = $anySynced.Count
            PrivilegedTotal = $principals.Count
            EnabledCount    = $enabled.Count
        }

        if ($anySynced.Count -eq 0) {
            return @{
                Status   = 'Pass'
                Message  = ('All {0} privileged account(s) are cloud-only.' -f $principals.Count)
                Evidence = $evidence
            }
        }

        # Global Administrator held by a synced account is the sharpest version
        # of this and worth calling out separately in the message.
        $syncedGlobalAdmins = @($anySynced | Where-Object { $_.Roles -contains 'Global Administrator' })

        $detail = ''
        if ($syncedGlobalAdmins.Count -gt 0) {
            $detail = (' {0} of them hold Global Administrator: {1}.' -f `
                       $syncedGlobalAdmins.Count, (($syncedGlobalAdmins.UserPrincipalName) -join ', '))
        }

        return @{
            Status   = 'Fail'
            Message  = ('{0} of {1} privileged account(s) are synced from on-premises AD.{2}' -f `
                        $anySynced.Count, $principals.Count, $detail)
            Evidence = $evidence
        }
    }
