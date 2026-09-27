New-GovGuardRule -Id 'GOV-IAM-018' `
    -Title 'Dormant privileged accounts' `
    -Severity 'High' `
    -Category 'Identity' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.1.1', '3.5.6') `
    -Scopes @('RoleManagement.Read.Directory', 'Directory.Read.All', 'AuditLog.Read.All') `
    -Rationale 'A privileged account nobody uses is attack surface with no operational value. Dormant admin accounts are attractive precisely because their absence of normal activity means an attacker using one generates no behavioural anomaly, and nobody notices a password that was never rotated. Vendor and former-staff admin accounts are the common cases.' `
    -ManualFix 'For each account: confirm with the owner whether it is still needed. Disable what is not. For what is, remove the standing assignment and make it PIM-eligible with approval, so the account holds no privilege while dormant. Break-glass accounts are the deliberate exception and should be excluded by name.' `
    -Test {
        param($Context)

        $dormantAfterDays = 90

        $principals = @(Get-GovGuardPrivilegedPrincipal)

        if ($principals.Count -eq 0) {
            return @{
                Status  = 'Pass'
                Message = 'No users hold privileged directory roles.'
            }
        }

        # Without Entra ID P1 the question cannot be answered at all. Say so
        # rather than reporting a pass built on absent data.
        if (-not $principals[0].SignInDataAvailable) {
            return @{
                Status   = 'NotApplicable'
                Message  = 'Sign-in activity requires Entra ID P1 or better; this tenant did not return it. Review privileged account activity in the sign-in logs instead.'
                Evidence = [pscustomobject]@{
                    PrivilegedAccountCount = $principals.Count
                    SignInDataAvailable    = $false
                }
            }
        }

        $enabled = @($principals | Where-Object { $_.AccountEnabled })

        $dormant = @($enabled | Where-Object {
            $null -eq $_.LastAnySignIn -or $_.DaysSinceSignIn -ge $dormantAfterDays
        })

        $evidence = [pscustomobject]@{
            DormantAccounts = @($dormant | ForEach-Object {
                [pscustomobject]@{
                    UserPrincipalName = $_.UserPrincipalName
                    Roles             = ($_.Roles -join ', ')
                    CloudOnly         = (-not $_.OnPremisesSyncEnabled)
                    LastSignIn        = $(if ($_.LastAnySignIn) { $_.LastAnySignIn.ToString('u') } else { 'never in retention window' })
                    DaysSinceSignIn   = $(if ($null -ne $_.DaysSinceSignIn) { $_.DaysSinceSignIn } else { 'n/a' })
                    Created           = $_.CreatedDateTime
                }
            })
            ThresholdDays        = $dormantAfterDays
            PrivilegedEnabled    = $enabled.Count
            PrivilegedTotal      = $principals.Count
            SignInDataAvailable  = $true
        }

        if ($dormant.Count -eq 0) {
            return @{
                Status   = 'Pass'
                Message  = ('All {0} enabled privileged account(s) have signed in within {1} days.' -f $enabled.Count, $dormantAfterDays)
                Evidence = $evidence
            }
        }

        $never = @($dormant | Where-Object { $null -eq $_.LastAnySignIn }).Count

        return @{
            Status   = 'Fail'
            Message  = ('{0} of {1} enabled privileged account(s) dormant beyond {2} days ({3} with no sign-in at all): {4}' -f `
                        $dormant.Count, $enabled.Count, $dormantAfterDays, $never, (($dormant.UserPrincipalName) -join ', '))
            Evidence = $evidence
        }
    }
