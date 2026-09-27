New-GovGuardRule -Id 'GOV-XTAP-017' `
    -Title 'Cross-cloud B2B collaboration with commercial partners is not enabled' `
    -Severity 'Medium' `
    -Category 'ExternalCollaboration' `
    -Clouds @('USGov', 'USGovDoD') `
    -Controls @('3.1.3') `
    -Frameworks @('Operational readiness') `
    -Scopes @('Policy.Read.All') `
    -WriteScopes @('Policy.ReadWrite.CrossTenantAccess') `
    -Rationale 'A sovereign tenant cannot invite a guest from a commercial tenant until the partner cloud is added to allowedCloudEndpoints, and the configuration has to be made on both sides. This is the most common cause of "the invite went out but they cannot redeem it" in GCC High, and it surfaces as a helpdesk problem rather than a policy problem.' `
    -ManualFix 'Entra > External Identities > Cross-tenant access settings > Microsoft cloud settings. Enable Microsoft Azure Commercial. The partner tenant must enable Microsoft Azure Government in the same place, then configure per-organization inbound/outbound settings on both sides.' `
    -Reference 'Verify against current Graph documentation - allowedCloudEndpoints has moved between the beta and v1.0 surfaces.' `
    -Test {
        param($Context)

        $policy = $null
        try {
            $policy = Invoke-GovGuardGraph -Uri 'v1.0/policies/crossTenantAccessPolicy' -Raw
        }
        catch {
            return @{
                Status  = 'Error'
                Message = ('Cross-tenant access policy read failed: {0}' -f $_.Exception.Message)
            }
        }

        $allowed = @(Get-GovGuardProperty -InputObject $policy -Path 'allowedCloudEndpoints')

        $partners = @()
        try {
            $partners = @(Invoke-GovGuardGraph -Uri 'v1.0/policies/crossTenantAccessPolicy/partners' -All)
        }
        catch {
            Write-Verbose -Message ("Partner enumeration failed: {0}" -f $_.Exception.Message)
        }

        $evidence = [pscustomobject]@{
            AllowedCloudEndpoints = $allowed
            ConfiguredPartners    = @($partners | ForEach-Object {
                [pscustomobject]@{
                    TenantId = [string](Get-GovGuardProperty -InputObject $_ -Path 'tenantId')
                    IsServiceProvider = Get-GovGuardProperty -InputObject $_ -Path 'isServiceProvider'
                }
            })
            TenantCloud           = $Context.Cloud
        }

        if ($allowed -contains 'microsoftonline.com') {
            return @{
                Status   = 'Pass'
                Message  = ('Commercial cloud endpoint enabled. {0} partner configuration(s) present.' -f $partners.Count)
                Evidence = $evidence
            }
        }

        return @{
            Status   = 'Fail'
            Message  = ('microsoftonline.com is not in allowedCloudEndpoints (current: {0}). Guests from commercial tenants cannot redeem invitations.' -f `
                        $(if ($allowed.Count -gt 0) { $allowed -join ', ' } else { 'none' }))
            Evidence = $evidence
        }
    } `
    -Remediate {
        param($Context, $Finding, $WhatIfMode)

        $target = 'microsoftonline.com'
        $current = @($Finding.Evidence.AllowedCloudEndpoints)

        if ($current -contains $target) {
            return @{ Status = 'Skipped'; Message = 'Already enabled.'; Changes = @() }
        }

        $desired = @($current + $target | Sort-Object -Unique)
        $body = @{ 'allowedCloudEndpoints' = $desired }

        if ($WhatIfMode) {
            return @{
                Status  = 'WouldRemediate'
                Message = ('Would PATCH allowedCloudEndpoints to: {0}. The partner tenant must make the reciprocal change before invitations redeem.' -f ($desired -join ', '))
                Changes = @(('WOULD PATCH v1.0/policies/crossTenantAccessPolicy -> allowedCloudEndpoints={0}' -f ($desired -join ',')))
            }
        }

        Invoke-GovGuardGraph -Uri 'v1.0/policies/crossTenantAccessPolicy' -Method PATCH -Body $body | Out-Null

        return @{
            Status  = 'Remediated'
            Message = ('allowedCloudEndpoints set to: {0}. This is one half of the configuration - the commercial partner must enable Microsoft Azure Government on their side.' -f ($desired -join ', '))
            Changes = @(('PATCHED v1.0/policies/crossTenantAccessPolicy -> allowedCloudEndpoints={0}' -f ($desired -join ',')))
        }
    }
