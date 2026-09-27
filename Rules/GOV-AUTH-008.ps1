New-GovGuardRule -Id 'GOV-AUTH-008' `
    -Title 'Phishable authentication methods are enabled tenant-wide' `
    -Severity 'High' `
    -Category 'Authentication' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.5.3') `
    -Frameworks @('CIS M365 1.1.x') `
    -Scopes @('Policy.Read.All') `
    -WriteScopes @('Policy.ReadWrite.AuthenticationMethod') `
    -Rationale 'SMS, voice and email OTP are interceptable. Where CUI is in scope the expectation is phishing-resistant authentication - FIDO2 or certificate-based - with the weak methods turned off rather than merely deprioritised.' `
    -ManualFix 'Entra portal > Protection > Authentication methods > Policies. Set SMS, Voice call and Email OTP to Disabled once FIDO2 and/or CBA are enrolled.' `
    -Test {
        param($Context)

        $weakMethods = @('Sms', 'Voice', 'Email')

        $policy = Invoke-GovGuardGraph -Uri 'v1.0/policies/authenticationMethodsPolicy' -Raw
        $configs = @(Get-GovGuardProperty -InputObject $policy -Path 'authenticationMethodConfigurations')

        if ($configs.Count -eq 0) {
            return @{
                Status  = 'Error'
                Message = 'Authentication methods policy returned no configurations.'
            }
        }

        $enabledWeak = @()
        $strongEnabled = @()

        foreach ($config in $configs) {
            $methodId = [string](Get-GovGuardProperty -InputObject $config -Path 'id')
            $state = [string](Get-GovGuardProperty -InputObject $config -Path 'state')

            if ($state -ne 'enabled') { continue }

            if ($weakMethods -contains $methodId) {
                $enabledWeak += $methodId
            }
            if (@('Fido2', 'X509Certificate') -contains $methodId) {
                $strongEnabled += $methodId
            }
        }

        $evidence = [pscustomobject]@{
            EnabledWeakMethods   = $enabledWeak
            EnabledStrongMethods = $strongEnabled
            AllMethodStates      = @($configs | ForEach-Object {
                [pscustomobject]@{
                    Method = [string](Get-GovGuardProperty -InputObject $_ -Path 'id')
                    State  = [string](Get-GovGuardProperty -InputObject $_ -Path 'state')
                }
            })
        }

        if ($enabledWeak.Count -eq 0) {
            return @{
                Status   = 'Pass'
                Message  = 'No phishable methods enabled tenant-wide.'
                Evidence = $evidence
            }
        }

        return @{
            Status   = 'Fail'
            Message  = ('Enabled phishable method(s): {0}. Phishing-resistant enabled: {1}.' -f `
                        ($enabledWeak -join ', '), `
                        $(if ($strongEnabled.Count -gt 0) { $strongEnabled -join ', ' } else { 'none' }))
            Evidence = $evidence
        }
    } `
    -Remediate {
        param($Context, $Finding, $WhatIfMode)

        $odataTypes = @{
            'Sms'   = '#microsoft.graph.smsAuthenticationMethodConfiguration'
            'Voice' = '#microsoft.graph.voiceAuthenticationMethodConfiguration'
            'Email' = '#microsoft.graph.emailAuthenticationMethodConfiguration'
        }

        $targets = @($Finding.Evidence.EnabledWeakMethods)
        if ($targets.Count -eq 0) {
            return @{ Status = 'Skipped'; Message = 'Nothing to disable.'; Changes = @() }
        }

        # Guard rail: never strip every method and lock the tenant out.
        $strong = @($Finding.Evidence.EnabledStrongMethods)
        $authenticatorEnabled = @($Finding.Evidence.AllMethodStates | Where-Object {
            $_.Method -eq 'MicrosoftAuthenticator' -and $_.State -eq 'enabled'
        }).Count -gt 0

        if ($strong.Count -eq 0 -and -not $authenticatorEnabled) {
            return @{
                Status  = 'Skipped'
                Message = 'Refusing to disable weak methods: no FIDO2, CBA or Authenticator is enabled. Enroll a stronger method first.'
                Changes = @()
            }
        }

        $changes = @()
        foreach ($method in $targets) {
            if (-not $odataTypes.ContainsKey($method)) { continue }

            $uri = 'v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/{0}' -f $method
            $body = @{
                '@odata.type' = $odataTypes[$method]
                'state'       = 'disabled'
            }

            if ($WhatIfMode) {
                $changes += ('WOULD PATCH {0} -> state=disabled' -f $uri)
                continue
            }

            Invoke-GovGuardGraph -Uri $uri -Method PATCH -Body $body | Out-Null
            $changes += ('PATCHED {0} -> state=disabled' -f $uri)
        }

        return @{
            Status  = $(if ($WhatIfMode) { 'WouldRemediate' } else { 'Remediated' })
            Message = ('{0} method(s): {1}' -f $(if ($WhatIfMode) { 'Would disable' } else { 'Disabled' }), ($targets -join ', '))
            Changes = $changes
        }
    }
