function Get-GovCloudProfile {
    <#
    .SYNOPSIS
        Returns the endpoint / environment-parameter profile for a named cloud.

    .DESCRIPTION
        Single source of truth for "which switch do I pass to which module".
        Every other function in the module asks this instead of hardcoding a URL.

        Cloud names:
          Global    - Commercial. GCC (Government Community Cloud, moderate) also
                      lives on these endpoints; it is commercial Entra/Graph with
                      government data-handling commitments. IsGovCommunity is set
                      by Connect-GovGuard from the tenant's license SKUs.
          USGov     - GCC High. Sovereign instance. graph.microsoft.us.
          USGovDoD  - DoD. Sovereign instance. dod-graph.microsoft.us.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Global', 'USGov', 'USGovDoD')]
        [string]$Cloud
    )

    $profiles = @{
        'Global'   = [pscustomobject]@{
            Cloud                  = 'Global'
            DisplayName            = 'Microsoft 365 Commercial / GCC'
            IsSovereign            = $false
            IsGovCommunity         = $false   # set post-auth from SKUs
            GraphEnvironment       = 'Global'
            GraphEndpoint          = 'https://graph.microsoft.com'
            LoginEndpoint          = 'https://login.microsoftonline.com'
            ExchangeEnvironmentName = 'O365Default'
            TeamsEnvironmentName   = $null     # omit the parameter entirely
            AzEnvironment          = 'AzureCloud'
            CloudEndpointId        = 'microsoftonline.com'
            Portals                = [pscustomobject]@{
                Entra    = 'https://entra.microsoft.com'
                M365Admin= 'https://admin.microsoft.com'
                Intune   = 'https://intune.microsoft.com'
                Defender = 'https://security.microsoft.com'
                Purview  = 'https://purview.microsoft.com'
                Azure    = 'https://portal.azure.com'
            }
        }
        'USGov'    = [pscustomobject]@{
            Cloud                  = 'USGov'
            DisplayName            = 'Microsoft 365 GCC High'
            IsSovereign            = $true
            IsGovCommunity         = $true
            GraphEnvironment       = 'USGov'
            GraphEndpoint          = 'https://graph.microsoft.us'
            LoginEndpoint          = 'https://login.microsoftonline.us'
            ExchangeEnvironmentName = 'O365USGovGCCHigh'
            TeamsEnvironmentName   = 'TeamsGCCH'
            AzEnvironment          = 'AzureUSGovernment'
            CloudEndpointId        = 'microsoftonline.us'
            Portals                = [pscustomobject]@{
                Entra    = 'https://entra.microsoft.us'
                M365Admin= 'https://portal.office365.us/adminportal'
                Intune   = 'https://intune.microsoft.us'
                Defender = 'https://security.microsoft.us'
                Purview  = 'https://purview.microsoft.us'
                Azure    = 'https://portal.azure.us'
            }
        }
        'USGovDoD' = [pscustomobject]@{
            Cloud                  = 'USGovDoD'
            DisplayName            = 'Microsoft 365 DoD'
            IsSovereign            = $true
            IsGovCommunity         = $true
            GraphEnvironment       = 'USGovDoD'
            GraphEndpoint          = 'https://dod-graph.microsoft.us'
            LoginEndpoint          = 'https://login.microsoftonline.us'
            ExchangeEnvironmentName = 'O365USGovDoD'
            TeamsEnvironmentName   = 'TeamsDOD'
            AzEnvironment          = 'AzureUSGovernment'
            CloudEndpointId        = 'microsoftonline.us'
            Portals                = [pscustomobject]@{
                Entra    = 'https://entra.microsoft.us'
                M365Admin= 'https://portal.apps.mil/adminportal'
                Intune   = 'https://intune.microsoft.us'
                Defender = 'https://security.apps.mil'
                Purview  = 'https://compliance.apps.mil'
                Azure    = 'https://portal.azure.us'
            }
        }
    }

    return $profiles[$Cloud]
}

function Resolve-GovCloud {
    <#
    .SYNOPSIS
        Detects which Microsoft cloud a tenant lives in, without authenticating.

    .DESCRIPTION
        Probes the OpenID Connect discovery document on each authority. The
        authority that answers for the tenant tells you the cloud instance.

        Caveat worth knowing before you rely on this: GCC High and DoD share
        login.microsoftonline.us, so the probe cannot separate them. When the
        sovereign authority answers, this returns USGov and flags Ambiguous.
        Pass -Cloud explicitly for DoD tenants, or let Connect-GovGuard confirm
        post-auth from the Graph context.

    .PARAMETER TenantDomain
        Any verified domain or the tenant GUID. Example: contoso.onmicrosoft.us

    .EXAMPLE
        Resolve-GovCloud -TenantDomain contoso.onmicrosoft.us
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantDomain,

        [int]$TimeoutSeconds = 15
    )

    # Commercial is probed FIRST and every answer is validated. The sovereign
    # endpoint returns a usable discovery document for domains that do not live
    # there, so "it answered" is not evidence. An answer only counts when the
    # issuer host matches the authority we asked and carries a real tenant GUID.
    $authorities = [ordered]@{
        'Global' = 'https://login.microsoftonline.com'
        'USGov'  = 'https://login.microsoftonline.us'
    }

    $guidPattern = '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'

    foreach ($entry in $authorities.GetEnumerator()) {
        $cloudName = $entry.Key
        $authorityHost = ([System.Uri]$entry.Value).Host
        $uri = '{0}/{1}/v2.0/.well-known/openid-configuration' -f $entry.Value, $TenantDomain

        try {
            $doc = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        }
        catch {
            Write-Verbose -Message ("No response from {0} for '{1}': {2}" -f $cloudName, $TenantDomain, $_.Exception.Message)
            continue
        }

        if (-not $doc -or -not $doc.issuer) { continue }

        # The issuer must name this authority, not redirect us elsewhere.
        $issuerHost = $null
        try { $issuerHost = ([System.Uri]$doc.issuer).Host } catch { }
        if ($issuerHost -ne $authorityHost) {
            Write-Verbose -Message ("{0} answered but issuer host is '{1}' - not a match." -f $cloudName, $issuerHost)
            continue
        }

        # A real tenant resolves to a GUID. 'common' or 'organizations' does not.
        if ($doc.issuer -notmatch $guidPattern) {
            Write-Verbose -Message ("{0} answered without a tenant GUID - generic endpoint, not this tenant." -f $cloudName)
            continue
        }

        # cloud_instance_name, when present, is authoritative over our guess.
        if ($doc.PSObject.Properties.Name -contains 'cloud_instance_name' -and $doc.cloud_instance_name) {
            $instance = $doc.cloud_instance_name
            $expected = if ($cloudName -eq 'Global') { 'microsoftonline.com' } else { 'microsoftonline.us' }
            if ($instance -ne $expected) {
                Write-Verbose -Message ("{0} answered but cloud_instance_name is '{1}'." -f $cloudName, $instance)
                continue
            }
        }

        $cloudProfile = Get-GovCloudProfile -Cloud $cloudName
        $regionScope = $null
        if ($doc.PSObject.Properties.Name -contains 'tenant_region_scope') {
            $regionScope = $doc.tenant_region_scope
        }

        return [pscustomobject]@{
            TenantDomain     = $TenantDomain
            Cloud            = $cloudName
            Profile          = $cloudProfile
            Issuer           = $doc.issuer
            TenantRegionScope= $regionScope
            Ambiguous        = ($cloudName -eq 'USGov')   # could be GCC High or DoD
            Note             = $(
                                   if ($cloudName -eq 'USGov') {
                                       'Sovereign authority answered. This is GCC High or DoD - pass -Cloud USGovDoD if the tenant is DoD.'
                                   }
                                   else {
                                       'Commercial authority answered. Commercial or GCC - GCC is confirmed post-auth from license SKUs.'
                                   }
                               )
        }
    }

    throw ("Could not resolve a Microsoft cloud for '{0}'. Check the domain, or pass -Cloud explicitly." -f $TenantDomain)
}
