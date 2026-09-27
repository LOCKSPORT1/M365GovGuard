function Connect-GovGuard {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph in the correct sovereign cloud and builds the
        module context every rule runs against.

    .DESCRIPTION
        Resolves the cloud (auto-detect or explicit), connects with the matching
        -Environment value, then confirms what it actually connected to rather
        than trusting the request. Also tags the context as GCC when a commercial
        connection returns government license SKUs.

        Two app registrations is the intended pattern: a read-only one for audit
        runs, a separate write-scoped one used only when remediating. Pass
        -IncludeWriteScopes only for the second.

    .PARAMETER TenantId
        Tenant GUID or a verified domain.

    .PARAMETER Cloud
        Auto (default), Global, USGov (GCC High) or USGovDoD.
        Auto cannot separate GCC High from DoD - pass USGovDoD explicitly there.

    .PARAMETER Interactive
        Sign in through the browser. The usual choice at a keyboard.

    .PARAMETER ClientId
        App registration id, for app-only authentication.

    .PARAMETER CertificateThumbprint
        App-only auth. Preferred for scheduled runs; no secrets to rotate.

    .PARAMETER IncludeWriteScopes
        Request the five ReadWrite scopes as well. Only when you intend to
        remediate; an audit does not need them.

    .PARAMETER AdditionalScopes
        Extra Graph scopes beyond the module defaults, for a rule you have added
        that needs a permission the standard set does not cover.

    .EXAMPLE
        Connect-GovGuard -TenantId contoso.onmicrosoft.us -Interactive

    .EXAMPLE
        Connect-GovGuard -TenantId $tid -Cloud USGov -ClientId $appId -CertificateThumbprint $thumb
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [ValidateSet('Auto', 'Global', 'USGov', 'USGovDoD')]
        [string]$Cloud = 'Auto',

        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [string]$CertificateThumbprint,

        [switch]$IncludeWriteScopes,

        [string[]]$AdditionalScopes = @()
    )

    $readScopes = @(
        'Organization.Read.All'
        'Directory.Read.All'
        'Policy.Read.All'
        'RoleManagement.Read.Directory'
        'Application.Read.All'
        'User.Read.All'
        'AuditLog.Read.All'
        'DeviceManagementConfiguration.Read.All'
        'DeviceManagementManagedDevices.Read.All'
    )

    $writeScopes = @(
        'Policy.ReadWrite.ConditionalAccess'
        'Policy.ReadWrite.AuthenticationMethod'
        'Policy.ReadWrite.CrossTenantAccess'
        'Policy.ReadWrite.Authorization'
        'RoleManagement.ReadWrite.Directory'
        'DeviceManagementConfiguration.ReadWrite.All'
    )

    $scopes = @($readScopes)
    if ($IncludeWriteScopes) { $scopes += $writeScopes }
    if ($AdditionalScopes.Count -gt 0) { $scopes += $AdditionalScopes }
    $scopes = @($scopes | Sort-Object -Unique)

    # --- resolve cloud -----------------------------------------------------
    if ($Cloud -eq 'Auto') {
        Write-Verbose -Message ("Auto-detecting cloud for '{0}'..." -f $TenantId)
        $resolved = Resolve-GovCloud -TenantDomain $TenantId
        $Cloud = $resolved.Cloud
        if ($resolved.Ambiguous) {
            Write-Warning -Message $resolved.Note
        }
    }

    $cloudProfile = Get-GovCloudProfile -Cloud $Cloud
    Write-Verbose -Message ("Connecting to {0} ({1})." -f $cloudProfile.DisplayName, $cloudProfile.GraphEndpoint)

    # --- connect -----------------------------------------------------------
    $connectParams = @{
        TenantId    = $TenantId
        Environment = $cloudProfile.GraphEnvironment
        NoWelcome   = $true
        ErrorAction = 'Stop'
    }

    if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
        $connectParams['ClientId'] = $ClientId
        $connectParams['CertificateThumbprint'] = $CertificateThumbprint
    }
    else {
        $connectParams['Scopes'] = $scopes
    }

    Connect-MgGraph @connectParams

    $mgContext = Get-MgContext
    if (-not $mgContext) { throw 'Connect-MgGraph returned no context.' }

    if ($mgContext.Environment -ne $cloudProfile.GraphEnvironment) {
        Write-Warning -Message ("Requested environment '{0}' but the session reports '{1}'." -f $cloudProfile.GraphEnvironment, $mgContext.Environment)
    }

    # --- enrich ------------------------------------------------------------
    $org = @(Invoke-GovGuardGraph -Uri 'v1.0/organization')
    $orgRecord = $null
    if ($org.Count -gt 0) { $orgRecord = $org[0] }

    $verifiedDomains = @()
    if (Test-GovGuardProperty -InputObject $orgRecord -Name 'verifiedDomains') {
        $verifiedDomains = @($orgRecord.verifiedDomains | ForEach-Object { $_.name })
    }

    # GCC detection: commercial endpoints, government SKUs.
    $isGovCommunity = $cloudProfile.IsGovCommunity
    if ($Cloud -eq 'Global') {
        try {
            $skus = @(Invoke-GovGuardGraph -Uri 'v1.0/subscribedSkus')
            $govSku = @($skus | Where-Object {
                (Test-GovGuardProperty -InputObject $_ -Name 'skuPartNumber') -and
                $_.skuPartNumber -match '_GOV|_USGOV|GCC'
            })
            if ($govSku.Count -gt 0) {
                $isGovCommunity = $true
                Write-Verbose -Message ("Government SKUs present ({0}) - treating as GCC." -f ($govSku.skuPartNumber -join ', '))
            }
        }
        catch {
            Write-Verbose -Message ("SKU probe failed, GCC flag left as-is: {0}" -f $_.Exception.Message)
        }
    }

    $script:GovGuardContext = [pscustomobject]@{
        TenantId        = $mgContext.TenantId
        TenantName      = $(if (Test-GovGuardProperty -InputObject $orgRecord -Name 'displayName') { $orgRecord.displayName } else { $TenantId })
        Cloud           = $Cloud
        CloudProfile    = $cloudProfile
        IsGovCommunity  = $isGovCommunity
        IsSovereign     = $cloudProfile.IsSovereign
        VerifiedDomains = $verifiedDomains
        ClientId        = $mgContext.ClientId
        AuthType        = $mgContext.AuthType
        Scopes          = @($mgContext.Scopes)
        HasWriteScopes  = @(@($mgContext.Scopes) | Where-Object { $_ -match 'ReadWrite' }).Count -gt 0
        ConnectedUtc    = (Get-Date).ToUniversalTime()
    }
    $script:GovGuardContext.PSObject.TypeNames.Insert(0, 'GovGuard.Context')

    Write-Host ("Connected to {0} [{1}] as {2}" -f `
        $script:GovGuardContext.TenantName, `
        $cloudProfile.DisplayName, `
        $script:GovGuardContext.AuthType) -ForegroundColor Green

    return $script:GovGuardContext
}

function Get-GovGuardContext {
    <#
    .SYNOPSIS
        Returns the active GovGuard context.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:GovGuardContext) {
        throw 'No GovGuard context. Run Connect-GovGuard first.'
    }
    return $script:GovGuardContext
}

function Disconnect-GovGuard {
    [CmdletBinding()]
    param()

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    $script:GovGuardContext = $null
    Write-Verbose -Message 'GovGuard context cleared.'
}
