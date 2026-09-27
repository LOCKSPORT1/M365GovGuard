function Get-GovGuardPrivilegedRoleName {
    <#
    .SYNOPSIS
        The directory roles this module treats as privileged.

    .DESCRIPTION
        Matched by display name rather than template GUID. Role definitions are
        resolved from the tenant at runtime, so a mistyped GUID cannot silently
        drop a role from every check that depends on it, and the list stays
        readable to anyone reviewing the rules.

        Global Administrator is the obvious one, but an account holding
        Privileged Role Administrator or Privileged Authentication Administrator
        can grant itself Global Administrator, so they belong in the same tier.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'Global Administrator'
        'Privileged Role Administrator'
        'Privileged Authentication Administrator'
        'Security Administrator'
        'Conditional Access Administrator'
        'Application Administrator'
        'Cloud Application Administrator'
        'Hybrid Identity Administrator'
        'User Administrator'
        'Authentication Administrator'
        'Exchange Administrator'
        'SharePoint Administrator'
        'Intune Administrator'
        'Helpdesk Administrator'
    )
}

function Get-GovGuardPrivilegedPrincipal {
    <#
    .SYNOPSIS
        Every user holding a privileged directory role, with the detail the
        identity rules need.

    .DESCRIPTION
        Returns one object per user - roles collapsed into a list - carrying
        account state, on-premises sync status and sign-in recency.

        Sign-in activity requires Entra ID P1 or better. Without it Graph
        rejects the whole request rather than omitting the property, so the
        query is retried without signInActivity and SignInDataAvailable comes
        back false. A rule that cannot answer its question should say so, not
        report a clean result.

    .OUTPUTS
        PSCustomObject with: PrincipalId, UserPrincipalName, DisplayName, Roles,
        AccountEnabled, OnPremisesSyncEnabled, LastInteractive,
        LastNonInteractive, LastAnySignIn, DaysSinceSignIn, SignInDataAvailable
    #>
    [CmdletBinding()]
    param()

    # --- resolve role definitions -------------------------------------------
    $wanted = Get-GovGuardPrivilegedRoleName
    $definitions = @(Invoke-GovGuardGraph -Uri 'v1.0/roleManagement/directory/roleDefinitions' -All)

    $privilegedRoles = @()
    foreach ($definition in $definitions) {
        $name = [string](Get-GovGuardProperty -InputObject $definition -Path 'displayName')
        if ($wanted -notcontains $name) { continue }
        $privilegedRoles += [pscustomobject]@{
            Id   = [string](Get-GovGuardProperty -InputObject $definition -Path 'id')
            Name = $name
        }
    }

    if ($privilegedRoles.Count -eq 0) {
        throw 'No privileged role definitions resolved. Check Directory.Read.All / RoleManagement.Read.Directory consent.'
    }

    # --- collect assignments -------------------------------------------------
    # roleAssignments requires a filter, so this is one call per role.
    $rolesByPrincipal = @{}

    foreach ($role in $privilegedRoles) {
        $assignments = @()
        try {
            $assignments = @(Invoke-GovGuardGraph -All -Uri (
                "v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '{0}'&`$expand=principal" -f $role.Id))
        }
        catch {
            Write-Verbose -Message ("Assignment query failed for '{0}': {1}" -f $role.Name, $_.Exception.Message)
            continue
        }

        foreach ($assignment in $assignments) {
            $principal = Get-GovGuardProperty -InputObject $assignment -Path 'principal'
            if ($null -eq $principal) { continue }

            # Groups and service principals are out of scope here; they need
            # their own treatment and would distort a per-user count.
            $odataType = [string](Get-GovGuardProperty -InputObject $principal -Path '@odata.type')
            if ($odataType -notmatch 'user') { continue }

            $principalId = [string](Get-GovGuardProperty -InputObject $principal -Path 'id')
            if (-not $principalId) { continue }

            if (-not $rolesByPrincipal.ContainsKey($principalId)) {
                $rolesByPrincipal[$principalId] = [System.Collections.Generic.List[string]]::new()
            }
            if ($rolesByPrincipal[$principalId] -notcontains $role.Name) {
                $rolesByPrincipal[$principalId].Add($role.Name)
            }
        }
    }

    if ($rolesByPrincipal.Keys.Count -eq 0) { return @() }

    # --- enrich each principal ----------------------------------------------
    $withSignIn = 'id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled,createdDateTime,signInActivity'
    $withoutSignIn = 'id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled,createdDateTime'

    $signInAvailable = $true
    $now = (Get-Date).ToUniversalTime()
    $results = @()

    foreach ($principalId in $rolesByPrincipal.Keys) {

        $user = $null
        if ($signInAvailable) {
            try {
                $user = Invoke-GovGuardGraph -Raw -Uri ("v1.0/users/{0}?`$select={1}" -f $principalId, $withSignIn)
            }
            catch {
                # P1 is required for signInActivity; the request fails whole.
                Write-Verbose -Message ("signInActivity unavailable, falling back: {0}" -f $_.Exception.Message)
                $signInAvailable = $false
            }
        }

        if ($null -eq $user) {
            try {
                $user = Invoke-GovGuardGraph -Raw -Uri ("v1.0/users/{0}?`$select={1}" -f $principalId, $withoutSignIn)
            }
            catch {
                Write-Verbose -Message ("Could not read user {0}: {1}" -f $principalId, $_.Exception.Message)
                continue
            }
        }

        $interactive = $null
        $nonInteractive = $null
        if ($signInAvailable) {
            $activity = Get-GovGuardProperty -InputObject $user -Path 'signInActivity'
            $rawInteractive = Get-GovGuardProperty -InputObject $activity -Path 'lastSignInDateTime'
            $rawNonInteractive = Get-GovGuardProperty -InputObject $activity -Path 'lastNonInteractiveSignInDateTime'

            if ($rawInteractive)    { $interactive    = [datetime]$rawInteractive }
            if ($rawNonInteractive) { $nonInteractive = [datetime]$rawNonInteractive }
        }

        # Either kind of sign-in counts as use. A vendor integration account may
        # only ever authenticate non-interactively.
        $lastAny = $null
        foreach ($candidate in @($interactive, $nonInteractive)) {
            if ($null -eq $candidate) { continue }
            if ($null -eq $lastAny -or $candidate -gt $lastAny) { $lastAny = $candidate }
        }

        $daysSince = $null
        if ($lastAny) { $daysSince = [math]::Floor(($now - $lastAny.ToUniversalTime()).TotalDays) }

        $syncEnabled = Get-GovGuardProperty -InputObject $user -Path 'onPremisesSyncEnabled'

        $results += [pscustomobject]@{
            PrincipalId           = $principalId
            UserPrincipalName     = [string](Get-GovGuardProperty -InputObject $user -Path 'userPrincipalName')
            DisplayName           = [string](Get-GovGuardProperty -InputObject $user -Path 'displayName')
            Roles                 = @($rolesByPrincipal[$principalId])
            AccountEnabled        = [bool](Get-GovGuardProperty -InputObject $user -Path 'accountEnabled')
            OnPremisesSyncEnabled = ($syncEnabled -eq $true)
            CreatedDateTime       = [string](Get-GovGuardProperty -InputObject $user -Path 'createdDateTime')
            LastInteractive       = $interactive
            LastNonInteractive    = $nonInteractive
            LastAnySignIn         = $lastAny
            DaysSinceSignIn       = $daysSince
            SignInDataAvailable   = $signInAvailable
        }
    }

    return @($results | Sort-Object -Property UserPrincipalName)
}
