<#
    Menu manifest - M365GovGuard

    Module discovery: the launcher imports the module once and drives its exported
    functions in-process, so the Graph session established by Connect-GovGuard
    persists between menu selections.
#>
@{

    Title   = 'M365 GovGuard - posture assessment'

    Root    = '.'

    Reports = 'Reports'

    LogPath = 'Logs\launcher.jsonl'

    Notice  = 'Connect first (C). Audits are read-only. Remediation previews unless you choose Apply.'

    # ------------------------------------------------------------------
    # Multi-tenant. The picker resolves each domain to its GUID and cloud with
    # an unauthenticated discovery probe, then injects both into any command
    # that exposes them - so the tenant is chosen once, shown in the banner,
    # recorded in every log line, and never retyped.
    # ------------------------------------------------------------------
    Tenants              = 'tenants.psd1'
    TenantParameter      = 'TenantId'
    TenantCloudParameter = 'Cloud'
    RequireTenant        = $true
    OnTenantSwitch       = 'Disconnect-GovGuard'

    # Session gating. SessionProbe is any command that throws when there is no
    # session; the engine uses it for the banner status and to offer a connect
    # before running anything marked RequiresSession.
    SessionProbe         = 'Get-GovGuardContext'
    SessionConnectKey    = 'C'

    Discovery = @{
        Mode       = 'Module'
        ModulePath = 'M365GovGuard.psd1'

        # Context helpers are noise in the numbered list; the curated keys cover them.
        Exclude    = @('Get-GovGuardContext')
    }

    # GovGuard uses -WhatIfMode, which is a [bool] defaulting to $true rather than a
    # switch. The engine detects that and passes -WhatIfMode:$false explicitly on a
    # live run, instead of omitting it and silently previewing.
    DryRunNames = @('WhatIfMode', 'WhatIf', 'Preview', 'DryRun')

    RedactParameters = @('Password', 'Secret', 'Credential', 'Token', 'ClientSecret')

    Sections = @(

        @{
            Name  = 'SESSION'
            Note  = 'start here'
            Items = @(
                @{
                    Key     = 'C'
                    Label   = 'Connect to a tenant'
                    Command = 'Connect-GovGuard'
                    Mode    = 'Live'
                    Args    = @{ Interactive = $true }
                    Note     = 'auto-detects the cloud; read-only scopes'
                    ReadOnly = $true
                }
                @{
                    Key     = 'W'
                    Label   = 'Connect for remediation'
                    Command = 'Connect-GovGuard'
                    Mode    = 'Live'
                    Args    = @{ Interactive = $true; IncludeWriteScopes = $true }
                    Note    = 'adds ReadWrite scopes - only when you intend to change things'
                }
                @{
                    Key     = 'X'
                    Label   = 'Disconnect'
                    Command = 'Disconnect-GovGuard'
                    Mode    = 'Live'
                    Note     = 'clears the session and the cached context'
                    ReadOnly = $true
                }
            )
        }

        @{
            Name  = 'ASSESS'
            Note  = 'read-only'
            Items = @(
                @{
                    Key     = 'A'
                    Label   = 'Audit all rules'
                    Command = 'Invoke-GovGuardAudit'
                    Mode    = 'Live'
                    Note            = 'runs every applicable rule, changes nothing'
                    ReadOnly        = $true
                    RequiresSession = $true
                }
                @{
                    Key     = 'S'
                    Label   = 'Audit critical and high'
                    Command = 'Invoke-GovGuardAudit'
                    Mode    = 'Live'
                    Args    = @{ Severity = @('Critical', 'High') }
                    Note            = 'the short list for a first look at a new tenant'
                    ReadOnly        = $true
                    RequiresSession = $true
                }
                @{
                    Key     = 'V'
                    Label   = 'View the rule set'
                    Command = 'Get-GovGuardRule'
                    Mode    = 'Live'
                    Note     = 'what will run, and which rules can self-remediate'
                    ReadOnly = $true
                }
            )
        }

        @{
            Name  = 'REPORT'
            Note  = 'JSON evidence bundle plus an HTML read-out'
            Items = @(
                @{
                    Key             = 'E'
                    Label           = 'Audit and export report'
                    Command         = 'Invoke-GovGuardAudit'
                    Mode            = 'Live'
                    Args            = @{ ReportPath = 'Reports' }
                    Note            = 'writes to the Reports folder beside the module'
                    ReadOnly        = $true
                    RequiresSession = $true
                }
            )
        }

        @{
            Name  = 'REMEDIATE'
            Note  = 'preview first, always'
            Items = @(
                @{
                    Key     = 'P'
                    Label   = 'Preview fixes'
                    Command = 'Invoke-GovGuardAudit'
                    Mode    = 'Preview'
                    Args            = @{ Remediate = $true }
                    Note            = 'shows every change it would make, writes nothing'
                    RequiresSession = $true
                }
                @{
                    Key     = 'F'
                    Label   = 'Apply fixes'
                    Command  = 'Invoke-GovGuardAudit'
                    Mode     = 'Live'
                    Args     = @{ Remediate = $true }
                    LiveArgs = @{ Force = $true }
                    Confirm  = $true
                    Note     = 'writes to the tenant - requires write scopes'
                    RequiresSession = $true
                }
            )
        }
    )
}
