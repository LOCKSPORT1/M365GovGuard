@{
    RootModule           = 'M365GovGuard.psm1'
    ModuleVersion        = '0.2.0'
    GUID                 = 'b4c1f0d2-6a7e-4f91-9d33-2f5c8a0e7b14'
    Author               = 'Joshua Christy'
    CompanyName          = ''
    Copyright            = ''
    Description          = 'Cloud-aware posture assessment and remediation engine for Microsoft 365 Commercial, GCC, GCC High and DoD tenants. Graph-native rules with framework mapping and dry-run remediation.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
    )

    FormatsToProcess     = @('M365GovGuard.format.ps1xml')

    FunctionsToExport    = @(
        'Connect-GovGuard',
        'Disconnect-GovGuard',
        'Get-GovGuardContext',
        'Get-GovGuardRule',
        'Get-GovGuardCoverage',
        'Invoke-GovGuardAudit',
        'Export-GovGuardReport'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags       = @('Microsoft365', 'GCCHigh', 'GovCloud', 'Graph', 'CMMC', 'NIST800-171', 'Entra', 'Intune')
            ProjectUri = ''
        }
    }
}
