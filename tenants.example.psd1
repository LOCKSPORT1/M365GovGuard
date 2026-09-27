<#
    Tenant list - example.

    Copy to tenants.psd1 and fill in. The real file is gitignored: tenant ids
    are not secret, but a published list of who you administer is not useful to
    anyone except someone targeting them.

    Per tenant:
      Name      what the picker and the launcher log show
      Domain    any verified domain; resolves the GUID and cloud unauthenticated
      Cloud     Global, USGov or USGovDoD. Set it explicitly for client tenants -
                discovery is a convenience, and intake should already know.
      TenantId  optional; discovery fills it, and warns if the two disagree
      Note      one line shown under the entry in the picker
#>
@{
    Tenants = @(

        @{
            Name   = 'Example Manufacturing'
            Domain = 'example.com'
            Cloud  = 'Global'
            Note   = 'commercial tenant, hybrid AD'
        }

        @{
            Name   = 'Example Defense'
            Domain = 'exampledefense.onmicrosoft.us'
            Cloud  = 'USGov'
            Note   = 'GCC High - CMMC L2 assessment pending'
        }
    )
}
