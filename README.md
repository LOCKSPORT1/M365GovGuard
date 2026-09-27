# M365GovGuard

Posture assessment and remediation for Microsoft 365 tenants, built for the sovereign clouds.

The same rule code runs against Commercial, GCC, GCC High and DoD. No endpoint URLs appear in any rule — the connection broker resolves the cloud and sets the environment, and rules declare which clouds they apply to so a GCC High run doesn't produce a wall of failures for workloads Microsoft hasn't shipped there.

Findings map to NIST SP 800-171 control identifiers from a catalog built out of the published NIST source, so the tool can answer the question a client facing a CMMC assessment actually asks: not "how many checks did you run" but "how much of the standard does this cover."

```
GOV-IAM-019   High    Fail   7 of 9 privileged account(s) are synced from on-premises AD.
                             4 of them hold Global Administrator.
```

## Why it's built this way

**One Graph dependency.** Every rule calls `Invoke-MgGraphRequest` through a wrapper, with relative URIs. `Microsoft.Graph.Authentication` is the only required module, instead of a dozen `Microsoft.Graph.*` submodules whose cmdlet names drift between releases and lag in the sovereign clouds.

**Applicability gating.** Each rule declares its clouds. Out-of-scope rules report `NotApplicable` with a reason rather than failing — and the report names them, because a check that didn't run is a gap in coverage, not a clean result.

**Dry run by default.** `-Remediate` previews. Writing requires `-WhatIfMode:$false -Force` and a session holding ReadWrite scopes.

**Nothing lockout-capable is auto-enforced.** Conditional Access remediations create policies in `enabledForReportingButNotEnforced`. The tool builds the policy; a human promotes it after reviewing report-only impact.

**Some rules refuse to fix themselves.** Removing a role assignment or creating a break-glass account isn't a decision for a scheduled job. Those rules carry a `ManualFix` string instead of a remediation block, and the engine reports `NotSupported` rather than pretending it tried.

**Severity follows the obligation.** A missing country restriction is Critical where ITAR applies and Medium in a commercial tenant. One severity for both teaches people to ignore the rule.

## Install

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
git clone https://github.com/LOCKSPORT1/M365GovGuard.git
Import-Module .\M365GovGuard\M365GovGuard.psd1
```

Deploying to a share: reference it by hostname, not IP — an IP path puts the files in the Internet zone and execution policy blocks them.

## Use

```powershell
# Connect. The cloud is auto-detected from the domain, unauthenticated.
Connect-GovGuard -TenantId contoso.onmicrosoft.us -Interactive

# Audit. Read-only.
Invoke-GovGuardAudit

# Audit and write both report artifacts
Invoke-GovGuardAudit -ReportPath Reports -ClientName 'Contoso Defense'

# Preview every fix without writing anything
Invoke-GovGuardAudit -Remediate | Select RuleId, RemediationStatus, RemediationMessage

# Apply, deliberately
Connect-GovGuard -TenantId contoso.onmicrosoft.us -Interactive -IncludeWriteScopes
Invoke-GovGuardAudit -Id GOV-AUTH-008 -Remediate -WhatIfMode:$false -Force

# What does the rule set cover?
Get-GovGuardCoverage -ByFamily
```

App-only, for scheduled runs:

```powershell
Connect-GovGuard -TenantId $tenantId -Cloud USGov -ClientId $appId -CertificateThumbprint $thumb
```

### Menu

`Launch-GovGuard.cmd` opens a manifest-driven launcher: pick a tenant, connect, audit, preview, report. Parameters are discovered from the commands themselves — script files through the PowerShell AST, module functions through command metadata — so prompts, pickers and help text come from the code rather than being maintained separately. Every invocation is logged to `Logs\launcher.jsonl` with tenant, operator, mode and result.

Copy `tenants.example.psd1` to `tenants.psd1` and fill it in. That file is gitignored.

## Rules

| Id | Severity | Fix | Covers |
|---|---|---|---|
| GOV-AUTH-008 | High | auto | Phishable auth methods enabled tenant-wide |
| GOV-CA-012 | Critical / Medium | auto | No country restriction on sign-in |
| GOV-CA-013 | Critical | auto | Legacy authentication not blocked |
| GOV-CA-020 | Critical | auto | No MFA requirement for all users |
| GOV-CA-022 | High | manual | Access not restricted to compliant devices |
| GOV-APP-023 | High | auto | Users can consent to any application |
| GOV-EXT-024 | Medium / High | partial | Guest invitation and directory permissions |
| GOV-IAM-010 | High | manual | Break-glass accounts missing or CA-covered |
| GOV-IAM-011 | High | manual | Standing Global Admin outside PIM |
| GOV-IAM-018 | High | manual | Dormant privileged accounts |
| GOV-IAM-019 | High | manual | Privileged accounts synced from on-premises AD |
| GOV-XTAP-017 | Medium | auto | Cross-cloud B2B not enabled (GCC High / DoD) |

Twelve rules covering 11 of the 110 controls in 800-171 Rev 2.

## Control catalog

`Controls\nist-800-171-r2.psd1` is generated from the official NIST requirements CSV by `Tools\Convert-ControlCatalog.ps1`, and records where it came from:

```powershell
Provenance = @{
    SourceUrl    = 'https://csrc.nist.gov/.../sp800-171r2-security-reqs.csv'
    SourceSha256 = '0F4D5941...'
    Retrieved    = '2026-09-25'
    Generator    = 'Convert-ControlCatalog.ps1 v1.0'
}
```

A **build step, not a runtime dependency**. A GCC High tenant is frequently administered from a network with no route to the internet, so a tool that fetches its catalog at startup fails in the environment it was built for. The catalog ships with the module.

The converter takes OSCAL JSON or a flat CSV, refuses to write if the parsed count doesn't match `-ExpectedControlCount`, and round-trips its own output before reporting success. CMMC Level 2 practice codes are derived from the family and control id rather than stored, so the mapping isn't typed twice.

Moving to a new revision is a new catalog file plus a crosswalk, not an edit to every rule.

## Coverage, honestly

Eight of the fourteen control families are reachable by an automated tool. The other six — Awareness and Training, Personnel Security, Physical Protection, Incident Response, Maintenance, Security Assessment — are policy and process. No tool sees whether staff completed training or whether the server room door locks, and a tool claiming coverage there would be lying.

Realistic ceiling is somewhere around 55–60 of 110, and roughly a third of the standard will never be automatable. `Get-GovGuardCoverage -ByFamily` shows where the rule set stands and, more usefully, where it doesn't.

Coverage also means a rule tests something relevant to a control — not that the control is satisfied, and not that an automated check addresses it in full. The generated report says so on its face.

## Writing a rule

Drop a `.ps1` in `Rules\` returning one `New-GovGuardRule`. It registers on import.

```powershell
New-GovGuardRule -Id 'GOV-MDM-030' `
    -Title 'Windows LAPS is not deployed' `
    -Severity 'High' `
    -Category 'Endpoint' `
    -Clouds @('Global', 'USGov', 'USGovDoD') `
    -Controls @('3.1.5') `
    -Scopes @('DeviceManagementConfiguration.Read.All') `
    -Rationale 'Shared local administrator passwords survive reimaging and move laterally...' `
    -ManualFix 'Intune > Endpoint security > Account protection > Create LAPS policy...' `
    -Test {
        param($Context)
        # return @{ Status = 'Pass'|'Fail'|'NotApplicable'; Message = ''; Evidence = $obj }
    }
```

Contract:

- `Test` takes `$Context`, returns a **hashtable** with at least `Status`.
- `Remediate` takes `$Context, $Finding, $WhatIfMode` and must make no write calls when `$WhatIfMode` is true.
- Use `Get-GovGuardProperty` rather than dotted paths — Graph omits null properties and the module runs under `Set-StrictMode -Version Latest`.
- Control ids are resolved against the catalog at registration, so a typo warns at import rather than appearing in a deliverable.

## Not here

Exchange Online, Teams, SharePoint tenant settings and Purview aren't Graph-native. Those need `ExchangeOnlineManagement`, `MicrosoftTeams`, `PnP.PowerShell` and Security & Compliance PowerShell, each with its own environment parameter. The connection broker already returns those values, so a second rule provider can be added without touching the engine — that's the main thing standing between the current 11 controls and the achievable ceiling.

## Caveats

1. **Not covered by automated tests.** Exercised against a live commercial tenant; the sovereign code paths are written from the service description and unverified against a real GCC High tenant.
2. **Break-glass detection in CA remediations** finds exclusion accounts by display name prefix. Replace that with configured object ids before any live remediation.
3. **`GOV-CA-012` defaults to US-only.** Change `$permittedCountries` if the client has authorised foreign locations.
4. **Guest role template ids in `GOV-EXT-024`** are stable but worth confirming against current documentation.
5. **Sovereign cloud feature parity moves.** Verify anything time-sensitive against the current Microsoft 365 Government service description.
6. The shared `Microsoft Graph Command Line Tools` app accumulates consent tenant-wide. A read-only session that reports write scopes is inheriting them. Use a dedicated app registration — one read-only for audits, one write-scoped for remediation, both certificate-based — to make the separation real rather than nominal.

## See also

**[M365-Ops-Toolkit](https://github.com/LOCKSPORT1/M365-Ops-Toolkit)** — multi-tenant Microsoft 365 and Azure operations tooling: Graph and ARM core, account containment, Azure posture sweep, runbooks.

## Licence

MIT. See `LICENSE`.
