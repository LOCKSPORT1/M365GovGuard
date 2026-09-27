# M365GovGuard operations runbook

How to run it, how to change it, and what to do when it misbehaves.

The README explains what the tool is and why it's built the way it is. This is the operational document — the one to follow at a keyboard.

---

## 1. Quick reference

| I want to | Do this |
|---|---|
| Audit a tenant | Launcher → pick tenant → `C` → `A` |
| Audit and produce a report | Launcher → `E` |
| See what would be fixed | Launcher → `P` |
| Actually fix something | Launcher → `W` → `F` |
| Check coverage | `Get-GovGuardCoverage -ByFamily` |
| See the rule set | `Get-GovGuardRule` or launcher → `V` |
| Drill into a finding | `$r \| Where RuleId -eq 'GOV-IAM-019' \| Format-List` |
| Update the module | `Tools\Update-GovGuard.ps1 -ExpectedRuleCount 12` |
| Rebuild the control catalog | `Tools\Convert-ControlCatalog.ps1` (see §6.3) |

**The only destructive path is `F`,** and it requires a write-scoped session, typing the command name to confirm, and every Conditional Access change it makes lands in report-only. Everything else is reads.

---

## 2. First-time setup on a new machine

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
git clone https://github.com/LOCKSPORT1/M365GovGuard.git D:\m365gov
cd D:\m365gov
Copy-Item tenants.example.psd1 tenants.psd1
notepad tenants.psd1     # fill in your tenants
```

Verify before trusting it:

```powershell
Import-Module D:\m365gov\M365GovGuard.psd1 -Force
Get-GovGuardRule
Get-GovGuardCoverage -ByFamily
```

Twelve rules and a coverage table means everything loaded. Warnings during import mean something didn't — see §7.

If deploying to a share rather than cloning, reference it **by hostname, never by IP**. An IP path puts the files in the Internet zone and execution policy blocks them regardless of the `-ExecutionPolicy Bypass` on the launcher.

---

## 3. Running an audit

### 3.1 Through the launcher

```
Launch-GovGuard.cmd
```

1. **Tenant picker.** Pick from the list, or `D` for a domain not on it. The domain resolves to its GUID and cloud over an unauthenticated discovery probe — no credentials needed, works for a prospect you have no access to. An ad-hoc lookup offers to be remembered; it only persists if you say yes.
2. **Banner** shows tenant, cloud, GUID and session state.
3. **`C`** connects with read-only scopes. `TenantId` and `Cloud` are injected from the picker, so there's nothing to type.
4. **`A`** runs every applicable rule. Skip the optional parameters — filtering twelve rules buys nothing.
5. Results print as a table. `E` instead of `A` also writes the report.

Press `A` without connecting and it offers to connect first, then continues into the audit.

### 3.2 From the console

The console is worth using when you want to drill into evidence, which the menu can't do.

```powershell
Import-Module D:\m365gov\M365GovGuard.psd1 -Force
Connect-GovGuard -TenantId contoso.com -Cloud Global -Interactive

$r = Invoke-GovGuardAudit
$r                                              # table
$r | Where-Object Status -eq 'Fail'             # just the failures
$r | Where-Object RuleId -eq 'GOV-IAM-019' | Format-List

# the useful part — the evidence behind a finding
($r | Where-Object RuleId -eq 'GOV-IAM-019').Evidence.SyncedPrivilegedAccounts | Format-Table -Wrap
```

**Sessions are per-process.** A new PowerShell window has no connection, and the launcher's session doesn't carry into a console you open afterwards.

### 3.3 Reading results

| Status | Means |
|---|---|
| `Pass` | The check found what it was looking for |
| `Fail` | It didn't. Read `Message` and `ManualFix` |
| `NotApplicable` | Rule doesn't apply to this cloud. Not a pass |
| `Error` | The rule threw. Usually a missing scope or a permission gap |

`Severity` is the effective severity for this tenant's cloud. Where it differs from `BaseSeverity`, the obligation differs — `GOV-CA-012` is Critical under ITAR and Medium in a commercial tenant.

---

## 4. Remediation

**Always preview first.** `P` in the launcher, or:

```powershell
Invoke-GovGuardAudit -Remediate | Select-Object RuleId, RemediationStatus, RemediationMessage, Changes
```

Nothing is written. `Changes` shows the exact URI and body each fix would send.

To apply, you need a write-scoped session — a different connection than the audit one:

```powershell
Connect-GovGuard -TenantId contoso.com -Cloud Global -Interactive -IncludeWriteScopes
Invoke-GovGuardAudit -Id GOV-AUTH-008 -Remediate -WhatIfMode:$false -Force
```

Or launcher: `W` then `F`. `F` makes you type the command name before it proceeds.

### What remediation will and won't do

- Conditional Access policies are created in **report-only**. The tool never enforces one. Promoting is a human decision after reviewing impact.
- `GOV-AUTH-008` refuses to disable weak MFA methods unless FIDO2, CBA or Authenticator is already enabled — otherwise it would lock out everyone unregistered.
- `GOV-EXT-024` restricts who can invite guests but won't change the guest role level, because that takes access from guests who already have it.
- Four rules have no remediation at all by design. Creating a break-glass account or removing a role assignment isn't a scheduled job's decision.

### After a remediation run

1. Read what changed — `Changes` on each result.
2. For any report-only CA policy created: review its impact in Entra sign-in logs for at least a full business cycle before enabling. Monthly batch jobs are invisible in a week of data.
3. Re-run the audit. The rule should now pass, or tell you what's still missing.

---

## 5. Client engagement workflow

**First contact with a new tenant:**

1. Add it to `tenants.psd1` with `Cloud` set explicitly. Discovery is a convenience; intake should already know which cloud they're in.
2. Connect read-only. Run `A`. Change nothing.
3. Run `E` to produce the report pair.
4. Read the "Worth looking into" section — that's your coverage gap, and it's the honest part of the conversation.

**Producing a deliverable:**

```powershell
Invoke-GovGuardAudit -ReportPath Reports -ClientName 'Contoso Defense'
```

Two files land in `Reports\`. The **HTML** is the client read-out: findings by severity, why each matters, how to fix it. The **JSON** is the evidence bundle — full payloads, control mappings, timestamps. That's what an assessor or a drift comparison works from.

Add `-IncludeEvidence` for your own copy; it's usually noise in a client read-out.

**`Reports\` and `Logs\` are gitignored.** They name real administrators and which accounts are dormant. Keep them out of anything public, and treat them as client-confidential.

---

## 6. Maintenance

### 6.1 The update loop

You edit in one place and everything else pulls.

```powershell
# make a change, test it
cd D:\m365gov
Import-Module .\M365GovGuard.psd1 -Force
Get-GovGuardRule                       # does it still load?

# commit and publish
git add -A
git commit -m "Add GOV-MDM-030: Windows LAPS not deployed"
git push
```

On any other machine or the share copy:

```powershell
D:\m365gov\Tools\Update-GovGuard.ps1 -ExpectedRuleCount 13
```

That pulls, then imports the module **in a separate process** and verifies it loads, the rules registered, and the catalog parses. It fails loudly rather than leaving you with a broken copy. Bump `-ExpectedRuleCount` as the rule set grows — it's what catches a partial copy.

`-WhatIfMode` shows what would change without pulling. `-Source \\server\share\M365GovGuard` copies from a share instead of git.

Local state — `Reports\`, `Logs\`, `tenants.cache.json` — is never touched by an update.

### 6.2 Adding a rule

1. Copy an existing rule in `Rules\` as a starting point. `GOV-IAM-018` is a good detect-only template; `GOV-CA-020` a good remediable one.
2. Pick control ids from the catalog. `Get-GovGuardControlCatalog` inside the module, or read `Controls\nist-800-171-r2.psd1`.
3. `Import-Module .\M365GovGuard.psd1 -Force`. A bad control id warns at import. A rule that fails to parse warns by name.
4. Test it alone: `Invoke-GovGuardAudit -Id GOV-XXX-NNN`.
5. Test what it does on a tenant where it should **pass**, not only one where it fails. A rule that fails everything is indistinguishable from a broken rule.
6. If remediable, run `-Remediate` in preview and read the `Changes` output before ever running it live.
7. Bump `ModuleVersion` in `M365GovGuard.psd1`, commit, push.

### 6.3 Updating the control catalog

Only needed when adopting a new revision or refreshing the source.

```powershell
# get the source
Invoke-WebRequest -Uri 'https://csrc.nist.gov/files/pubs/sp/800/171/r2/upd1/final/docs/sp800-171r2-security-reqs.csv' `
  -OutFile D:\m365gov\Tools\nist-official.csv

# preview
D:\m365gov\Tools\Convert-ControlCatalog.ps1 -CsvPath D:\m365gov\Tools\nist-official.csv `
  -IdColumn 'Identifier' -FamilyColumn 'Family' -StatementColumn 'Security Requirement' `
  -SourceUrl 'https://csrc.nist.gov/...' -ExpectedControlCount 110 -WhatIfMode

# write it
D:\m365gov\Tools\Convert-ControlCatalog.ps1 ... -OutputPath D:\m365gov\Controls\nist-800-171-r2.psd1
```

The generated `.psd1` **is** committed, with its provenance block. The downloaded source is not — it's gitignored and regenerable.

**Moving to a new revision** (Rev 3, say) is a new catalog file plus a crosswalk, not an edit to every rule. Rules keep their control ids; the catalog owns what those ids mean. Don't silently swap baselines — CMMC assesses against Rev 2, and a report citing Rev 3 numbering against a Rev 2 assessment is worse than no report.

### 6.4 Versioning

`ModuleVersion` in `M365GovGuard.psd1` is read at import and stamped into every report. Bump it whenever you push a change that alters behaviour — reports from different dates sitting side by side need to be distinguishable.

Rough convention: patch for a fix, minor for new rules or capabilities, major when the rule schema changes in a way existing rules must be edited for.

---

## 7. Troubleshooting

Every entry here is a failure that actually happened.

### "No commands discovered" / module exports nothing

The `Private\`, `Public\` and `Rules\` subfolders are missing — usually files downloaded individually and landed flat. The module imports cleanly and defines nothing.

```powershell
D:\m365gov\Tools\Repair-GovGuardLayout.ps1 -Path D:\m365gov -WhatIfMode
D:\m365gov\Tools\Repair-GovGuardLayout.ps1 -Path D:\m365gov
```

### Import warnings naming every rule file

Usually one broken shared dependency in `Private\`. Read the first warning, not the twelfth — they're all the same cause.

### Output prints as a wall of properties instead of a table

The format file didn't load. It's cached per session, so `-Force` on the module isn't always enough — **open a new PowerShell window**. If it persists, confirm `M365GovGuard.format.ps1xml` is in the module root and `FormatsToProcess` is in the `.psd1`.

### AADSTS900383 on sign-in

Authenticating to the sovereign authority for a commercial tenant, or the reverse. Pass `-Cloud` explicitly to bypass auto-detection. For client tenants, always set `Cloud` in `tenants.psd1` — discovery is a convenience, not a source of truth.

### "No GovGuard context"

Not connected in this process. Sessions don't cross process boundaries; the launcher's connection isn't available in a console you open afterwards.

### A rule returns `Error`

Usually a missing Graph scope. Check `(Get-MgContext).Scopes` against the rule's `Scopes`. If the scope is present and consented, the API may genuinely not exist in that cloud — a persistent 403 with correct consent is often an availability gap, not a permission problem.

### `HasWriteScopes: True` on a read-only session

The shared `Microsoft Graph Command Line Tools` app accumulates consent tenant-wide, so you inherit scopes you didn't request. Nothing you ran wrote anything, but the separation is nominal. Fix it with dedicated app registrations — one read-only, one write-scoped, both certificate-based.

### `Get-GovGuardCoverage` shows 0 everywhere

The catalog didn't load or the rules didn't register. Check `Controls\nist-800-171-r2.psd1` exists and import warnings.

---

## 8. Safety rules

1. **Never run `F` against a client tenant you haven't previewed with `P` first.**
2. **Never enforce a Conditional Access policy the same day you create it.** Report-only for a full business cycle.
3. **Confirm the banner tenant before anything.** The launcher injects the tenant, so a wrong pick applies to everything that follows.
4. **Reports are client-confidential.** They name privileged accounts and identify which are dormant.
5. **Verify sovereign-cloud claims against the current service description** before they reach a statement of work. Parity moves.
6. **Don't edit generated files** — `Controls\*.psd1` is regenerated by the converter, and hand edits break provenance.

---

## 9. What this does not do

Exchange, Teams, SharePoint tenant settings and Purview are not Graph-native and aren't covered. Roughly a third of 800-171 is policy and process that no tool can observe. `Get-GovGuardCoverage -ByFamily` is the honest picture, and the generated report states the same on its face.

Saying that plainly is better than a coverage number with no caveats.
