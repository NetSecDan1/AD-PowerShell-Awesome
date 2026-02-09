# RODC Reporting Suite

A collection of read-only PowerShell diagnostic scripts for auditing, monitoring, and optimizing Read-Only Domain Controller (RODC) deployments in Active Directory environments.

## Overview

Read-Only Domain Controllers are commonly deployed in branch offices and edge locations where physical security cannot be guaranteed. While RODCs reduce the attack surface, they introduce operational complexity around authentication caching, replication health, DNS registration, and Password Replication Policy (PRP) management.

The RODC Reporting Suite provides seven scripts that give visibility into every operational dimension of RODC health:

- **Authentication efficiency** -- Are users being serviced locally or falling back to hub DCs?
- **Replication integrity** -- Is stale replication causing authentication failures?
- **Performance baselines** -- What does authentication latency look like across sites?
- **PRP optimization** -- Which accounts should be cached locally?
- **DNS correctness** -- Are SRV records properly registered for each RODC?
- **Security posture** -- Is the RODC hardened according to best practices?
- **Script compatibility** -- Do existing AD scripts break when run against an RODC?

Every script in the suite is **strictly read-only**. No Active Directory objects, DNS records, group memberships, or registry keys are modified. Reports are generated as self-contained HTML files (dark-themed, print-friendly), CSV exports, and JSON files for automation pipelines.

---

## Prerequisites

### Required on All Scripts

| Requirement | Details |
|---|---|
| PowerShell | Version 5.1 or later (Windows PowerShell). All scripts use `#Requires -Version 5.1`. |
| ActiveDirectory module | Included with RSAT (Remote Server Administration Tools). Required by all scripts except `Test-RODCScriptCompatibility.ps1`. |
| Permissions | Domain Admin, or delegated read permissions on RODC computer objects, event logs, and DNS zones. |

### Required by Specific Scripts

| Requirement | Scripts |
|---|---|
| `repadmin.exe` | `Get-RODCReplicationAuthCorrelation.ps1`, `Get-RODCAuthPerformance.ps1` |
| `DnsServer` module | `Test-RODCDnsRegistration.ps1` |
| WinRM enabled on RODCs | `Get-RODCReplicationAuthCorrelation.ps1`, `Get-RODCAuthSourceAnalysis.ps1`, `Get-RODCAuthPerformance.ps1`, `Get-RODCPRPRecommendations.ps1` |
| Audit policy: "Credential Validation" | `Get-RODCAuthSourceAnalysis.ps1`, `Get-RODCPRPRecommendations.ps1` (Event ID 4649) |
| Audit policy: "Kerberos Authentication Service" / "Kerberos Service Ticket Operations" | `Get-RODCReplicationAuthCorrelation.ps1`, `Get-RODCAuthPerformance.ps1` (Event IDs 4768, 4769, 4776) |

### Verifying Prerequisites

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Check for ActiveDirectory module
Get-Module -ListAvailable -Name ActiveDirectory

# Check for DnsServer module
Get-Module -ListAvailable -Name DnsServer

# Check for repadmin
Get-Command repadmin.exe -ErrorAction SilentlyContinue

# Verify audit policy on an RODC
Invoke-Command -ComputerName RODC01 -ScriptBlock {
    auditpol /get /subcategory:"Credential Validation"
    auditpol /get /subcategory:"Kerberos Authentication Service"
    auditpol /get /subcategory:"Kerberos Service Ticket Operations"
}
```

---

## Quick Start

**Step 1: Download the scripts** to a domain controller or management server with RSAT installed.

**Step 2: Run the simplest script first** to validate your environment:

```powershell
# From a hub DC or management server with RSAT
.\Get-RODCAuthSourceAnalysis.ps1 -RODCName "RODC01" -HoursBack 24
```

**Step 3: Open the HTML report** generated in `C:\Reports\RODC\` and review the findings.

---

## Scripts Reference

---

### 1. Get-RODCReplicationAuthCorrelation.ps1

- **Purpose**: Correlates RODC replication health with authentication failures to identify service-impacting replication issues. Cross-references `repadmin /showrepl` output with Security event log entries (Events 4776, 4768, 4769) to determine whether stale replication is causing authentication problems.
- **Run From**: Hub DC or management server with RSAT and `repadmin.exe`. Can also run directly on an RODC.
- **Output**: HTML report, CSV export, JSON export.
- **Runtime**: 1--3 minutes per RODC (depends on event log volume and WinRM latency).

#### Key Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-RODCName` | `string[]` | All RODCs in forest | One or more RODC hostnames to analyze. Omit to auto-discover all RODCs. |
| `-SiteFilter` | `string[]` | None | Limit analysis to RODCs in specific AD sites. |
| `-HoursBack` | `int` | `24` | Hours of event log and replication history to examine (1--8760). |
| `-ReplicationThresholdMinutes` | `int` | `60` | Replication lag in minutes beyond which an RODC is flagged as stale (1--1440). |
| `-AuthFailureThreshold` | `int` | `10` | Minimum authentication failures to flag the RODC (1--100000). |
| `-OutputPath` | `string` | `C:\Reports\RODC` | Directory for output files. Created automatically if it does not exist. |

#### Basic Usage

```powershell
# Analyze all RODCs in the forest with defaults (last 24 hours)
.\Get-RODCReplicationAuthCorrelation.ps1

# Analyze a specific RODC over the last 48 hours
.\Get-RODCReplicationAuthCorrelation.ps1 -RODCName RODC01 -HoursBack 48
```

#### Advanced Usage

```powershell
# Analyze RODCs in a specific site with tighter thresholds
.\Get-RODCReplicationAuthCorrelation.ps1 `
    -SiteFilter "BranchOffice-NYC" `
    -HoursBack 72 `
    -ReplicationThresholdMinutes 30 `
    -AuthFailureThreshold 5 `
    -OutputPath "D:\AuditReports"

# Analyze multiple named RODCs
.\Get-RODCReplicationAuthCorrelation.ps1 `
    -RODCName RODC01, RODC02, RODC03 `
    -HoursBack 48 `
    -Verbose
```

#### Report Highlights

- Executive summary with total RODCs, replication issues, auth failure issues, and correlated findings.
- Per-RODC findings table sorted by impact score (weighted combination of replication lag and failure count).
- Severity ratings: High, Medium, Low based on lag duration and failure volume.
- Detailed evidence sections with naming context replication details, auth failure breakdown (NTLM vs Kerberos), and raw `repadmin` output.

---

### 2. Get-RODCAuthSourceAnalysis.ps1

- **Purpose**: Analyzes where RODC authentication requests are serviced -- local credential cache hits versus hub DC fallback. Identifies accounts generating the most hub fallback traffic, PRP configuration conflicts, and stale allow-list entries.
- **Run From**: Directly on the RODC, or from a hub DC / management server targeting a remote RODC.
- **Output**: HTML report (with SVG score ring visualization), CSV export, JSON export.
- **Runtime**: 30 seconds to 2 minutes per RODC.

#### Key Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-RODCName` | `string` | Local machine | Target RODC hostname. Omit to analyze the local machine. |
| `-HoursBack` | `int` | `24` | Hours of Event 4649 history to analyze (1--8760). |
| `-IncludeComputerAccounts` | `switch` | Off | Include computer accounts (trailing `$`) in analysis. By default, only user and service accounts are reported. |
| `-MinRequestThreshold` | `int` | `5` | Minimum auth requests an account must have before appearing in the top fallback ranking (1--10000). |
| `-OutputPath` | `string` | `C:\Reports\RODC` | Directory for output files. |

#### Basic Usage

```powershell
# Run from the RODC itself, all defaults
.\Get-RODCAuthSourceAnalysis.ps1

# Target a specific RODC from a hub DC
.\Get-RODCAuthSourceAnalysis.ps1 -RODCName "RODC-BRANCH01"
```

#### Advanced Usage

```powershell
# 72-hour window, include computer accounts, lower noise filter
.\Get-RODCAuthSourceAnalysis.ps1 `
    -RODCName "RODC-BRANCH01" `
    -HoursBack 72 `
    -IncludeComputerAccounts `
    -MinRequestThreshold 1 `
    -OutputPath "D:\Audits\RODC"
```

#### Report Highlights

- Cache hit rate as a visual SVG score ring (percentage of requests serviced locally).
- Top 20 fallback accounts ranked by hub fallback count, enriched with account type, PRP status, privileged group membership, and SPNs.
- Configuration issues: PRP conflicts (accounts in both allow and deny lists), stale PRP entries (allowed but never cached), and high-fallback service accounts.
- Estimated latency overhead from hub fallback traffic.
- Evidence section with PRP group DNs, revealed credential list, and sample Event 4649 entries.

---

### 3. Get-RODCAuthPerformance.ps1

- **Purpose**: Measures RODC authentication latency patterns by correlating Kerberos events (4768, 4769, 4649) into authentication "transactions" and computing latency statistics (P50, P95, P99, standard deviation). Optionally includes network baseline tests to hub DCs.
- **Run From**: Hub DC or management server. Can also run on the RODC itself.
- **Output**: HTML report, CSV export (one row per transaction), JSON export.
- **Runtime**: 1--5 minutes per RODC (depends on event volume and optional network tests).

> **Important limitation**: Windows Security event log timestamps have **second** granularity, not millisecond. All latency figures are approximate inter-event timings.

#### Key Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-RODCName` | `string[]` | Local machine | One or more RODC names to analyze. |
| `-HoursBack` | `int` | `24` | Hours of event history to examine (1--720). |
| `-LocalLatencyThresholdMs` | `int` | `200` | Latency threshold in ms for local (cache-hit) transactions. Transactions exceeding this are flagged (1--60000). |
| `-HubLatencyThresholdMs` | `int` | `1000` | Latency threshold in ms for hub DC fallback transactions (1--60000). |
| `-IncludeNetworkTest` | `switch` | Off | Run `Test-NetConnection` against hub DCs on ports 389 (LDAP) and 445 (SMB) for a round-trip-time baseline. |
| `-OutputPath` | `string` | `C:\Reports\RODC` | Directory for output files. |

#### Basic Usage

```powershell
# Analyze the local RODC with defaults
.\Get-RODCAuthPerformance.ps1

# Analyze two RODCs over 48 hours with network baseline
.\Get-RODCAuthPerformance.ps1 -RODCName "RODC01","RODC02" -HoursBack 48 -IncludeNetworkTest
```

#### Advanced Usage

```powershell
# Tighter thresholds and custom output
.\Get-RODCAuthPerformance.ps1 `
    -RODCName "RODC01" `
    -HoursBack 72 `
    -LocalLatencyThresholdMs 100 `
    -HubLatencyThresholdMs 500 `
    -IncludeNetworkTest `
    -OutputPath "D:\AuditReports"
```

#### Report Highlights

- Executive summary: total transactions, local vs hub counts, median and P95 latencies, threshold exceedance counts.
- Per-RODC performance table with site, hub DC partner, network RTT, and latency percentiles.
- Top latency outliers table (transactions exceeding 2 standard deviations from mean).
- Hub DC load distribution: which hub DCs are handling the most fallback traffic and their associated latency.
- Limitations section documenting the second-granularity constraint and other caveats.

---

### 4. Get-RODCPRPRecommendations.ps1

- **Purpose**: Analyzes authentication event patterns (Event 4649) and current PRP configuration to generate scored, actionable recommendations for which accounts to add to the Password Replication Policy allow list. Flags privileged accounts, sensitive service accounts, and multi-site authentication patterns as high-risk exclusions.
- **Run From**: Hub DC or management server. Can target a specific RODC or all RODCs in the domain.
- **Output**: HTML report (with implementation commands), CSV export, JSON export.
- **Runtime**: 1--5 minutes depending on number of RODCs and unique accounts.

> **Read-only**: This script does NOT modify any PRP groups. Implementation commands are provided in the report with `-WhatIf` for manual review and execution.

#### Key Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-RODCName` | `string` | All RODCs in domain | Name of a specific RODC to analyze. Omit to analyze all. |
| `-DaysBack` | `int` | `7` | Days of Event 4649 history to analyze (1--365). |
| `-MinRequestThreshold` | `int` | `10` | Minimum average requests per day for an account to be recommended (1--10000). |
| `-ExcludePrivileged` | `bool` | `$true` | Exclude privileged accounts (Domain Admins, Enterprise Admins, etc.) from allow-list recommendations. |
| `-OutputPath` | `string` | `C:\Reports\RODC` | Directory for output files. |

#### Basic Usage

```powershell
# Analyze all RODCs in the domain, 7-day window
.\Get-RODCPRPRecommendations.ps1

# Analyze a specific RODC with 14-day lookback
.\Get-RODCPRPRecommendations.ps1 -RODCName "RODC-BRANCH01" -DaysBack 14
```

#### Advanced Usage

```powershell
# Lower threshold, verbose output, custom path
.\Get-RODCPRPRecommendations.ps1 `
    -RODCName "RODC-BRANCH01" `
    -DaysBack 14 `
    -MinRequestThreshold 5 `
    -ExcludePrivileged $true `
    -OutputPath "D:\AuditReports" `
    -Verbose
```

#### Report Highlights

- Executive summary: total accounts analyzed, recommended additions, high-risk exclusions, estimated hub fallback reduction percentage.
- Recommendations table ranked by impact score (requests/day multiplied by hub latency penalty), showing account type, PRP status, risk level, and actionable recommendation.
- Conflicts and warnings: PRP allow/deny conflicts, privileged high-volume accounts, sensitive service accounts with high fallback rates.
- Implementation commands section with ready-to-use `Add-ADGroupMember` commands (all include `-WhatIf` by default).
- Risk scoring: accounts are scored on privilege level, SPN sensitivity, multi-site usage, and request volume.

---

### 5. Test-RODCScriptCompatibility.ps1

- **Purpose**: Audits a directory of existing PowerShell scripts for RODC compatibility issues. Detects four categories of problems: writable LDAP operations (`Set-AD*`, `New-AD*`, `Remove-AD*`), FSMO role assumptions, unreplicated attribute references, and WinRM assumptions without error handling. Optionally generates patched script copies with RODC compatibility guards.
- **Run From**: Any machine with PowerShell 5.1. **No Active Directory module required** (static code analysis only).
- **Output**: HTML report, CSV inventory, optional patched script copies (`.RODC-Compatible.ps1` suffix).
- **Runtime**: Seconds. Static analysis scales linearly with total lines of code.

#### Key Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ScriptPath` | `string` | **Required** | Directory containing `.ps1` scripts to scan. Searched recursively. |
| `-OutputPath` | `string` | `C:\Reports\RODC` | Directory for CSV, HTML, and patched scripts. |
| `-AutoPatch` | `switch` | Off | Generate RODC-compatible patched copies of scripts with auto-patchable issues. Original files are **never** modified. |

#### Basic Usage

```powershell
# Scan all scripts in a directory
.\Test-RODCScriptCompatibility.ps1 -ScriptPath "C:\Scripts\AD"

# Scan with verbose output
.\Test-RODCScriptCompatibility.ps1 -ScriptPath "C:\Scripts\AD" -Verbose
```

#### Advanced Usage

```powershell
# Scan and generate patched copies
.\Test-RODCScriptCompatibility.ps1 `
    -ScriptPath "D:\Ops\DC-Scripts" `
    -OutputPath "D:\Audit" `
    -AutoPatch `
    -Verbose
```

#### Report Highlights

- Health ring showing percentage of compatible scripts.
- Executive summary: scripts scanned, compatible, incompatible, review needed, severity breakdown.
- Issue category breakdown: write operations, FSMO assumptions, unreplicated attributes, WinRM issues.
- Per-script inventory table with issue counts, severity levels, and compatibility status.
- Detailed findings table with script name, issue type, line number, code snippet, description, severity, and auto-patchability.
- Auto-patched scripts section (when `-AutoPatch` is used) listing original and patched file paths.

#### Patched Script Behavior

When `-AutoPatch` is enabled, patched copies include:
- An `-ExcludeRODCs` parameter added to the param block.
- `Test-IsRODC` and `Get-WritableDC` helper functions.
- RODC guard wrappers around `Set-AD*`, `New-AD*`, `Remove-AD*`, and account mutation cmdlets.
- `-ErrorAction Stop` added to WinRM cmdlets missing error handling.
- Updated `.NOTES` section documenting the RODC compatibility changes.

---

### 6a. Test-RODCSecurityPosture.ps1

> **Status**: Planned. This script is not yet included in the repository.

- **Purpose**: Validates RODC security hardening against Microsoft best practices, including BitLocker status, credential caching limits, delegated administration configuration, firewall rules, and physical security indicators.
- **Run From**: Hub DC or management server with RSAT.
- **Output**: HTML report, CSV export, JSON export.
- **Runtime**: 1--2 minutes per RODC (estimated).

This script will be documented in detail once it is added to the suite.

---

### 6d. Test-RODCDnsRegistration.ps1

- **Purpose**: Verifies RODC DNS SRV record registration in AD-integrated DNS zones. Checks for required site-specific and domain-wide `_kerberos` and `_ldap` SRV records, Global Catalog SRV records (if applicable), forward (A) records, reverse (PTR) records, incorrect writable-DC-only SRV records that should not exist on an RODC, and DNS scavenging configuration.
- **Run From**: Domain controller or management server with DNS management access (DnsServer module).
- **Output**: HTML report, CSV export, JSON export, optional remediation script.
- **Runtime**: 15--60 seconds per RODC.

#### Key Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-RODCName` | `string[]` | All RODCs in domain | One or more RODC hostnames to check. Omit to discover all RODCs. |
| `-DnsServer` | `string` | PDC Emulator | DNS server to query for record validation. |
| `-OutputPath` | `string` | `C:\Reports\RODC` | Directory for output files. |
| `-GenerateRemediationScript` | `switch` | Off | Generate a `.ps1` file containing `Add-DnsServerResourceRecord` commands for any missing records. The script is **not** auto-executed. |

#### Basic Usage

```powershell
# Check all RODCs, query the PDC Emulator
.\Test-RODCDnsRegistration.ps1

# Check a specific RODC
.\Test-RODCDnsRegistration.ps1 -RODCName "RODC01"
```

#### Advanced Usage

```powershell
# Check specific RODCs against a specific DNS server, generate remediation script
.\Test-RODCDnsRegistration.ps1 `
    -RODCName "RODC01","RODC02" `
    -DnsServer "DC01.corp.contoso.com" `
    -OutputPath "D:\Audits\RODC" `
    -GenerateRemediationScript `
    -Verbose
```

#### Report Highlights

- Health ring showing percentage of RODCs with clean DNS registration.
- Executive summary dashboard: total RODCs, passed, warnings, failed, missing SRV count, incorrect SRV count.
- Findings table per RODC: missing SRV records, incorrect SRV records, A record status, PTR record status, overall status.
- DNS scavenging configuration table: aging enabled/disabled, refresh and no-refresh intervals, risk assessment.
- Per-RODC evidence panels (collapsible) with detailed missing and incorrect record lists.
- Remediation script (when requested) with `Add-DnsServerResourceRecord` commands, each commented with the RODC name and record type.

#### DNS Records Checked

| Record Type | Description |
|---|---|
| `_kerberos._tcp.<Site>._sites.dc._msdcs.<Domain>` | Site-specific Kerberos SRV (required) |
| `_kerberos._tcp.dc._msdcs.<Domain>` | Domain-wide Kerberos SRV (required) |
| `_ldap._tcp.<Site>._sites.dc._msdcs.<Domain>` | Site-specific LDAP SRV (required) |
| `_ldap._tcp.dc._msdcs.<Domain>` | Domain-wide LDAP SRV (required) |
| `_kerberos._tcp.<Site>._sites.<Domain>` | Site-specific Kerberos (required) |
| `_ldap._tcp.<Site>._sites.<Domain>` | Site-specific LDAP (required) |
| `_gc._tcp.<Site>._sites.<ForestRoot>` | Global Catalog SRV (if RODC is GC) |
| A record in forward zone | Host record (required) |
| PTR record in reverse zone | Reverse lookup record (recommended) |
| `_kerberos._tcp.<Domain>` | **Should NOT exist** for RODC (writable DC only) |
| `_ldap._tcp.pdc._msdcs.<Domain>` | **Should NOT exist** for RODC (PDC Emulator only) |

---

## Recommended Execution Order

When deploying the suite for the first time, run the scripts in this order. Each step builds confidence and context for the next.

| Order | Script | Reasoning |
|---|---|---|
| 1 | **Get-RODCAuthSourceAnalysis.ps1** (Report 2) | Simplest single-RODC script. Validates that event logs are configured, WinRM is reachable, and the ActiveDirectory module works. Immediately shows cache hit rate. |
| 2 | **Test-RODCDnsRegistration.ps1** (Report 6d) | Quick to run, high-visibility results. DNS issues are one of the most common causes of RODC problems. Fixes here often resolve other issues. |
| 3 | **Get-RODCReplicationAuthCorrelation.ps1** (Report 1) | Builds on the auth data from Report 2 by adding replication health correlation. Identifies whether replication lag is causing the auth failures you observed. |
| 4 | **Get-RODCPRPRecommendations.ps1** (Report 4) | Uses the same Event 4649 data as Report 2. Now that you understand auth patterns and replication health, PRP recommendations are actionable. |
| 5 | **Get-RODCAuthPerformance.ps1** (Report 3) | Most data-intensive script. Requires a good baseline understanding from previous reports. Latency outlier analysis is most meaningful after DNS and replication issues are resolved. |
| 6 | **Test-RODCSecurityPosture.ps1** (Report 6a) | Comprehensive security audit. Best run after operational issues are resolved so that findings reflect the intended security posture. *(Planned -- not yet available.)* |
| 7 | **Test-RODCScriptCompatibility.ps1** (Report 5) | Ongoing task. Run against your existing AD script library at any time. Independent of the other reports. |

---

## Output Files

### Directory Structure

All scripts default to `C:\Reports\RODC` and create the directory automatically if it does not exist. Override with `-OutputPath`.

```
C:\Reports\RODC\
    RODCCorrelation_20260209_143022.html
    RODCCorrelation_20260209_143022.csv
    RODCCorrelation_20260209_143022.json
    RODC-AuthSource_RODC01_20260209_150105.html
    RODC-AuthSource_RODC01_20260209_150105.csv
    RODC-AuthSource_RODC01_20260209_150105.json
    RODCAuthPerformance_20260209_151530.html
    RODCAuthPerformance_20260209_151530.csv
    RODCAuthPerformance_20260209_151530.json
    RODC_PRP_Recommendations_20260209_152200.html
    RODC_PRP_Recommendations_20260209_152200.csv
    RODC_PRP_Recommendations_20260209_152200.json
    RODC_ScriptCompatibility_20260209_160000.html
    RODC_ScriptCompatibility_20260209_160000.csv
    RODC-DNS-Report_20260209_161500.html
    RODC-DNS-Report_20260209_161500.csv
    RODC-DNS-Report_20260209_161500.json
    RODC-DNS-Remediation_20260209_161500.ps1
    PatchedScripts\
        MyScript.RODC-Compatible.ps1
```

### File Naming Convention

All output files use the pattern:

```
<ReportPrefix>_<Timestamp>.{html|csv|json}
```

The timestamp is formatted as `yyyyMMdd_HHmmss` (e.g., `20260209_143022`), ensuring that repeated runs do not overwrite previous reports.

### Output Formats

| Format | Purpose |
|---|---|
| **HTML** | Self-contained, dark-themed report suitable for viewing in any browser. Includes embedded CSS with no external dependencies. Print-friendly with `@media print` styles. |
| **CSV** | Flat export of findings for import into Excel, Power BI, or any tabular analysis tool. One row per finding/account/transaction. |
| **JSON** | Full-depth structured export including report metadata, executive summary, detailed findings, and evidence. Suitable for automation pipelines and programmatic consumption. |

---

## Safety Design

Every script in the RODC Reporting Suite is designed to be safe for production environments.

### Read-Only Guarantee

- **No `Set-*`, `New-*`, or `Remove-*` AD cmdlets are executed.** All data collection uses `Get-AD*`, `Get-WinEvent`, `Get-DnsServerResourceRecord`, `repadmin /showrepl`, and `Test-NetConnection`.
- **No registry modifications** are made.
- **No Group Policy changes** are applied.
- **No PRP groups are modified.** The PRP Recommendations script provides implementation commands in the report for manual review, but never executes them.
- **No DNS records are created.** The DNS Registration script generates a separate remediation script file that must be manually reviewed and executed by an administrator.
- **Original scripts are never modified** by the Script Compatibility auditor. Patched copies are written as new files with a `.RODC-Compatible.ps1` suffix.

### Graceful Failure Handling

- Unreachable RODCs are skipped with a warning in the report rather than terminating the entire run.
- Empty event logs produce zero counts (not errors).
- Missing modules are detected at startup with clear error messages.
- WinRM connectivity is tested before attempting remote event log queries.

---

## Testing in Non-Production

Before running the suite against production RODCs, follow these best practices:

1. **Start with a single RODC.** Use the `-RODCName` parameter to target one RODC rather than discovering all RODCs automatically.

2. **Use short time windows.** Start with `-HoursBack 1` or `-DaysBack 1` to minimize event log query time and validate that everything works.

3. **Run with `-Verbose`.** All scripts support the `-Verbose` flag and produce detailed diagnostic output showing each step of data collection and analysis.

4. **Review HTML output before scaling.** Open the HTML report and verify that data looks reasonable before running against all RODCs.

5. **Test WinRM connectivity first.** Many scripts require WinRM access to RODCs for remote event log queries:

    ```powershell
    # Test WinRM to a single RODC
    Test-WSMan -ComputerName RODC01

    # Test WinRM to all RODCs
    Get-ADDomainController -Filter { IsReadOnly -eq $true } | ForEach-Object {
        $result = Test-WSMan -ComputerName $_.HostName -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            RODC      = $_.HostName
            Site      = $_.Site
            WinRM     = if ($result) { 'OK' } else { 'FAILED' }
        }
    } | Format-Table -AutoSize
    ```

6. **Verify audit policies.** Scripts that query Event 4649, 4768, 4769, or 4776 require specific audit policies enabled on the target RODCs. If event logs are empty, the reports will show zero findings rather than errors.

7. **Use a lab environment if available.** If you have a test forest with RODCs, run the full suite there first to familiarize yourself with the output format and data volume.

---

## Troubleshooting

### WinRM Not Enabled

**Symptom**: "WinRM is unreachable on this RODC" warnings; auth failure and event log data is missing.

**Solution**:
```powershell
# Enable WinRM on the RODC (requires local admin or GPO)
Invoke-Command -ComputerName RODC01 -ScriptBlock { Enable-PSRemoting -Force }

# Or via Group Policy:
# Computer Configuration > Administrative Templates > Windows Components >
# Windows Remote Management > WinRM Service > Allow remote server management
```

### Missing RSAT Modules

**Symptom**: "The ActiveDirectory PowerShell module is not installed" error at startup.

**Solution**:
```powershell
# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell
Install-WindowsFeature RSAT-DNS-Server

# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0
```

### Event Logs Not Configured

**Symptom**: Reports show zero authentication events, zero cache hits, and zero fallback counts.

**Solution**: Enable the required audit policies on target RODCs:
```powershell
# Enable Credential Validation auditing (for Event 4649)
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Enable Kerberos auditing (for Events 4768, 4769)
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

Alternatively, deploy these via Group Policy linked to the RODC OU:
```
Computer Configuration > Windows Settings > Security Settings >
Advanced Audit Policy Configuration > Account Logon
```

After enabling audit policies, wait at least one `-HoursBack` period before re-running the scripts.

### Insufficient Permissions

**Symptom**: "Access denied" errors when querying RODC event logs, PRP attributes, or DNS zones.

**Solution**: The executing account needs:
- **Read access to RODC computer objects** in AD (specifically `msDS-RevealOnDemandGroup`, `msDS-NeverRevealGroup`, `msDS-RevealedList`, `msDS-RevealedUsers`).
- **Event Log Readers** group membership on target RODCs (or Domain Admin).
- **DNS zone read permissions** for `Test-RODCDnsRegistration.ps1`.
- **`repadmin` access** requires Domain Admin or delegated replication monitoring permissions.

### Empty Results

**Symptom**: Reports are generated but contain no findings or zero rows.

**Common causes**:
1. **No RODCs in the environment.** Verify with `Get-ADDomainController -Filter { IsReadOnly -eq $true }`.
2. **Event logs are empty.** Audit policies may not be enabled (see above).
3. **Time window is too short.** Increase `-HoursBack` or `-DaysBack`.
4. **RODC name is misspelled.** Verify the hostname matches `Get-ADDomainController -Identity RODC01`.
5. **RODC is newly promoted.** A freshly promoted RODC will have no cached credentials, no event history, and minimal DNS registration until clients begin authenticating.

### repadmin Not Found

**Symptom**: "repadmin.exe was not found on this system" error.

**Solution**: Install AD DS management tools:
```powershell
# Windows Server
Install-WindowsFeature RSAT-AD-Tools

# This includes repadmin.exe, dcdiag.exe, and other AD diagnostic tools
```

### Script Compatibility Scanner Reports False Positives

**Symptom**: `Test-RODCScriptCompatibility.ps1` flags lines inside comment blocks or help text.

**Explanation**: The scanner uses line-by-line regex matching. While it includes basic comment block detection, some edge cases (nested comments, here-strings containing AD cmdlet names) may produce false positives. Review each finding in the HTML report and use the code snippet and line number to determine whether the flagged code is actually executed.

---

## Contributing

This suite is part of the AD-PowerShell-Awesome project. Contributions, bug reports, and feature requests are welcome. When contributing scripts:

- Maintain the **read-only design principle** -- no modifications to AD, DNS, or RODC configuration.
- Include comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`).
- Generate output in all three formats: HTML, CSV, and JSON.
- Use timestamp-based filenames to avoid overwriting previous reports.
- Support `-Verbose` for diagnostic output.
- Handle unreachable RODCs gracefully rather than terminating.
