# AD-PowerShell-Awesome

A curated collection of PowerShell scripts for Active Directory administration, health checking, and security auditing.

## RODC Reporting Suite

The **[RODC Reporting Suite](RODC-Reporting-Suite/)** is a collection of 7 read-only diagnostic scripts for auditing, monitoring, and optimizing Read-Only Domain Controller deployments.

| Script | Purpose |
|--------|---------|
| `Get-RODCAuthSourceAnalysis.ps1` | Analyzes auth requests: local cache hits vs hub DC fallback |
| `Get-RODCAuthPerformance.ps1` | Measures authentication latency patterns across sites |
| `Get-RODCReplicationAuthCorrelation.ps1` | Correlates replication health with auth failures |
| `Get-RODCPRPRecommendations.ps1` | Recommends Password Replication Policy changes based on usage |
| `Test-RODCScriptCompatibility.ps1` | Audits existing AD scripts for RODC compatibility issues |
| `Test-RODCSecurityPosture.ps1` | Validates RODC security hardening (10-point checklist) |
| `Test-RODCDnsRegistration.ps1` | Verifies DNS SRV record registration for RODCs |

All scripts are **strictly read-only** and safe for production use. See the [RODC Reporting Suite README](RODC-Reporting-Suite/README.md) for detailed usage instructions.

### Quick Start

```powershell
# Run from a domain controller or RSAT management server
.\RODC-Reporting-Suite\Get-RODCAuthSourceAnalysis.ps1
.\RODC-Reporting-Suite\Test-RODCDnsRegistration.ps1
.\RODC-Reporting-Suite\Test-RODCSecurityPosture.ps1
```

### Requirements

- Windows PowerShell 5.1+
- ActiveDirectory module (RSAT)
- Domain Admin or delegated read access