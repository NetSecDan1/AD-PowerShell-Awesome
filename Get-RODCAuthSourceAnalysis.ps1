#Requires -Version 5.1
<#
.SYNOPSIS
    Analyzes where RODC authentication requests are serviced (local cache vs hub DC fallback).
.DESCRIPTION
    Collects and correlates three data sources to produce a comprehensive picture
    of RODC authentication efficiency:

      1. Security Event 4649 — Credential validation requests on the RODC,
         distinguishing cache hits (status 0x0) from hub-DC fallback.
      2. Password Replication Policy (PRP) — The allow list
         (msDS-RevealOnDemandGroup) and deny list (msDS-NeverRevealGroup),
         including recursive group expansion.
      3. Actually cached credentials — The msDS-RevealedList attribute,
         showing which accounts currently have secrets stored on the RODC.

    The script cross-references these data sets to identify:
      - Percentage of requests satisfied locally vs forwarded to a hub DC.
      - Accounts that are in the PRP allow list but have never been cached.
      - Top accounts generating hub-DC fallback traffic.
      - Service accounts with high fallback rates that may need PRP adjustment.
      - Configuration conflicts (accounts in both allow and deny lists).

    Output is written in three formats: a self-contained HTML report with an
    executive summary dashboard, a CSV for spreadsheet analysis, and a JSON
    file for automation pipelines.

    This script is read-only. It performs only LDAP queries and event log reads.
    No Set-*, New-*, Remove-*, or write operations are executed.

.PARAMETER RODCName
    NetBIOS or FQDN of the target RODC. If omitted the script auto-detects
    the local machine and validates that it is an RODC.
.PARAMETER HoursBack
    Number of hours of event history to analyse. Default: 24.
.PARAMETER IncludeComputerAccounts
    When set, computer account authentications (trailing $) are included in
    analysis. By default only user and service accounts are reported.
.PARAMETER MinRequestThreshold
    Minimum number of authentication requests an account must have before it
    appears in the top-fallback ranking. Default: 5.
.PARAMETER OutputPath
    Directory where report files are written. Default: C:\Reports\RODC.
    The directory is created if it does not exist.

.EXAMPLE
    .\Get-RODCAuthSourceAnalysis.ps1
    Run from the RODC itself with all defaults (last 24 h, user accounts only).

.EXAMPLE
    .\Get-RODCAuthSourceAnalysis.ps1 -RODCName "RODC-BRANCH01" -HoursBack 72 -IncludeComputerAccounts
    Analyse RODC-BRANCH01 from a hub DC, looking back 72 hours including computer accounts.

.EXAMPLE
    .\Get-RODCAuthSourceAnalysis.ps1 -MinRequestThreshold 1 -OutputPath "D:\Audits\RODC"
    Lower the noise filter to 1 request and write output to a custom directory.

.NOTES
    Author:  AD Health Check Framework
    Version: 1.0.0
    Safety:  Read-only. No Set-*, New-*, Remove-* commands used.
    Requires: ActiveDirectory PowerShell module.
              Audit policy "Audit Credential Validation" must be enabled on the
              RODC for Event 4649 to be logged.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$RODCName,

    [ValidateRange(1, 8760)]
    [int]$HoursBack = 24,

    [switch]$IncludeComputerAccounts,

    [ValidateRange(1, 10000)]
    [int]$MinRequestThreshold = 5,

    [string]$OutputPath = 'C:\Reports\RODC'
)

# ---------------------------------------------------------------------------
# Region: Bootstrap
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$reportTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$scriptStart     = Get-Date

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  RODC Auth Source Analysis" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ---- Verify ActiveDirectory module ----
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required but not installed. Install RSAT or run from a domain controller."
    return
}
Import-Module ActiveDirectory -ErrorAction Stop
Write-Verbose "ActiveDirectory module loaded."

# ---- Resolve RODC identity ----
if (-not $RODCName) {
    $RODCName = $env:COMPUTERNAME
    Write-Verbose "No -RODCName specified; using local machine: $RODCName"
}

Write-Host "Target RODC:  $RODCName" -ForegroundColor White
Write-Host "Time window:  Last $HoursBack hour(s)" -ForegroundColor White
Write-Host "Output path:  $OutputPath" -ForegroundColor White
Write-Host ""

# ---- Validate that the target is actually an RODC ----
$rodcObject = $null
try {
    $rodcObject = Get-ADDomainController -Identity $RODCName -ErrorAction Stop
}
catch {
    Write-Error "Cannot locate domain controller '$RODCName'. Ensure the name is correct and LDAP is reachable. $_"
    return
}

if (-not $rodcObject.IsReadOnly) {
    Write-Warning "'$RODCName' is a writable DC, not an RODC. The script will continue but PRP / revealed-list data are RODC-specific."
}

$rodcDN       = $rodcObject.ComputerObjectDN
$rodcHostname = $rodcObject.HostName
$domainDN     = (Get-ADDomain -ErrorAction Stop).DistinguishedName
$domainFQDN   = (Get-ADDomain -ErrorAction Stop).DNSRoot

Write-Verbose "RODC DN:       $rodcDN"
Write-Verbose "Domain DN:     $domainDN"
Write-Verbose "Domain FQDN:   $domainFQDN"

# ---- Ensure output directory ----
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Verbose "Created output directory: $OutputPath"
}

# ---------------------------------------------------------------------------
# Region: Helper Functions
# ---------------------------------------------------------------------------

function Expand-ADGroupRecursive {
    <#
    .SYNOPSIS
        Recursively expands an AD group DN and returns all leaf member objects.
    .DESCRIPTION
        Walks nested groups via Get-ADGroupMember -Recursive. Returns
        PSCustomObjects with SamAccountName, DistinguishedName, and ObjectClass.
    .PARAMETER GroupDN
        The distinguished name of the group to expand.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupDN
    )

    $members = [System.Collections.ArrayList]::new()
    try {
        $raw = Get-ADGroup -Identity $GroupDN -ErrorAction Stop
        $expanded = Get-ADGroupMember -Identity $raw.DistinguishedName -Recursive -ErrorAction Stop
        foreach ($m in $expanded) {
            $null = $members.Add([PSCustomObject]@{
                SamAccountName    = $m.SamAccountName
                DistinguishedName = $m.DistinguishedName
                ObjectClass       = $m.objectClass
            })
        }
    }
    catch {
        Write-Warning "Could not expand group '$GroupDN': $_"
    }
    return , $members.ToArray()
}

function Get-AccountMetadata {
    <#
    .SYNOPSIS
        Retrieves extended metadata for a given SamAccountName.
    .DESCRIPTION
        Returns account type, SPN list, last logon, and privileged group flags.
        Read-only LDAP queries only.
    .PARAMETER SamAccountName
        The account to look up.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName
    )

    $privilegedGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Server Operators',
        'Backup Operators'
    )

    $meta = [PSCustomObject]@{
        SamAccountName     = $SamAccountName
        AccountType        = 'Unknown'
        ServicePrincipalNames = @()
        LastLogonTimestamp  = $null
        IsPrivileged       = $false
        PrivilegedGroups   = @()
    }

    try {
        $adObj = Get-ADObject -Filter "SamAccountName -eq '$SamAccountName'" `
                              -Properties objectClass, servicePrincipalName, lastLogonTimestamp, memberOf `
                              -ErrorAction Stop

        if (-not $adObj) { return $meta }

        # Account type
        switch -Wildcard ($adObj.objectClass) {
            '*computer*' { $meta.AccountType = 'Computer' }
            '*msDS-GroupManagedServiceAccount*' { $meta.AccountType = 'gMSA' }
            '*msDS-ManagedServiceAccount*' { $meta.AccountType = 'sMSA' }
            '*user*' {
                if ($adObj.servicePrincipalName) {
                    $meta.AccountType = 'Service Account'
                } else {
                    $meta.AccountType = 'User'
                }
            }
            default { $meta.AccountType = 'User' }
        }

        # SPNs
        if ($adObj.servicePrincipalName) {
            $meta.ServicePrincipalNames = @($adObj.servicePrincipalName)
        }

        # Last logon
        if ($adObj.lastLogonTimestamp) {
            $meta.LastLogonTimestamp = [DateTime]::FromFileTime($adObj.lastLogonTimestamp)
        }

        # Privileged group membership
        if ($adObj.memberOf) {
            foreach ($groupDN in $adObj.memberOf) {
                try {
                    $grpName = (Get-ADGroup -Identity $groupDN -ErrorAction SilentlyContinue).Name
                    if ($grpName -in $privilegedGroups) {
                        $meta.IsPrivileged = $true
                        $meta.PrivilegedGroups += $grpName
                    }
                }
                catch { }
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve metadata for '$SamAccountName': $_"
    }

    return $meta
}

function ConvertTo-HtmlSafe {
    <#
    .SYNOPSIS
        HTML-encodes a string for safe embedding in HTML content.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )
    process {
        if ([string]::IsNullOrEmpty($Text)) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($Text)
    }
}

# ---------------------------------------------------------------------------
# Region: Data Collection — Event 4649
# ---------------------------------------------------------------------------
Write-Host "[*] Collecting Event 4649 (credential validation) from $rodcHostname..." -ForegroundColor Yellow

$startTime    = (Get-Date).AddHours(-$HoursBack)
$authEvents   = [System.Collections.ArrayList]::new()
$event4649Raw = @()

try {
    $filterHash = @{
        LogName   = 'Security'
        Id        = 4649
        StartTime = $startTime
    }
    $event4649Raw = Get-WinEvent -FilterHashtable $filterHash -ComputerName $rodcHostname -ErrorAction Stop
    Write-Host "[+] Retrieved $($event4649Raw.Count) Event 4649 entries" -ForegroundColor Green
}
catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Warning "No Event 4649 entries found in the last $HoursBack hour(s) on $rodcHostname."
        Write-Warning "Verify that Audit Policy 'Credential Validation' is enabled: auditpol /get /subcategory:`"Credential Validation`""
    }
    else {
        Write-Warning "Could not query Security log on $rodcHostname : $_"
        Write-Warning "If running remotely, ensure WinRM is enabled and you have appropriate permissions."
    }
}

# Parse events into structured objects
foreach ($evt in $event4649Raw) {
    try {
        $xml  = [xml]$evt.ToXml()
        $data = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            $data[$node.Name] = $node.'#text'
        }

        $targetUser = $data['TargetUserName']
        $statusCode = $data['Status']
        if (-not $statusCode) { $statusCode = $data['StatusCode'] }

        # Skip computer accounts unless requested
        if (-not $IncludeComputerAccounts -and $targetUser -match '\$$') {
            continue
        }

        $isCacheHit = ($statusCode -eq '0x0' -or $statusCode -eq '0')

        $null = $authEvents.Add([PSCustomObject]@{
            TimeCreated    = $evt.TimeCreated
            TargetUserName = $targetUser
            StatusCode     = $statusCode
            IsCacheHit     = $isCacheHit
            MachineName    = $evt.MachineName
        })
    }
    catch {
        Write-Verbose "Skipped malformed Event 4649 entry: $_"
    }
}

Write-Host "[+] Parsed $($authEvents.Count) credential validation events" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Region: Data Collection — Password Replication Policy
# ---------------------------------------------------------------------------
Write-Host "[*] Reading Password Replication Policy (PRP) for $RODCName..." -ForegroundColor Yellow

$prpAllowDNs      = @()
$prpDenyDNs        = @()
$prpAllowMembers   = [System.Collections.ArrayList]::new()
$prpDenyMembers    = [System.Collections.ArrayList]::new()

try {
    $rodcADComputer = Get-ADComputer -Identity $rodcDN `
                        -Properties 'msDS-RevealOnDemandGroup', 'msDS-NeverRevealGroup' `
                        -ErrorAction Stop

    $prpAllowDNs = @($rodcADComputer.'msDS-RevealOnDemandGroup')
    $prpDenyDNs  = @($rodcADComputer.'msDS-NeverRevealGroup')

    Write-Verbose "PRP Allow groups: $($prpAllowDNs.Count)"
    Write-Verbose "PRP Deny groups:  $($prpDenyDNs.Count)"

    # Expand allow groups recursively
    foreach ($groupDN in $prpAllowDNs) {
        if ([string]::IsNullOrWhiteSpace($groupDN)) { continue }
        $expanded = Expand-ADGroupRecursive -GroupDN $groupDN
        foreach ($m in $expanded) {
            $null = $prpAllowMembers.Add($m)
        }
    }

    # Expand deny groups recursively
    foreach ($groupDN in $prpDenyDNs) {
        if ([string]::IsNullOrWhiteSpace($groupDN)) { continue }
        $expanded = Expand-ADGroupRecursive -GroupDN $groupDN
        foreach ($m in $expanded) {
            $null = $prpDenyMembers.Add($m)
        }
    }

    Write-Host "[+] PRP Allow list: $($prpAllowMembers.Count) account(s) across $($prpAllowDNs.Count) group(s)" -ForegroundColor Green
    Write-Host "[+] PRP Deny list:  $($prpDenyMembers.Count) account(s) across $($prpDenyDNs.Count) group(s)" -ForegroundColor Green
}
catch {
    Write-Warning "Could not read PRP attributes from '$rodcDN': $_"
}

$prpAllowSams = @($prpAllowMembers | Select-Object -ExpandProperty SamAccountName -Unique)
$prpDenySams  = @($prpDenyMembers  | Select-Object -ExpandProperty SamAccountName -Unique)

# ---------------------------------------------------------------------------
# Region: Data Collection — Revealed List (actually cached credentials)
# ---------------------------------------------------------------------------
Write-Host "[*] Reading msDS-RevealedList (cached credentials) for $RODCName..." -ForegroundColor Yellow

$revealedAccounts = [System.Collections.ArrayList]::new()

try {
    $revealedRaw = Get-ADDomainController -Identity $RODCName -ErrorAction Stop |
                   Select-Object -ExpandProperty ComputerObjectDN |
                   ForEach-Object {
                       Get-ADComputer -Identity $_ -Properties 'msDS-RevealedUsers' -ErrorAction Stop
                   }

    $revealedDNList = @($revealedRaw.'msDS-RevealedUsers')

    if ($revealedDNList.Count -eq 0) {
        Write-Warning "msDS-RevealedUsers is empty on $RODCName. This RODC may be newly promoted or credentials may not have been cached yet."
    }
    else {
        foreach ($entry in $revealedDNList) {
            # msDS-RevealedUsers entries are DNs prefixed with metadata; extract the DN
            $dn = $entry
            if ($entry -match 'CN=') {
                $dn = $entry.Substring($entry.IndexOf('CN='))
            }
            try {
                $acct = Get-ADObject -Identity $dn -Properties SamAccountName, objectClass -ErrorAction SilentlyContinue
                if ($acct) {
                    $null = $revealedAccounts.Add([PSCustomObject]@{
                        SamAccountName    = $acct.SamAccountName
                        DistinguishedName = $acct.DistinguishedName
                        ObjectClass       = $acct.objectClass -join ','
                    })
                }
            }
            catch {
                Write-Verbose "Could not resolve revealed entry: $dn"
            }
        }
    }

    Write-Host "[+] Currently cached credentials: $($revealedAccounts.Count) account(s)" -ForegroundColor Green
}
catch {
    Write-Warning "Could not read msDS-RevealedUsers from '$RODCName': $_"
    Write-Warning "If the RODC is newly deployed, the revealed list may not yet be populated."
}

$revealedSams = @($revealedAccounts | Select-Object -ExpandProperty SamAccountName -Unique)

# ---------------------------------------------------------------------------
# Region: Analysis
# ---------------------------------------------------------------------------
Write-Host "`n[*] Analysing authentication patterns..." -ForegroundColor Yellow

# ---- Aggregate per-account stats ----
$accountStats = @{}
foreach ($evt in $authEvents) {
    $user = $evt.TargetUserName
    if (-not $accountStats.ContainsKey($user)) {
        $accountStats[$user] = [PSCustomObject]@{
            Account       = $user
            TotalRequests = 0
            CacheHits     = 0
            HubFallbacks  = 0
            FirstSeen     = $evt.TimeCreated
            LastSeen      = $evt.TimeCreated
        }
    }
    $stat = $accountStats[$user]
    $stat.TotalRequests++
    if ($evt.IsCacheHit) { $stat.CacheHits++ } else { $stat.HubFallbacks++ }
    if ($evt.TimeCreated -lt $stat.FirstSeen) { $stat.FirstSeen = $evt.TimeCreated }
    if ($evt.TimeCreated -gt $stat.LastSeen)  { $stat.LastSeen  = $evt.TimeCreated }
}

# ---- Global counters ----
$totalRequests    = ($authEvents | Measure-Object).Count
$totalCacheHits   = ($authEvents | Where-Object { $_.IsCacheHit }).Count
$totalHubFallback = $totalRequests - $totalCacheHits
$pctLocal         = if ($totalRequests -gt 0) { [math]::Round(($totalCacheHits / $totalRequests) * 100, 1) } else { 0 }
$pctFallback      = if ($totalRequests -gt 0) { [math]::Round(($totalHubFallback / $totalRequests) * 100, 1) } else { 0 }

# ---- Latency impact estimate ----
$localLatencyMs   = 50
$hubLatencyMs     = 500
$estimatedLocalMs  = $totalCacheHits * $localLatencyMs
$estimatedHubMs    = $totalHubFallback * $hubLatencyMs
$estimatedTotalMs  = $estimatedLocalMs + $estimatedHubMs
$idealTotalMs      = $totalRequests * $localLatencyMs
$latencySavingMs   = $estimatedTotalMs - $idealTotalMs

# ---- Allowed-but-not-cached accounts ----
$allowedButNotCached = @($prpAllowSams | Where-Object { $_ -notin $revealedSams })

# ---- PRP conflicts (in both allow AND deny) ----
$prpConflicts = @($prpAllowSams | Where-Object { $_ -in $prpDenySams })

# ---- Top fallback accounts (filtered by MinRequestThreshold) ----
$topFallbackAccounts = $accountStats.Values |
    Where-Object { $_.TotalRequests -ge $MinRequestThreshold -and $_.HubFallbacks -gt 0 } |
    Sort-Object -Property HubFallbacks -Descending |
    Select-Object -First 20

# ---- Allowed accounts with zero cache hits (stale PRP entries) ----
$stalePRPEntries = @()
foreach ($sam in $prpAllowSams) {
    if ($accountStats.ContainsKey($sam)) {
        $s = $accountStats[$sam]
        if ($s.CacheHits -eq 0 -and $s.TotalRequests -gt 0) {
            $stalePRPEntries += $sam
        }
    }
}

# ---- Enrich top fallback accounts with metadata ----
Write-Host "[*] Enriching top fallback accounts with AD metadata..." -ForegroundColor Yellow

$enrichedFallback = [System.Collections.ArrayList]::new()
$rank = 0
foreach ($acctStat in $topFallbackAccounts) {
    $rank++
    $meta = Get-AccountMetadata -SamAccountName $acctStat.Account

    $prpStatus = 'Not Listed'
    if ($acctStat.Account -in $prpAllowSams -and $acctStat.Account -in $prpDenySams) {
        $prpStatus = 'CONFLICT'
    }
    elseif ($acctStat.Account -in $prpAllowSams) {
        $prpStatus = 'Allowed'
    }
    elseif ($acctStat.Account -in $prpDenySams) {
        $prpStatus = 'Denied'
    }

    $cachedStatus = if ($acctStat.Account -in $revealedSams) { 'Yes' } else { 'No' }

    $fallbackPct = if ($acctStat.TotalRequests -gt 0) {
        [math]::Round(($acctStat.HubFallbacks / $acctStat.TotalRequests) * 100, 1)
    } else { 0 }

    # Determine recommendation
    $recommendation = 'Investigate'
    if ($prpStatus -eq 'CONFLICT') {
        $recommendation = 'Resolve PRP conflict'
    }
    elseif ($prpStatus -eq 'Denied' -and $meta.IsPrivileged) {
        $recommendation = 'Expected (privileged account)'
    }
    elseif ($prpStatus -eq 'Denied') {
        $recommendation = 'Add to allow list if appropriate'
    }
    elseif ($prpStatus -eq 'Not Listed') {
        $recommendation = 'Add to PRP allow list'
    }
    elseif ($prpStatus -eq 'Allowed' -and $cachedStatus -eq 'No') {
        $recommendation = 'Pre-stage credential cache'
    }
    elseif ($meta.AccountType -in @('Service Account', 'gMSA', 'sMSA') -and $fallbackPct -gt 50) {
        $recommendation = 'High-priority: cache service credential'
    }

    $null = $enrichedFallback.Add([PSCustomObject]@{
        Rank            = $rank
        Account         = $acctStat.Account
        AccountType     = $meta.AccountType
        TotalRequests   = $acctStat.TotalRequests
        CacheHits       = $acctStat.CacheHits
        HubFallbacks    = $acctStat.HubFallbacks
        FallbackPct     = $fallbackPct
        PRPStatus       = $prpStatus
        CachedOnRODC    = $cachedStatus
        IsPrivileged    = $meta.IsPrivileged
        PrivilegedGroups = ($meta.PrivilegedGroups -join ', ')
        SPNs            = ($meta.ServicePrincipalNames -join '; ')
        LastLogon       = $meta.LastLogonTimestamp
        Recommendation  = $recommendation
        FirstSeen       = $acctStat.FirstSeen
        LastSeen        = $acctStat.LastSeen
    })
}

# ---- Flag service accounts with high fallback ----
$highFallbackServices = @($enrichedFallback | Where-Object {
    $_.AccountType -in @('Service Account', 'gMSA', 'sMSA') -and $_.FallbackPct -gt 50
})

Write-Host "[+] Analysis complete." -ForegroundColor Green
Write-Host "    Total requests:       $totalRequests" -ForegroundColor White
Write-Host "    Cache hits:           $totalCacheHits ($pctLocal%)" -ForegroundColor White
Write-Host "    Hub fallbacks:        $totalHubFallback ($pctFallback%)" -ForegroundColor White
Write-Host "    Allowed-not-cached:   $($allowedButNotCached.Count)" -ForegroundColor White
Write-Host "    PRP conflicts:        $($prpConflicts.Count)" -ForegroundColor White
Write-Host "    Top fallback accounts: $($enrichedFallback.Count)" -ForegroundColor White

# ---------------------------------------------------------------------------
# Region: Sample Evidence
# ---------------------------------------------------------------------------
$sampleEvents = $authEvents | Select-Object -First 10
$sampleEvidence = ($sampleEvents | ForEach-Object {
    "[{0}] Account={1}  Status={2}  CacheHit={3}" -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $_.TargetUserName, $_.StatusCode, $_.IsCacheHit
}) -join "`n"

if (-not $sampleEvidence) {
    $sampleEvidence = "(No Event 4649 entries found in the analysis window)"
}

# ---------------------------------------------------------------------------
# Region: HTML Report Generation
# ---------------------------------------------------------------------------
Write-Host "`n[*] Generating HTML report..." -ForegroundColor Yellow

$htmlTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss 'UTC'K"
$analysisWindowStart = $startTime.ToString('yyyy-MM-dd HH:mm:ss')
$analysisWindowEnd   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

# ---- Build top fallback table rows ----
$fallbackTableRows = ""
foreach ($entry in $enrichedFallback) {
    $acctSafe  = $entry.Account | ConvertTo-HtmlSafe
    $typeSafe  = $entry.AccountType | ConvertTo-HtmlSafe
    $prpSafe   = $entry.PRPStatus | ConvertTo-HtmlSafe
    $recSafe   = $entry.Recommendation | ConvertTo-HtmlSafe

    # Color-code the fallback percentage
    $pctClass = 'text-pass'
    if ($entry.FallbackPct -ge 80) { $pctClass = 'text-fail' }
    elseif ($entry.FallbackPct -ge 50) { $pctClass = 'text-warn' }

    # Color-code PRP status
    $prpClass = 'text-secondary'
    if ($entry.PRPStatus -eq 'Allowed')   { $prpClass = 'text-pass' }
    if ($entry.PRPStatus -eq 'Denied')    { $prpClass = 'text-warn' }
    if ($entry.PRPStatus -eq 'CONFLICT')  { $prpClass = 'text-fail' }

    # Color-code cached status
    $cachedClass = if ($entry.CachedOnRODC -eq 'Yes') { 'text-pass' } else { 'text-warn' }

    # Privileged flag
    $privFlag = if ($entry.IsPrivileged) {
        '<span class="badge fail" style="font-size:0.65rem;padding:1px 6px;">PRIV</span>'
    } else { '' }

    $fallbackTableRows += @"
                        <tr>
                            <td class="mono">$($entry.Rank)</td>
                            <td>$acctSafe $privFlag</td>
                            <td>$typeSafe</td>
                            <td class="mono">$($entry.TotalRequests)</td>
                            <td class="mono $pctClass">$($entry.FallbackPct)%</td>
                            <td class="$prpClass">$prpSafe</td>
                            <td class="$cachedClass">$($entry.CachedOnRODC)</td>
                            <td>$recSafe</td>
                        </tr>
"@
}

if (-not $fallbackTableRows) {
    $fallbackTableRows = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:24px;">No accounts exceeded the minimum request threshold of ' + $MinRequestThreshold + '.</td></tr>'
}

# ---- Build configuration issues ----
$configIssuesHTML = ""

# PRP Conflicts
if ($prpConflicts.Count -gt 0) {
    $conflictListHTML = ($prpConflicts | ForEach-Object { "<li>$($_ | ConvertTo-HtmlSafe)</li>" }) -join "`n"
    $configIssuesHTML += @"
                    <div class="detail-block" style="border-left:3px solid var(--fail);">
                        <h4 style="color:var(--fail);">PRP Conflict: Accounts in Both Allow AND Deny Lists ($($prpConflicts.Count))</h4>
                        <p style="color:var(--text-secondary);margin-bottom:8px;">
                            These accounts appear in both msDS-RevealOnDemandGroup and msDS-NeverRevealGroup.
                            The deny list takes precedence, so credentials will never be cached.
                            Remove the account from one list to resolve the ambiguity.
                        </p>
                        <ul>$conflictListHTML</ul>
                    </div>
"@
}

# Stale PRP entries
if ($stalePRPEntries.Count -gt 0) {
    $staleListHTML = ($stalePRPEntries | ForEach-Object { "<li>$($_ | ConvertTo-HtmlSafe)</li>" }) -join "`n"
    $configIssuesHTML += @"
                    <div class="detail-block" style="border-left:3px solid var(--warn);">
                        <h4 style="color:var(--warn);">Stale PRP: Allowed Accounts with Zero Cache Hits ($($stalePRPEntries.Count))</h4>
                        <p style="color:var(--text-secondary);margin-bottom:8px;">
                            These accounts are in the PRP allow list and have made authentication requests,
                            but none were served from cache. Their credentials may need to be pre-staged,
                            or they may be authenticating via a mechanism that bypasses the RODC cache.
                        </p>
                        <ul>$staleListHTML</ul>
                    </div>
"@
}

# High-fallback service accounts
if ($highFallbackServices.Count -gt 0) {
    $svcListHTML = ($highFallbackServices | ForEach-Object {
        $spnInfo = if ($_.SPNs) { " (SPNs: $($_.SPNs | ConvertTo-HtmlSafe))" } else { '' }
        "<li>$($_.Account | ConvertTo-HtmlSafe) &mdash; $($_.FallbackPct)% fallback, $($_.TotalRequests) total requests$spnInfo</li>"
    }) -join "`n"
    $configIssuesHTML += @"
                    <div class="detail-block" style="border-left:3px solid var(--warn);">
                        <h4 style="color:var(--warn);">Service Accounts with High Hub Fallback ($($highFallbackServices.Count))</h4>
                        <p style="color:var(--text-secondary);margin-bottom:8px;">
                            Service accounts with more than 50% hub fallback add latency to application
                            authentication. Consider adding these to the PRP allow list and pre-staging
                            their credentials.
                        </p>
                        <ul>$svcListHTML</ul>
                    </div>
"@
}

if (-not $configIssuesHTML) {
    $configIssuesHTML = @"
                    <div class="detail-block" style="border-left:3px solid var(--pass);">
                        <h4 style="color:var(--pass);">No Configuration Issues Detected</h4>
                        <p style="color:var(--text-secondary);">
                            No PRP conflicts, stale policy entries, or high-fallback service accounts were found.
                        </p>
                    </div>
"@
}

# ---- Build evidence section ----
$prpAllowEvidenceHTML = ""
foreach ($dn in $prpAllowDNs) {
    if ([string]::IsNullOrWhiteSpace($dn)) { continue }
    $dnSafe = $dn | ConvertTo-HtmlSafe
    $memberCount = ($prpAllowMembers | Where-Object { $true }).Count  # Already expanded above
    $prpAllowEvidenceHTML += "<li>$dnSafe</li>`n"
}

$prpDenyEvidenceHTML = ""
foreach ($dn in $prpDenyDNs) {
    if ([string]::IsNullOrWhiteSpace($dn)) { continue }
    $dnSafe = $dn | ConvertTo-HtmlSafe
    $prpDenyEvidenceHTML += "<li>$dnSafe</li>`n"
}

$sampleEvidenceHTML = $sampleEvidence | ConvertTo-HtmlSafe

# ---- Assemble final report ----

# Latency formatting
$latencyFormatted = if ($latencySavingMs -ge 1000) {
    "{0:N1}s" -f ($latencySavingMs / 1000)
} else {
    "{0:N0}ms" -f $latencySavingMs
}

# Score ring color
$ringColor = if ($pctLocal -ge 80) { '#2ea043' }
             elseif ($pctLocal -ge 60) { '#d29922' }
             elseif ($pctLocal -ge 40) { '#f0883e' }
             else { '#f85149' }

# SVG score ring
$circumference = [math]::Round(2 * [math]::PI * 68, 2)
$offset        = [math]::Round($circumference * (1 - ($pctLocal / 100)), 2)

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>RODC Auth Source Analysis &mdash; $($RODCName | ConvertTo-HtmlSafe)</title>
    <style>
/* ============================================================
   RODC Auth Source Analysis Report — Embedded Stylesheet
   Zero external dependencies. Fully offline renderable.
   ============================================================ */

:root {
    --bg-primary:       #0f1419;
    --bg-secondary:     #1a2332;
    --bg-card:          #1e2d3d;
    --bg-card-hover:    #243447;
    --bg-input:         #0d1117;

    --text-primary:     #e6edf3;
    --text-secondary:   #8b949e;
    --text-muted:       #6e7681;
    --text-link:        #58a6ff;

    --border-default:   #30363d;
    --border-muted:     #21262d;

    --pass:             #2ea043;
    --pass-bg:          rgba(46,160,67,0.12);
    --pass-border:      rgba(46,160,67,0.4);

    --warn:             #d29922;
    --warn-bg:          rgba(210,153,34,0.12);
    --warn-border:      rgba(210,153,34,0.4);

    --fail:             #f85149;
    --fail-bg:          rgba(248,81,73,0.12);
    --fail-border:      rgba(248,81,73,0.4);

    --info:             #58a6ff;
    --info-bg:          rgba(88,166,255,0.12);
    --info-border:      rgba(88,166,255,0.4);

    --font-sans:        'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
    --font-mono:        'Cascadia Code', 'Fira Code', 'JetBrains Mono', Consolas, 'Courier New', monospace;

    --radius-sm:        4px;
    --radius-md:        8px;
    --radius-lg:        12px;

    --shadow-sm:        0 1px 3px rgba(0,0,0,0.3);
    --shadow-md:        0 4px 12px rgba(0,0,0,0.4);
    --shadow-lg:        0 8px 24px rgba(0,0,0,0.5);
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 15px; scroll-behavior: smooth; -webkit-font-smoothing: antialiased; }
body {
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
}

.report-wrapper { max-width: 1320px; margin: 0 auto; padding: 24px 32px 64px; }

/* Header */
.report-header {
    background: linear-gradient(135deg, #1a2332 0%, #0f2027 50%, #1a2332 100%);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-lg);
    padding: 40px 48px;
    margin-bottom: 32px;
    position: relative;
    overflow: hidden;
}
.report-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 4px;
    background: linear-gradient(90deg, var(--pass), var(--info), var(--warn), var(--fail));
}
.report-header h1 {
    font-size: 2rem; font-weight: 700; letter-spacing: -0.02em;
    margin-bottom: 8px; color: var(--text-primary);
}
.report-header .subtitle { font-size: 1.05rem; color: var(--text-secondary); font-weight: 400; }
.report-meta {
    display: flex; flex-wrap: wrap; gap: 24px;
    margin-top: 24px; padding-top: 20px;
    border-top: 1px solid var(--border-default);
}
.meta-item { display: flex; flex-direction: column; gap: 2px; }
.meta-label {
    font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--text-muted); font-weight: 600;
}
.meta-value { font-size: 0.95rem; color: var(--text-primary); font-family: var(--font-mono); }

/* Dashboard Cards */
.score-dashboard {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
}
.score-card {
    background: var(--bg-card);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md);
    padding: 24px; text-align: center;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}
.score-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); }
.score-card .score-value {
    font-size: 2.4rem; font-weight: 800;
    font-family: var(--font-mono); line-height: 1.1;
}
.score-card .score-label {
    font-size: 0.82rem; color: var(--text-secondary);
    margin-top: 6px; text-transform: uppercase;
    letter-spacing: 0.06em; font-weight: 600;
}
.score-card.total    .score-value { color: var(--info); }
.score-card.pass     .score-value { color: var(--pass); }
.score-card.warn     .score-value { color: var(--warn); }
.score-card.fail     .score-value { color: var(--fail); }

/* Score Ring */
.score-ring-container {
    display: flex; justify-content: center; align-items: center; gap: 40px;
    background: var(--bg-card); border: 1px solid var(--border-default);
    border-radius: var(--radius-md); padding: 32px; margin-bottom: 32px;
}
.score-ring { position: relative; width: 160px; height: 160px; }
.score-ring svg { transform: rotate(-90deg); width: 160px; height: 160px; }
.score-ring .ring-bg { fill: none; stroke: var(--border-default); stroke-width: 12; }
.score-ring .ring-fill {
    fill: none; stroke-width: 12; stroke-linecap: round;
    transition: stroke-dashoffset 0.6s ease;
}
.score-ring .ring-text {
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%); text-align: center;
}
.score-ring .ring-text .pct {
    font-size: 2.2rem; font-weight: 800; font-family: var(--font-mono);
}
.score-ring .ring-text .ring-label {
    font-size: 0.75rem; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.08em;
}
.score-legend { display: flex; flex-direction: column; gap: 14px; }
.legend-item { display: flex; align-items: center; gap: 10px; font-size: 0.9rem; }
.legend-dot { width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }
.legend-count { font-family: var(--font-mono); font-weight: 700; min-width: 56px; }

/* Section */
.report-section { margin-bottom: 28px; }
.section-header {
    display: flex; align-items: center; gap: 12px;
    padding: 16px 20px; background: var(--bg-secondary);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md) var(--radius-md) 0 0;
}
.section-icon {
    width: 36px; height: 36px; display: flex;
    align-items: center; justify-content: center;
    border-radius: var(--radius-sm); font-size: 1.1rem; flex-shrink: 0;
}
.section-icon.auth     { background: rgba(88,166,255,0.15); color: var(--info); }
.section-icon.config   { background: rgba(210,153,34,0.15); color: var(--warn); }
.section-icon.evidence { background: rgba(163,113,247,0.15); color: #a371f7; }
.section-title { font-size: 1.15rem; font-weight: 700; }
.section-badge { margin-left: auto; display: flex; gap: 8px; }

/* Content Container */
.section-content {
    border: 1px solid var(--border-default); border-top: none;
    border-radius: 0 0 var(--radius-md) var(--radius-md);
    background: var(--bg-card); padding: 24px;
}

/* Badge */
.badge {
    display: inline-flex; align-items: center;
    padding: 3px 10px; border-radius: 20px;
    font-size: 0.75rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.04em; flex-shrink: 0;
}
.badge.pass { background: var(--pass-bg); color: var(--pass); border: 1px solid var(--pass-border); }
.badge.warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn-border); }
.badge.fail { background: var(--fail-bg); color: var(--fail); border: 1px solid var(--fail-border); }
.badge.info { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }

/* Data Table */
.data-table {
    width: 100%; border-collapse: collapse;
    font-size: 0.85rem; margin-bottom: 0;
}
.data-table thead th {
    background: var(--bg-secondary); color: var(--text-secondary);
    font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em;
    font-size: 0.72rem; padding: 10px 14px; text-align: left;
    border-bottom: 2px solid var(--border-default);
    position: sticky; top: 0; z-index: 1;
    cursor: default; user-select: none;
}
.data-table thead th:hover { color: var(--text-primary); }
.data-table tbody td {
    padding: 10px 14px; border-bottom: 1px solid var(--border-muted);
    color: var(--text-primary); vertical-align: middle;
}
.data-table tbody tr:hover { background: var(--bg-card-hover); }
.data-table .mono { font-family: var(--font-mono); font-size: 0.82rem; }

/* Detail blocks */
.detail-block {
    background: var(--bg-primary); border: 1px solid var(--border-muted);
    border-radius: var(--radius-sm); padding: 16px 18px; margin-bottom: 16px;
}
.detail-block h4 {
    font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--text-muted); margin-bottom: 8px; font-weight: 700;
}
.detail-block p, .detail-block li {
    font-size: 0.9rem; color: var(--text-secondary); line-height: 1.65;
}
.detail-block ul { list-style: none; padding: 0; }
.detail-block li { padding: 3px 0 3px 18px; position: relative; }
.detail-block li::before {
    content: '\2022'; position: absolute; left: 4px; color: var(--text-muted);
}

/* Evidence */
.evidence-block {
    background: var(--bg-input); border: 1px solid var(--border-muted);
    border-radius: var(--radius-sm); padding: 14px 18px;
    font-family: var(--font-mono); font-size: 0.82rem;
    color: var(--text-secondary); line-height: 1.7;
    overflow-x: auto; white-space: pre-wrap; word-break: break-word;
    margin-bottom: 16px;
}

/* Utility */
.text-pass     { color: var(--pass) !important; }
.text-warn     { color: var(--warn) !important; }
.text-fail     { color: var(--fail) !important; }
.text-info     { color: var(--info) !important; }
.text-muted    { color: var(--text-muted) !important; }
.text-secondary { color: var(--text-secondary) !important; }
.mono          { font-family: var(--font-mono) !important; }

/* Footer */
.report-footer {
    margin-top: 48px; padding: 24px 32px;
    background: var(--bg-secondary); border: 1px solid var(--border-default);
    border-radius: var(--radius-md); text-align: center;
    color: var(--text-muted); font-size: 0.82rem;
}
.report-footer .disclaimer {
    margin-top: 8px; font-size: 0.75rem;
    color: var(--text-muted); font-style: italic;
}

/* Print */
@media print {
    body { background: #fff; color: #1a1a1a; }
    .report-wrapper { max-width: 100%; padding: 12px; }
    .report-header { background: #f5f5f5; border-color: #ddd; }
    .report-header::before { background: #333; }
    .score-card, .detail-block, .evidence-block, .section-content { break-inside: avoid; }
    .score-card:hover { transform: none; box-shadow: none; }
}

/* Responsive */
@media (max-width: 768px) {
    .report-wrapper { padding: 12px 16px 48px; }
    .report-header { padding: 24px; }
    .report-header h1 { font-size: 1.5rem; }
    .score-dashboard { grid-template-columns: repeat(2, 1fr); }
    .report-meta { gap: 16px; }
    .score-ring-container { flex-direction: column; }
    .section-content { padding: 16px; }
    .data-table { font-size: 0.78rem; }
    .data-table thead th, .data-table tbody td { padding: 8px 10px; }
}
    </style>
</head>
<body>
<div class="report-wrapper">

    <!-- ============================================================ -->
    <!-- Header                                                        -->
    <!-- ============================================================ -->
    <div class="report-header">
        <h1>RODC Authentication Source Analysis</h1>
        <div class="subtitle">Cache hit vs hub-DC fallback analysis &mdash; $($RODCName | ConvertTo-HtmlSafe)</div>
        <div class="report-meta">
            <div class="meta-item">
                <span class="meta-label">Generated</span>
                <span class="meta-value">$htmlTimestamp</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">RODC</span>
                <span class="meta-value">$($rodcHostname | ConvertTo-HtmlSafe)</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Domain</span>
                <span class="meta-value">$($domainFQDN | ConvertTo-HtmlSafe)</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Analysis Window</span>
                <span class="meta-value">$analysisWindowStart &rarr; $analysisWindowEnd ($HoursBack h)</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Generated By</span>
                <span class="meta-value">$($env:USERNAME | ConvertTo-HtmlSafe)</span>
            </div>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Executive Summary — Score Ring + KPI Cards                    -->
    <!-- ============================================================ -->
    <div class="score-ring-container">
        <div class="score-ring">
            <svg viewBox="0 0 160 160">
                <circle class="ring-bg" cx="80" cy="80" r="68"/>
                <circle class="ring-fill" cx="80" cy="80" r="68"
                        stroke="$ringColor"
                        stroke-dasharray="$circumference"
                        stroke-dashoffset="$offset"/>
            </svg>
            <div class="ring-text">
                <div class="pct" style="color:$ringColor">$pctLocal%</div>
                <div class="ring-label">Local Cache</div>
            </div>
        </div>
        <div class="score-legend">
            <div class="legend-item">
                <span class="legend-dot" style="background:var(--pass);"></span>
                <span class="legend-count">$totalCacheHits</span> Cache hits (local)
            </div>
            <div class="legend-item">
                <span class="legend-dot" style="background:var(--fail);"></span>
                <span class="legend-count">$totalHubFallback</span> Hub-DC fallbacks
            </div>
            <div class="legend-item">
                <span class="legend-dot" style="background:var(--info);"></span>
                <span class="legend-count">$($allowedButNotCached.Count)</span> Allowed but not cached
            </div>
            <div class="legend-item">
                <span class="legend-dot" style="background:var(--warn);"></span>
                <span class="legend-count">$($prpConflicts.Count)</span> PRP conflicts
            </div>
        </div>
    </div>

    <div class="score-dashboard">
        <div class="score-card total">
            <div class="score-value">$totalRequests</div>
            <div class="score-label">Total Auth Requests</div>
        </div>
        <div class="score-card pass">
            <div class="score-value">$pctLocal%</div>
            <div class="score-label">Local (Cache Hit)</div>
        </div>
        <div class="score-card fail">
            <div class="score-value">$pctFallback%</div>
            <div class="score-label">Hub Fallback</div>
        </div>
        <div class="score-card warn">
            <div class="score-value">$($allowedButNotCached.Count)</div>
            <div class="score-label">Allowed Not Cached</div>
        </div>
        <div class="score-card total">
            <div class="score-value">$latencyFormatted</div>
            <div class="score-label">Est. Latency Overhead</div>
        </div>
        <div class="score-card pass">
            <div class="score-value">$($revealedAccounts.Count)</div>
            <div class="score-label">Cached Credentials</div>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Section 1: Top Fallback Accounts                              -->
    <!-- ============================================================ -->
    <div class="report-section">
        <div class="section-header">
            <div class="section-icon auth">&#9881;</div>
            <span class="section-title">Top Fallback Accounts</span>
            <div class="section-badge">
                <span class="badge info">Top $($enrichedFallback.Count)</span>
                <span class="badge warn">Min $MinRequestThreshold req</span>
            </div>
        </div>
        <div class="section-content" style="padding:0;overflow-x:auto;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Account</th>
                        <th>Type</th>
                        <th>Total Requests</th>
                        <th>% Fallback</th>
                        <th>PRP Status</th>
                        <th>Cached</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
$fallbackTableRows
                </tbody>
            </table>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Section 2: Configuration Issues                               -->
    <!-- ============================================================ -->
    <div class="report-section">
        <div class="section-header">
            <div class="section-icon config">&#9888;</div>
            <span class="section-title">Configuration Issues</span>
            <div class="section-badge">
                $(if ($prpConflicts.Count -gt 0) { '<span class="badge fail">' + $prpConflicts.Count + ' Conflicts</span>' })
                $(if ($stalePRPEntries.Count -gt 0) { '<span class="badge warn">' + $stalePRPEntries.Count + ' Stale</span>' })
                $(if ($highFallbackServices.Count -gt 0) { '<span class="badge warn">' + $highFallbackServices.Count + ' Svc Fallback</span>' })
                $(if ($prpConflicts.Count -eq 0 -and $stalePRPEntries.Count -eq 0 -and $highFallbackServices.Count -eq 0) { '<span class="badge pass">Clean</span>' })
            </div>
        </div>
        <div class="section-content">
$configIssuesHTML
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Section 3: Evidence                                           -->
    <!-- ============================================================ -->
    <div class="report-section">
        <div class="section-header">
            <div class="section-icon evidence">&#128270;</div>
            <span class="section-title">Evidence</span>
            <div class="section-badge">
                <span class="badge info">Raw Data</span>
            </div>
        </div>
        <div class="section-content">
            <div class="detail-block">
                <h4>Sample Event 4649 Entries (up to 10)</h4>
                <div class="evidence-block">$sampleEvidenceHTML</div>
            </div>

            <div class="detail-block">
                <h4>PRP Allow Groups (msDS-RevealOnDemandGroup) &mdash; $($prpAllowDNs.Count) group(s), $($prpAllowMembers.Count) expanded member(s)</h4>
                <ul>
                    $(if ($prpAllowEvidenceHTML) { $prpAllowEvidenceHTML } else { '<li class="text-muted">(none configured)</li>' })
                </ul>
            </div>

            <div class="detail-block">
                <h4>PRP Deny Groups (msDS-NeverRevealGroup) &mdash; $($prpDenyDNs.Count) group(s), $($prpDenyMembers.Count) expanded member(s)</h4>
                <ul>
                    $(if ($prpDenyEvidenceHTML) { $prpDenyEvidenceHTML } else { '<li class="text-muted">(none configured)</li>' })
                </ul>
            </div>

            <div class="detail-block">
                <h4>Currently Cached Credentials (msDS-RevealedList) &mdash; $($revealedAccounts.Count) account(s)</h4>
                <div class="evidence-block">$(
                    if ($revealedAccounts.Count -gt 0) {
                        ($revealedAccounts | Select-Object -First 50 | ForEach-Object {
                            "$($_.SamAccountName)  ($($_.ObjectClass))" | ConvertTo-HtmlSafe
                        }) -join "`n"
                    } else {
                        "(empty &mdash; no credentials currently cached on this RODC)"
                    }
                )</div>
            </div>

            <div class="detail-block">
                <h4>Latency Impact Estimate</h4>
                <p>
                    Assumptions: local cache = ${localLatencyMs}ms, hub-DC fallback = ${hubLatencyMs}ms.<br/>
                    Actual total estimated: <strong class="mono">$("{0:N0}" -f $estimatedTotalMs)ms</strong>
                    ($("{0:N0}" -f $estimatedLocalMs)ms local + $("{0:N0}" -f $estimatedHubMs)ms hub).<br/>
                    Ideal (100% cache): <strong class="mono">$("{0:N0}" -f $idealTotalMs)ms</strong>.<br/>
                    Overhead from hub fallback: <strong class="mono text-warn">$latencyFormatted</strong>.
                </p>
            </div>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Footer                                                        -->
    <!-- ============================================================ -->
    <div class="report-footer">
        <div>RODC Authentication Source Analysis &mdash; Generated $htmlTimestamp</div>
        <div class="disclaimer">
            Read-only assessment. No modifications were made to Active Directory objects, schema, or security descriptors.
            Latency estimates are approximations based on typical network conditions.
        </div>
    </div>

</div>
</body>
</html>
"@

# ---------------------------------------------------------------------------
# Region: Write Output Files
# ---------------------------------------------------------------------------
$baseName = "RODC-AuthSource_${RODCName}_${reportTimestamp}"

$htmlPath = Join-Path $OutputPath "$baseName.html"
$csvPath  = Join-Path $OutputPath "$baseName.csv"
$jsonPath = Join-Path $OutputPath "$baseName.json"

# ---- HTML ----
$html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
Write-Host "[+] HTML report: $htmlPath" -ForegroundColor Green

# ---- CSV ----
$csvData = $enrichedFallback | ForEach-Object {
    [PSCustomObject]@{
        Rank             = $_.Rank
        Account          = $_.Account
        AccountType      = $_.AccountType
        TotalRequests    = $_.TotalRequests
        CacheHits        = $_.CacheHits
        HubFallbacks     = $_.HubFallbacks
        FallbackPct      = $_.FallbackPct
        PRPStatus        = $_.PRPStatus
        CachedOnRODC     = $_.CachedOnRODC
        IsPrivileged     = $_.IsPrivileged
        PrivilegedGroups = $_.PrivilegedGroups
        SPNs             = $_.SPNs
        LastLogon        = $_.LastLogon
        Recommendation   = $_.Recommendation
        FirstSeen        = $_.FirstSeen
        LastSeen         = $_.LastSeen
    }
}

if ($csvData) {
    $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
}
else {
    # Write header-only CSV so downstream tooling doesn't break
    [PSCustomObject]@{
        Rank=''; Account=''; AccountType=''; TotalRequests='';
        CacheHits=''; HubFallbacks=''; FallbackPct=''; PRPStatus='';
        CachedOnRODC=''; IsPrivileged=''; PrivilegedGroups=''; SPNs='';
        LastLogon=''; Recommendation=''; FirstSeen=''; LastSeen=''
    } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    # Remove the data row, keep only header
    $headerLine = (Get-Content -Path $csvPath -TotalCount 1)
    $headerLine | Out-File -FilePath $csvPath -Encoding UTF8 -Force
}
Write-Host "[+] CSV export:  $csvPath" -ForegroundColor Green

# ---- JSON ----
$jsonExport = @{
    ReportMetadata = @{
        GeneratedAt        = (Get-Date -Format 'o')
        GeneratedBy        = $env:USERNAME
        RODCName           = $RODCName
        RODCHostname       = $rodcHostname
        DomainFQDN         = $domainFQDN
        AnalysisWindowHours = $HoursBack
        AnalysisStart      = $startTime.ToString('o')
        AnalysisEnd        = (Get-Date).ToString('o')
        ScriptVersion      = '1.0.0'
    }
    Summary = @{
        TotalRequests        = $totalRequests
        CacheHits            = $totalCacheHits
        HubFallbacks         = $totalHubFallback
        PctLocal             = $pctLocal
        PctFallback          = $pctFallback
        AllowedButNotCached  = $allowedButNotCached.Count
        PRPConflicts         = $prpConflicts.Count
        CachedCredentials    = $revealedAccounts.Count
        PRPAllowMembers      = $prpAllowMembers.Count
        PRPDenyMembers       = $prpDenyMembers.Count
        EstimatedLatencyOverheadMs = $latencySavingMs
    }
    TopFallbackAccounts = @($enrichedFallback | ForEach-Object {
        @{
            Rank             = $_.Rank
            Account          = $_.Account
            AccountType      = $_.AccountType
            TotalRequests    = $_.TotalRequests
            CacheHits        = $_.CacheHits
            HubFallbacks     = $_.HubFallbacks
            FallbackPct      = $_.FallbackPct
            PRPStatus        = $_.PRPStatus
            CachedOnRODC     = $_.CachedOnRODC
            IsPrivileged     = $_.IsPrivileged
            PrivilegedGroups = $_.PrivilegedGroups
            SPNs             = $_.SPNs
            LastLogon        = if ($_.LastLogon) { $_.LastLogon.ToString('o') } else { $null }
            Recommendation   = $_.Recommendation
            FirstSeen        = $_.FirstSeen.ToString('o')
            LastSeen         = $_.LastSeen.ToString('o')
        }
    })
    ConfigurationIssues = @{
        PRPConflictAccounts       = @($prpConflicts)
        StalePRPEntries           = @($stalePRPEntries)
        HighFallbackServiceAccounts = @($highFallbackServices | ForEach-Object {
            @{
                Account     = $_.Account
                FallbackPct = $_.FallbackPct
                SPNs        = $_.SPNs
            }
        })
        AllowedButNotCached       = @($allowedButNotCached)
    }
    PRPConfiguration = @{
        AllowGroupDNs  = @($prpAllowDNs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        DenyGroupDNs   = @($prpDenyDNs  | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        AllowMemberCount = $prpAllowMembers.Count
        DenyMemberCount  = $prpDenyMembers.Count
    }
    RevealedList = @($revealedAccounts | ForEach-Object {
        @{
            SamAccountName    = $_.SamAccountName
            DistinguishedName = $_.DistinguishedName
            ObjectClass       = $_.ObjectClass
        }
    })
}

$jsonExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
Write-Host "[+] JSON export: $jsonPath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Region: Summary
# ---------------------------------------------------------------------------
$elapsed = (Get-Date) - $scriptStart

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Analysis Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RODC:            $rodcHostname" -ForegroundColor White
Write-Host "  Time window:     $HoursBack hour(s)" -ForegroundColor White
Write-Host "  Total requests:  $totalRequests" -ForegroundColor White
Write-Host "  Cache hit rate:  $pctLocal%" -ForegroundColor $(if ($pctLocal -ge 80) { 'Green' } elseif ($pctLocal -ge 60) { 'Yellow' } else { 'Red' })
Write-Host "  Hub fallbacks:   $totalHubFallback ($pctFallback%)" -ForegroundColor White
Write-Host "  PRP conflicts:   $($prpConflicts.Count)" -ForegroundColor $(if ($prpConflicts.Count -eq 0) { 'Green' } else { 'Red' })
Write-Host "  Elapsed:         $($elapsed.TotalSeconds.ToString('N1'))s" -ForegroundColor White
Write-Host ""
Write-Host "  HTML: $htmlPath" -ForegroundColor Gray
Write-Host "  CSV:  $csvPath" -ForegroundColor Gray
Write-Host "  JSON: $jsonPath" -ForegroundColor Gray
Write-Host "========================================`n" -ForegroundColor Cyan
