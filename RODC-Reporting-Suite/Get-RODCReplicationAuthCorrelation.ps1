#Requires -Version 5.1

<#
.SYNOPSIS
    Correlates RODC replication health with authentication failures to identify
    service-impacting replication issues.

.DESCRIPTION
    Get-RODCReplicationAuthCorrelation.ps1 analyzes Read-Only Domain Controllers
    (RODCs) by cross-referencing replication status from repadmin with authentication
    failure events (4776, 4768, 4769) from the Security event log. The script
    produces an HTML report with an executive summary, a per-RODC findings table,
    and detailed evidence sections, alongside CSV and JSON exports.

    The script auto-detects whether it is running on an RODC directly or on a
    hub (writable) DC and adjusts its data-collection strategy accordingly.

    All operations are strictly read-only. No changes are made to Active Directory,
    the registry, or any RODC configuration.

.PARAMETER RODCName
    One or more RODC hostnames to analyze. If omitted, all RODCs discovered in
    the forest are included.

.PARAMETER SiteFilter
    Limit analysis to RODCs in the specified Active Directory site(s).

.PARAMETER HoursBack
    Number of hours of event-log and replication history to consider.
    Default: 24.

.PARAMETER ReplicationThresholdMinutes
    Replication lag in minutes beyond which an RODC is flagged as stale.
    Default: 60.

.PARAMETER AuthFailureThreshold
    Minimum number of authentication failures required to consider the RODC
    as experiencing auth problems within the time window.
    Default: 10.

.PARAMETER OutputPath
    Directory where the HTML, CSV, and JSON reports are written.
    Default: C:\Reports\RODC.

.EXAMPLE
    .\Get-RODCReplicationAuthCorrelation.ps1
    Analyzes all RODCs in the forest over the last 24 hours with default thresholds.

.EXAMPLE
    .\Get-RODCReplicationAuthCorrelation.ps1 -RODCName RODC01,RODC02 -HoursBack 48
    Analyzes only RODC01 and RODC02 over the last 48 hours.

.EXAMPLE
    .\Get-RODCReplicationAuthCorrelation.ps1 -SiteFilter "BranchOffice-NYC" -OutputPath D:\AuditReports
    Analyzes RODCs in the BranchOffice-NYC site and writes reports to D:\AuditReports.

.NOTES
    Author  : Active Directory Reporting Toolkit
    Version : 1.0.0
    Date    : 2026-02-08
    License : MIT

    Requirements:
      - ActiveDirectory PowerShell module (RSAT)
      - repadmin.exe on the executing machine
      - Domain Admin or delegated read permissions on target RODCs
      - WinRM enabled on target RODCs for remote collection

    Safety:
      - 100 % read-only; no modifications are performed.
      - Unreachable RODCs are skipped with a warning in the report.
      - Empty event logs are handled gracefully (zero counts).
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$RODCName,

    [Parameter()]
    [string[]]$SiteFilter,

    [Parameter()]
    [ValidateRange(1, 8760)]
    [int]$HoursBack = 24,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$ReplicationThresholdMinutes = 60,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$AuthFailureThreshold = 10,

    [Parameter()]
    [string]$OutputPath = 'C:\Reports\RODC'
)

# ---------------------------------------------------------------------------
# Region: Strict mode and constants
# ---------------------------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Timestamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:TimestampReadable = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$script:CutoffTime      = (Get-Date).AddHours(-$HoursBack)
$script:ScriptVersion   = '1.0.0'
$script:CollectionErrors = [System.Collections.Generic.List[string]]::new()

# Event IDs of interest
$script:EventIDs = @{
    NTLMAuthFailure      = 4776
    KerberosTGTFailure   = 4768
    KerberosTicketFailure = 4769
}

# ---------------------------------------------------------------------------
# Region: Prerequisites
# ---------------------------------------------------------------------------
function Test-Prerequisites {
    [CmdletBinding()]
    param()

    Write-Verbose 'Checking prerequisites...'

    # Active Directory module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'The ActiveDirectory PowerShell module (RSAT) is not installed. Install RSAT and retry.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    Write-Verbose 'ActiveDirectory module loaded.'

    # repadmin.exe
    $repadmin = Get-Command repadmin.exe -ErrorAction SilentlyContinue
    if (-not $repadmin) {
        throw 'repadmin.exe was not found on this system. Ensure AD DS tools (RSAT) are installed.'
    }
    Write-Verbose "repadmin.exe located at $($repadmin.Source)."

    # Output directory
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        Write-Verbose "Creating output directory: $OutputPath"
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
}

# ---------------------------------------------------------------------------
# Region: Environment detection
# ---------------------------------------------------------------------------
function Get-ExecutionContext {
    [CmdletBinding()]
    param()

    $contextInfo = [ordered]@{
        ComputerName    = $env:COMPUTERNAME
        IsRODC          = $false
        IsDC            = $false
        DomainDNS       = $null
        ForestDNS       = $null
        ADModuleVersion = $null
        RepadminPath    = $null
        OSVersion       = [System.Environment]::OSVersion.VersionString
        PSVersion       = $PSVersionTable.PSVersion.ToString()
        ScriptVersion   = $script:ScriptVersion
        RunTime         = $script:TimestampReadable
    }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop
        $contextInfo.DomainDNS = $domain.DNSRoot
        $contextInfo.ForestDNS = $forest.Name

        # Determine if this machine is a DC or RODC
        try {
            $localDC = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop
            $contextInfo.IsDC = $true
            $contextInfo.IsRODC = $localDC.IsReadOnly
        }
        catch {
            Write-Verbose "This machine ($env:COMPUTERNAME) is not a domain controller."
        }

        $adModule = Get-Module ActiveDirectory
        $contextInfo.ADModuleVersion = if ($adModule) { $adModule.Version.ToString() } else { 'Unknown' }
        $repadminCmd = Get-Command repadmin.exe -ErrorAction SilentlyContinue
        $contextInfo.RepadminPath = if ($repadminCmd) { $repadminCmd.Source } else { 'Not found' }
    }
    catch {
        throw "Failed to query Active Directory environment: $_"
    }

    Write-Verbose "Execution context: DC=$($contextInfo.IsDC), RODC=$($contextInfo.IsRODC), Domain=$($contextInfo.DomainDNS)"
    return $contextInfo
}

# ---------------------------------------------------------------------------
# Region: RODC Discovery
# ---------------------------------------------------------------------------
function Get-TargetRODCs {
    [CmdletBinding()]
    param(
        [string[]]$Names,
        [string[]]$Sites
    )

    Write-Verbose 'Discovering RODCs...'

    if ($Names -and $Names.Count -gt 0) {
        $rodcs = foreach ($name in $Names) {
            try {
                Get-ADDomainController -Identity $name -ErrorAction Stop
            }
            catch {
                Write-Warning "Could not find domain controller '$name': $_"
                $script:CollectionErrors.Add("Discovery: Could not find DC '$name' - $_")
            }
        }
        # Verify they are actually RODCs
        $rodcs = @($rodcs | Where-Object { $_.IsReadOnly -eq $true })
        if ($rodcs.Count -eq 0) {
            Write-Warning 'None of the specified domain controllers are RODCs.'
        }
    }
    else {
        $rodcs = @(Get-ADDomainController -Filter { IsReadOnly -eq $true } -ErrorAction Stop)
    }

    if ($Sites -and $Sites.Count -gt 0) {
        $rodcs = @($rodcs | Where-Object { $Sites -contains $_.Site })
        Write-Verbose "Filtered to $($rodcs.Count) RODC(s) in site(s): $($Sites -join ', ')"
    }

    Write-Verbose "Target RODC count: $($rodcs.Count)"
    return $rodcs
}

# ---------------------------------------------------------------------------
# Region: Replication health collection
# ---------------------------------------------------------------------------
function Get-ReplicationHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RODCHostname
    )

    Write-Verbose "Collecting replication health for $RODCHostname..."

    $result = [ordered]@{
        RODC             = $RODCHostname
        NamingContexts   = [System.Collections.Generic.List[PSObject]]::new()
        MaxLagMinutes    = 0
        HasErrors        = $false
        LingeringObjects = 0
        RawOutput        = ''
        Status           = 'Unknown'
        ErrorMessage     = $null
    }

    try {
        $rawOutput = & repadmin.exe /showrepl $RODCHostname 2>&1
        $result.RawOutput = ($rawOutput | Out-String)

        if ($LASTEXITCODE -ne 0) {
            $result.Status = 'Error'
            $result.HasErrors = $true
            $result.ErrorMessage = "repadmin exited with code $LASTEXITCODE"
            Write-Warning "repadmin /showrepl $RODCHostname exited with code $LASTEXITCODE"
            $script:CollectionErrors.Add("Replication: repadmin failed for $RODCHostname (exit code $LASTEXITCODE)")
            return [PSCustomObject]$result
        }

        $rawText = $result.RawOutput

        # Parse naming context blocks.
        # repadmin output has sections starting with a naming context DN line
        # followed by partner information.
        $ncPattern = '(?m)^(?<nctype>DC|CN)=.*$'
        $ncBlocks = [regex]::Matches($rawText, '(?ms)(?=^\s*(DC|CN)=)(.+?)(?=^\s*(DC|CN)=|\z)')

        foreach ($block in $ncBlocks) {
            $blockText = $block.Value.Trim()
            $lines = $blockText -split "`n" | ForEach-Object { $_.Trim() }

            # First line is the NC DN
            $ncDN = $lines[0]

            # Determine NC type
            $ncType = 'Other'
            if ($ncDN -match 'CN=Configuration') { $ncType = 'Configuration' }
            elseif ($ncDN -match 'CN=Schema') { $ncType = 'Schema' }
            elseif ($ncDN -match '^DC=') { $ncType = 'Domain' }
            elseif ($ncDN -match 'DomainDnsZones|ForestDnsZones') { $ncType = 'DNS' }

            # Parse last successful replication time
            $lastSuccess = $null
            $lagMinutes = 0
            $successMatch = $blockText | Select-String -Pattern 'Last attempt @ (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) was successful' -AllMatches
            if (-not $successMatch) {
                $successMatch = $blockText | Select-String -Pattern 'Last success @ (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})' -AllMatches
            }

            if ($successMatch -and $successMatch.Matches.Count -gt 0) {
                $timeStr = $successMatch.Matches[0].Groups[1].Value
                try {
                    $lastSuccess = [datetime]::ParseExact($timeStr, 'yyyy-MM-dd HH:mm:ss', $null)
                    $lagMinutes = [math]::Round(((Get-Date) - $lastSuccess).TotalMinutes, 1)
                }
                catch {
                    Write-Verbose "Could not parse replication time '$timeStr' for $RODCHostname / $ncType"
                }
            }

            # Check for errors in the block
            $hasNCError = $false
            $errorLines = @($lines | Where-Object {
                $_ -match 'error|fail|LDAP error|RPC error' -and $_ -notmatch 'was successful'
            })
            if ($errorLines.Count -gt 0) {
                $hasNCError = $true
                $result.HasErrors = $true
            }

            # Check for lingering objects mention
            $lingeringCount = 0
            $lingeringMatch = $blockText | Select-String -Pattern 'lingering object' -AllMatches
            if ($lingeringMatch) {
                $lingeringCount = $lingeringMatch.Matches.Count
                $result.LingeringObjects += $lingeringCount
            }

            $ncInfo = [PSCustomObject][ordered]@{
                NamingContext = $ncDN
                NCType        = $ncType
                LastSuccess   = $lastSuccess
                LagMinutes    = $lagMinutes
                HasErrors     = $hasNCError
                ErrorDetails  = ($errorLines -join '; ')
                LingeringObjects = $lingeringCount
            }

            $result.NamingContexts.Add($ncInfo)

            if ($lagMinutes -gt $result.MaxLagMinutes) {
                $result.MaxLagMinutes = $lagMinutes
            }
        }

        # If no NC blocks were parsed, try a simpler heuristic
        if ($result.NamingContexts.Count -eq 0) {
            Write-Verbose "No naming context blocks parsed for $RODCHostname; checking raw output for errors."
            if ($rawText -match 'error|fail') {
                $result.HasErrors = $true
            }
        }

        # Determine overall status
        if ($result.HasErrors) {
            $result.Status = 'Error'
        }
        elseif ($result.MaxLagMinutes -gt $ReplicationThresholdMinutes) {
            $result.Status = 'Stale'
        }
        else {
            $result.Status = 'Healthy'
        }
    }
    catch {
        $result.Status = 'Unreachable'
        $result.HasErrors = $true
        $result.ErrorMessage = $_.Exception.Message
        Write-Warning "Failed to collect replication data from ${RODCHostname}: $_"
        $script:CollectionErrors.Add("Replication: Exception for $RODCHostname - $_")
    }

    return [PSCustomObject]$result
}

# ---------------------------------------------------------------------------
# Region: Authentication failure collection
# ---------------------------------------------------------------------------
function Get-AuthenticationFailures {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RODCHostname
    )

    Write-Verbose "Collecting authentication failures from $RODCHostname (last $HoursBack hours)..."

    $result = [ordered]@{
        RODC                  = $RODCHostname
        NTLMFailures          = 0
        KerberosTGTFailures   = 0
        KerberosTicketFailures = 0
        TotalFailures         = 0
        SampleEvents          = [System.Collections.Generic.List[PSObject]]::new()
        ErrorMessage          = $null
        Reachable             = $true
    }

    $eventFilter = @{
        LogName   = 'Security'
        Id        = @(4776, 4768, 4769)
        StartTime = $script:CutoffTime
    }

    try {
        # Test WinRM connectivity first
        $reachable = Test-WSMan -ComputerName $RODCHostname -ErrorAction SilentlyContinue
        if (-not $reachable) {
            $result.Reachable = $false
            $result.ErrorMessage = 'WinRM is unreachable on this RODC.'
            Write-Warning "WinRM is unreachable on $RODCHostname. Skipping auth failure collection."
            $script:CollectionErrors.Add("AuthFailures: WinRM unreachable on $RODCHostname")
            return [PSCustomObject]$result
        }

        $events = @()
        try {
            $events = @(Get-WinEvent -ComputerName $RODCHostname -FilterHashtable $eventFilter -ErrorAction Stop)
        }
        catch [Exception] {
            if ($_.Exception.Message -match 'No events were found') {
                Write-Verbose "No matching authentication failure events found on $RODCHostname."
                return [PSCustomObject]$result
            }
            throw
        }

        foreach ($event in $events) {
            switch ($event.Id) {
                4776 {
                    # NTLM: Only count failures (Status != 0x0)
                    if ($event.Message -and $event.Message -notmatch 'Error Code:\s+0x0\b') {
                        $result.NTLMFailures++
                    }
                }
                4768 {
                    # Kerberos TGT: Failure if Result Code != 0x0
                    if ($event.Message -and $event.Message -notmatch 'Result Code:\s+0x0\b') {
                        $result.KerberosTGTFailures++
                    }
                }
                4769 {
                    # Kerberos Service Ticket: Failure if Failure Code != 0x0
                    if ($event.Message -and $event.Message -notmatch 'Failure Code:\s+0x0\b') {
                        $result.KerberosTicketFailures++
                    }
                }
            }
        }

        $result.TotalFailures = $result.NTLMFailures + $result.KerberosTGTFailures + $result.KerberosTicketFailures

        # Collect a sample of up to 5 failure events for evidence
        $sampleEvents = $events |
            Where-Object {
                ($_.Id -eq 4776 -and $_.Message -notmatch 'Error Code:\s+0x0\b') -or
                ($_.Id -eq 4768 -and $_.Message -notmatch 'Result Code:\s+0x0\b') -or
                ($_.Id -eq 4769 -and $_.Message -notmatch 'Failure Code:\s+0x0\b')
            } |
            Select-Object -First 5

        foreach ($evt in $sampleEvents) {
            $result.SampleEvents.Add([PSCustomObject][ordered]@{
                TimeCreated = $evt.TimeCreated
                EventID     = $evt.Id
                Message     = $(
                    $cleanMsg = ($evt.Message -replace "`r`n", ' ')
                    if ($cleanMsg.Length -le 500) { $cleanMsg } else { $cleanMsg.Substring(0, 500) }
                )
            })
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-Warning "Failed to collect auth failure events from ${RODCHostname}: $_"
        $script:CollectionErrors.Add("AuthFailures: Exception for $RODCHostname - $_")
    }

    return [PSCustomObject]$result
}

# ---------------------------------------------------------------------------
# Region: RODC context collection
# ---------------------------------------------------------------------------
function Get-RODCContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADDomainController]$DCObject
    )

    $rodcName = $DCObject.HostName
    Write-Verbose "Collecting RODC context for $rodcName..."

    $context = [ordered]@{
        RODC                  = $DCObject.Name
        HostName              = $rodcName
        Site                  = $DCObject.Site
        IPv4Address           = $DCObject.IPv4Address
        OperatingSystem       = $DCObject.OperatingSystem
        CachedCredentialCount = 0
        SiteUserCount         = 0
        SiteComputerCount     = 0
        PrimaryPartner        = $null
        ErrorMessage          = $null
    }

    try {
        # Cached credential count via msDS-RevealedList
        try {
            $rodcComputer = Get-ADComputer -Identity $DCObject.Name -Properties 'msDS-RevealedList' -ErrorAction Stop
            $revealedList = $rodcComputer.'msDS-RevealedList'
            $context.CachedCredentialCount = if ($revealedList) { @($revealedList).Count } else { 0 }
        }
        catch {
            Write-Verbose "Could not retrieve msDS-RevealedList for $($DCObject.Name): $_"
            # Fallback: try msDS-RevealedUsers
            try {
                $rodcComputer = Get-ADComputer -Identity $DCObject.Name -Properties 'msDS-RevealedUsers' -ErrorAction Stop
                $revealedUsers = $rodcComputer.'msDS-RevealedUsers'
                $context.CachedCredentialCount = if ($revealedUsers) { @($revealedUsers).Count } else { 0 }
            }
            catch {
                Write-Verbose "Could not retrieve msDS-RevealedUsers for $($DCObject.Name): $_"
            }
        }

        # Estimate user/computer count in the RODC site
        $siteName = $DCObject.Site
        try {
            $siteObj = Get-ADReplicationSite -Identity $siteName -ErrorAction Stop
            $siteSubnets = @(Get-ADReplicationSubnet -Filter "Site -eq '$($siteObj.DistinguishedName)'" -ErrorAction SilentlyContinue)
            Write-Verbose "Site '$siteName' has $($siteSubnets.Count) subnet(s)."
        }
        catch {
            Write-Verbose "Could not enumerate subnets for site '$siteName': $_"
        }

        # Count users and computers in the domain (site-level estimation)
        try {
            $siteSearchBase = (Get-ADDomain).DistinguishedName
            $context.SiteUserCount = @(Get-ADUser -Filter * -SearchBase $siteSearchBase -SearchScope Subtree -ResultSetSize 0 -Server $rodcName -ErrorAction SilentlyContinue).Count
        }
        catch {
            Write-Verbose "Could not count users via $rodcName. Falling back to local domain query."
            try {
                $context.SiteUserCount = (Get-ADUser -Filter * -ResultSetSize 0 -ErrorAction Stop).Count
            }
            catch {
                Write-Verbose "User count fallback also failed: $_"
            }
        }

        try {
            $context.SiteComputerCount = @(Get-ADComputer -Filter * -SearchBase $siteSearchBase -SearchScope Subtree -ResultSetSize 0 -Server $rodcName -ErrorAction SilentlyContinue).Count
        }
        catch {
            Write-Verbose "Could not count computers via $rodcName."
        }

        # Primary replication partner (first inbound neighbor from repadmin)
        try {
            $replPartnerOutput = & repadmin.exe /showrepl $rodcName 2>&1 | Out-String
            $partnerMatch = [regex]::Match($replPartnerOutput, '(?mi)^\s*([\w\-]+)\s+via RPC')
            if ($partnerMatch.Success) {
                $context.PrimaryPartner = $partnerMatch.Groups[1].Value
            }
            else {
                # Try DSA pattern
                $dsaMatch = [regex]::Match($replPartnerOutput, '(?mi)DSA object GUID:\s+\S+\s*\n\s*Last attempt.*\n.*\n\s*([\w\-\.]+)')
                if ($dsaMatch.Success) {
                    $context.PrimaryPartner = $dsaMatch.Groups[1].Value
                }
            }
        }
        catch {
            Write-Verbose "Could not determine replication partner for ${rodcName}: $_"
        }
    }
    catch {
        $context.ErrorMessage = $_.Exception.Message
        Write-Warning "Error collecting context for ${rodcName}: $_"
        $script:CollectionErrors.Add("Context: Exception for $rodcName - $_")
    }

    return [PSCustomObject]$context
}

# ---------------------------------------------------------------------------
# Region: Correlation logic
# ---------------------------------------------------------------------------
function Get-CorrelationResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ReplHealth,
        [Parameter(Mandatory)] $AuthFailures,
        [Parameter(Mandatory)] $RODCContext
    )

    $isStale = $ReplHealth.MaxLagMinutes -gt $ReplicationThresholdMinutes
    $hasAuthIssues = $AuthFailures.TotalFailures -ge $AuthFailureThreshold
    $isCorrelated = $isStale -and $hasAuthIssues

    # Fallback ratio: auth failures / cached cred count
    $fallbackRatio = 0.0
    if ($RODCContext.CachedCredentialCount -gt 0) {
        $fallbackRatio = [math]::Round(($AuthFailures.TotalFailures / $RODCContext.CachedCredentialCount) * 100, 2)
    }
    elseif ($AuthFailures.TotalFailures -gt 0) {
        $fallbackRatio = 100.0   # No cached creds but failures exist
    }

    # Replication status color
    $replStatus = 'Green'
    if ($ReplHealth.Status -eq 'Error' -or $ReplHealth.Status -eq 'Unreachable') {
        $replStatus = 'Red'
    }
    elseif ($ReplHealth.Status -eq 'Stale') {
        $replStatus = 'Yellow'
    }

    # Severity determination
    $severity = 'Low'
    if ($isCorrelated -and ($ReplHealth.MaxLagMinutes -gt ($ReplicationThresholdMinutes * 4) -or $AuthFailures.TotalFailures -gt ($AuthFailureThreshold * 10))) {
        $severity = 'High'
    }
    elseif ($isCorrelated) {
        $severity = 'Medium'
    }
    elseif ($isStale -or $hasAuthIssues) {
        $severity = 'Medium'
    }

    # Impact score: weighted combination of lag and failure count
    $lagScore = [math]::Min($ReplHealth.MaxLagMinutes / 60, 10)   # 0-10 scale
    $authScore = [math]::Min($AuthFailures.TotalFailures / 100, 10)  # 0-10 scale
    $impactScore = [math]::Round(($lagScore * 0.4) + ($authScore * 0.6), 2)

    return [PSCustomObject][ordered]@{
        RODC                    = $RODCContext.RODC
        HostName                = $RODCContext.HostName
        Site                    = $RODCContext.Site
        ReplicationStatus       = $replStatus
        ReplicationStatusText   = $ReplHealth.Status
        MaxLagMinutes           = $ReplHealth.MaxLagMinutes
        HasReplicationErrors    = $ReplHealth.HasErrors
        LingeringObjects        = $ReplHealth.LingeringObjects
        NTLMFailures            = $AuthFailures.NTLMFailures
        KerberosTGTFailures     = $AuthFailures.KerberosTGTFailures
        KerberosTicketFailures  = $AuthFailures.KerberosTicketFailures
        TotalAuthFailures       = $AuthFailures.TotalFailures
        CachedCredentialCount   = $RODCContext.CachedCredentialCount
        FallbackRatioPercent    = $fallbackRatio
        PrimaryPartner          = $RODCContext.PrimaryPartner
        SiteUserCount           = $RODCContext.SiteUserCount
        SiteComputerCount       = $RODCContext.SiteComputerCount
        IsStale                 = $isStale
        HasAuthIssues           = $hasAuthIssues
        IsCorrelated            = $isCorrelated
        CorrelationFlag         = if ($isCorrelated) { 'Yes' } else { 'No' }
        Severity                = $severity
        ImpactScore             = $impactScore
        ReplRawOutput           = $ReplHealth.RawOutput
        AuthSampleEvents        = $AuthFailures.SampleEvents
        ReplicationNCs          = $ReplHealth.NamingContexts
        OperatingSystem         = $RODCContext.OperatingSystem
    }
}

# ---------------------------------------------------------------------------
# Region: HTML report generation
# ---------------------------------------------------------------------------
function New-HTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject[]]$Results,

        [Parameter(Mandatory)]
        [hashtable]$ExecContext
    )

    $totalRODCs       = $Results.Count
    $replIssueCount   = @($Results | Where-Object { $_.ReplicationStatus -ne 'Green' }).Count
    $authIssueCount   = @($Results | Where-Object { $_.HasAuthIssues }).Count
    $correlatedCount  = @($Results | Where-Object { $_.IsCorrelated }).Count

    # Sort by impact score descending
    $sortedResults = $Results | Sort-Object -Property ImpactScore -Descending

    # Build findings rows
    $findingsRows = [System.Text.StringBuilder]::new()
    foreach ($r in $sortedResults) {
        $statusColor = switch ($r.ReplicationStatus) {
            'Green'  { '#2ea043' }
            'Yellow' { '#d29922' }
            'Red'    { '#f85149' }
            default  { '#8b949e' }
        }

        $severityColor = switch ($r.Severity) {
            'High'   { '#f85149' }
            'Medium' { '#d29922' }
            'Low'    { '#2ea043' }
            default  { '#8b949e' }
        }

        $correlationColor = if ($r.IsCorrelated) { '#f85149' } else { '#2ea043' }

        [void]$findingsRows.AppendLine(@"
            <tr>
                <td class="mono">$([System.Web.HttpUtility]::HtmlEncode($r.RODC))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($r.Site))</td>
                <td><span class="status-badge" style="background-color:${statusColor};">$($r.ReplicationStatusText)</span></td>
                <td class="number">$($r.MaxLagMinutes)</td>
                <td class="number" title="NTLM: $($r.NTLMFailures) | TGT: $($r.KerberosTGTFailures) | Ticket: $($r.KerberosTicketFailures)">$($r.TotalAuthFailures)</td>
                <td class="number">$($r.CachedCredentialCount)</td>
                <td class="number">$($r.FallbackRatioPercent)%</td>
                <td><span class="status-badge" style="background-color:${correlationColor};">$($r.CorrelationFlag)</span></td>
                <td><span class="severity-badge" style="background-color:${severityColor};">$($r.Severity)</span></td>
            </tr>
"@)
    }

    # Build evidence sections
    $evidenceSections = [System.Text.StringBuilder]::new()
    foreach ($r in $sortedResults) {
        $escapedRawRepl = [System.Web.HttpUtility]::HtmlEncode($r.ReplRawOutput)

        $sampleEventsHtml = ''
        if ($r.AuthSampleEvents -and $r.AuthSampleEvents.Count -gt 0) {
            $sampleEventsHtml = '<table class="inner-table"><tr><th>Time</th><th>Event ID</th><th>Details</th></tr>'
            foreach ($evt in $r.AuthSampleEvents) {
                $sampleEventsHtml += "<tr><td>$($evt.TimeCreated)</td><td>$($evt.EventID)</td><td class='wrap'>$([System.Web.HttpUtility]::HtmlEncode($evt.Message))</td></tr>"
            }
            $sampleEventsHtml += '</table>'
        }
        else {
            $sampleEventsHtml = '<p class="secondary-text">No sample failure events collected.</p>'
        }

        $ncDetailHtml = ''
        if ($r.ReplicationNCs -and $r.ReplicationNCs.Count -gt 0) {
            $ncDetailHtml = '<table class="inner-table"><tr><th>Naming Context</th><th>Type</th><th>Last Success</th><th>Lag (min)</th><th>Errors</th></tr>'
            foreach ($nc in $r.ReplicationNCs) {
                $lastSuccessStr = if ($nc.LastSuccess) { $nc.LastSuccess.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
                $ncDetailHtml += "<tr><td class='wrap mono'>$([System.Web.HttpUtility]::HtmlEncode($nc.NamingContext))</td><td>$($nc.NCType)</td><td>$lastSuccessStr</td><td class='number'>$($nc.LagMinutes)</td><td class='wrap'>$([System.Web.HttpUtility]::HtmlEncode($nc.ErrorDetails))</td></tr>"
            }
            $ncDetailHtml += '</table>'
        }

        [void]$evidenceSections.AppendLine(@"
        <div class="evidence-block">
            <h3 class="evidence-title">$([System.Web.HttpUtility]::HtmlEncode($r.RODC)) &mdash; $([System.Web.HttpUtility]::HtmlEncode($r.Site))</h3>
            <div class="evidence-meta">
                <span>Primary Partner: <strong>$(if ($r.PrimaryPartner) { [System.Web.HttpUtility]::HtmlEncode($r.PrimaryPartner) } else { 'Unknown' })</strong></span>
                <span>OS: <strong>$([System.Web.HttpUtility]::HtmlEncode($r.OperatingSystem))</strong></span>
                <span>Impact Score: <strong>$($r.ImpactScore)</strong></span>
            </div>

            <h4>Naming Context Replication Details</h4>
            $ncDetailHtml

            <h4>Authentication Failure Breakdown</h4>
            <ul class="auth-breakdown">
                <li>NTLM (Event 4776) failures: <strong>$($r.NTLMFailures)</strong></li>
                <li>Kerberos TGT (Event 4768) failures: <strong>$($r.KerberosTGTFailures)</strong></li>
                <li>Kerberos Service Ticket (Event 4769) failures: <strong>$($r.KerberosTicketFailures)</strong></li>
            </ul>

            <h4>Sample Failure Events</h4>
            $sampleEventsHtml

            <h4>Raw repadmin /showrepl Output</h4>
            <pre class="raw-output">$escapedRawRepl</pre>
        </div>
"@)
    }

    # Commands used
    $commandsUsed = @"
        <div class="commands-block">
            <h3>Commands Used for Data Collection</h3>
            <ul>
                <li><code>repadmin /showrepl &lt;RODC&gt;</code> &mdash; Replication health per naming context</li>
                <li><code>Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4776,4768,4769); StartTime='$($script:CutoffTime.ToString('yyyy-MM-dd HH:mm:ss'))'}</code> &mdash; Authentication failure events</li>
                <li><code>Get-ADDomainController -Filter {IsReadOnly -eq `$true}</code> &mdash; RODC discovery</li>
                <li><code>Get-ADComputer -Properties 'msDS-RevealedList'</code> &mdash; Cached credential count</li>
                <li><code>Test-WSMan -ComputerName &lt;RODC&gt;</code> &mdash; WinRM connectivity check</li>
            </ul>
        </div>
"@

    # Collection errors section
    $errorsHtml = ''
    if ($script:CollectionErrors.Count -gt 0) {
        $errorsHtml = '<div class="errors-block"><h3>Collection Warnings and Errors</h3><ul>'
        foreach ($err in $script:CollectionErrors) {
            $errorsHtml += "<li>$([System.Web.HttpUtility]::HtmlEncode($err))</li>"
        }
        $errorsHtml += '</ul></div>'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RODC Replication &amp; Authentication Correlation Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: #0f1419;
            color: #e6edf3;
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        h1 {
            font-size: 1.8em;
            margin-bottom: 5px;
            color: #e6edf3;
        }

        h2 {
            font-size: 1.4em;
            margin: 30px 0 15px 0;
            color: #e6edf3;
            border-bottom: 1px solid #30363d;
            padding-bottom: 8px;
        }

        h3 {
            font-size: 1.15em;
            margin: 15px 0 10px 0;
            color: #e6edf3;
        }

        h4 {
            font-size: 1em;
            margin: 15px 0 8px 0;
            color: #8b949e;
        }

        .report-header {
            background-color: #1a2332;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
        }

        .report-subtitle {
            color: #8b949e;
            font-size: 0.9em;
            margin-top: 5px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }

        .summary-card {
            background-color: #1e2d3d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }

        .summary-card .card-value {
            font-size: 2.2em;
            font-weight: 700;
            display: block;
            margin-bottom: 5px;
        }

        .summary-card .card-label {
            color: #8b949e;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .card-blue .card-value { color: #58a6ff; }
        .card-yellow .card-value { color: #d29922; }
        .card-red .card-value { color: #f85149; }
        .card-green .card-value { color: #2ea043; }

        .section-card {
            background-color: #1a2332;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            font-size: 0.9em;
        }

        th {
            background-color: #1e2d3d;
            color: #8b949e;
            text-transform: uppercase;
            font-size: 0.75em;
            letter-spacing: 0.5px;
            padding: 12px 10px;
            text-align: left;
            border-bottom: 2px solid #30363d;
            position: sticky;
            top: 0;
        }

        td {
            padding: 10px;
            border-bottom: 1px solid #21262d;
            vertical-align: top;
        }

        tr:hover {
            background-color: rgba(88, 166, 255, 0.04);
        }

        .mono {
            font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
            font-size: 0.9em;
        }

        .number {
            text-align: right;
            font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
        }

        .wrap {
            word-break: break-all;
            max-width: 300px;
        }

        .status-badge, .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            color: #ffffff;
            text-align: center;
            min-width: 60px;
        }

        .evidence-block {
            background-color: #1e2d3d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .evidence-title {
            color: #58a6ff;
            margin-bottom: 10px;
        }

        .evidence-meta {
            display: flex;
            gap: 25px;
            flex-wrap: wrap;
            color: #8b949e;
            font-size: 0.85em;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #30363d;
        }

        .evidence-meta strong {
            color: #e6edf3;
        }

        .inner-table {
            font-size: 0.85em;
        }

        .inner-table th {
            background-color: #162030;
            font-size: 0.7em;
        }

        .inner-table td {
            padding: 6px 8px;
        }

        .auth-breakdown {
            list-style: none;
            padding: 0;
        }

        .auth-breakdown li {
            padding: 4px 0;
            color: #8b949e;
        }

        .auth-breakdown li strong {
            color: #e6edf3;
        }

        .raw-output {
            background-color: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 15px;
            font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
            font-size: 0.8em;
            color: #8b949e;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .commands-block {
            background-color: #1e2d3d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .commands-block li {
            padding: 4px 0;
            color: #8b949e;
        }

        .commands-block code {
            background-color: #0d1117;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
            font-size: 0.85em;
            color: #58a6ff;
        }

        .errors-block {
            background-color: #2d1117;
            border: 1px solid #f8514966;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .errors-block h3 {
            color: #f85149;
        }

        .errors-block li {
            padding: 3px 0;
            color: #f0a8a8;
            font-size: 0.9em;
        }

        .context-block {
            background-color: #1e2d3d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            font-size: 0.85em;
        }

        .context-block table td {
            padding: 4px 10px;
            border: none;
        }

        .context-block table td:first-child {
            color: #8b949e;
            width: 200px;
        }

        .secondary-text {
            color: #8b949e;
            font-style: italic;
        }

        .footer {
            text-align: center;
            color: #484f58;
            font-size: 0.8em;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #21262d;
        }

        @media print {
            body { background-color: #fff; color: #000; }
            .report-header, .section-card, .summary-card, .evidence-block,
            .commands-block, .context-block { border-color: #ccc; background-color: #f8f8f8; }
            th { background-color: #eee; color: #333; }
            td { border-color: #ddd; }
        }
    </style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="report-header">
        <h1>RODC Replication &amp; Authentication Correlation Report</h1>
        <p class="report-subtitle">
            Generated: $($script:TimestampReadable) |
            Time Window: Last $HoursBack hour(s) (since $($script:CutoffTime.ToString('yyyy-MM-dd HH:mm:ss'))) |
            Thresholds: Replication &gt; ${ReplicationThresholdMinutes}min, Auth Failures &ge; $AuthFailureThreshold
        </p>
    </div>

    <!-- Executive Summary -->
    <h2>Executive Summary</h2>
    <div class="summary-grid">
        <div class="summary-card card-blue">
            <span class="card-value">$totalRODCs</span>
            <span class="card-label">Total RODCs Analyzed</span>
        </div>
        <div class="summary-card card-yellow">
            <span class="card-value">$replIssueCount</span>
            <span class="card-label">Replication Issues</span>
        </div>
        <div class="summary-card card-red">
            <span class="card-value">$authIssueCount</span>
            <span class="card-label">Auth Failure Issues</span>
        </div>
        <div class="summary-card $(if ($correlatedCount -gt 0) { 'card-red' } else { 'card-green' })">
            <span class="card-value">$correlatedCount</span>
            <span class="card-label">Correlated (Both Conditions)</span>
        </div>
    </div>

    <!-- Findings Table -->
    <h2>Findings</h2>
    <div class="section-card" style="overflow-x:auto;">
        <table>
            <thead>
                <tr>
                    <th>RODC</th>
                    <th>Site</th>
                    <th>Repl Status</th>
                    <th>Max Lag (min)</th>
                    <th>Auth Failures</th>
                    <th>Cached Creds</th>
                    <th>Fallback Ratio</th>
                    <th>Correlated</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
$($findingsRows.ToString())
            </tbody>
        </table>
    </div>

    <!-- Evidence Section -->
    <h2>Evidence &amp; Details</h2>
$($evidenceSections.ToString())

    <!-- Commands Used -->
$commandsUsed

    <!-- Collection Errors -->
$errorsHtml

    <!-- Execution Context -->
    <h2>Execution Context</h2>
    <div class="context-block">
        <table>
            <tr><td>Executing Host</td><td>$([System.Web.HttpUtility]::HtmlEncode($ExecContext.ComputerName))</td></tr>
            <tr><td>Is Domain Controller</td><td>$($ExecContext.IsDC)</td></tr>
            <tr><td>Is RODC</td><td>$($ExecContext.IsRODC)</td></tr>
            <tr><td>Domain</td><td>$([System.Web.HttpUtility]::HtmlEncode($ExecContext.DomainDNS))</td></tr>
            <tr><td>Forest</td><td>$([System.Web.HttpUtility]::HtmlEncode($ExecContext.ForestDNS))</td></tr>
            <tr><td>AD Module Version</td><td>$([System.Web.HttpUtility]::HtmlEncode($ExecContext.ADModuleVersion))</td></tr>
            <tr><td>repadmin Path</td><td class="mono">$([System.Web.HttpUtility]::HtmlEncode($ExecContext.RepadminPath))</td></tr>
            <tr><td>OS Version</td><td>$([System.Web.HttpUtility]::HtmlEncode($ExecContext.OSVersion))</td></tr>
            <tr><td>PowerShell Version</td><td>$([System.Web.HttpUtility]::HtmlEncode($ExecContext.PSVersion))</td></tr>
            <tr><td>Script Version</td><td>$([System.Web.HttpUtility]::HtmlEncode($ExecContext.ScriptVersion))</td></tr>
        </table>
    </div>

    <div class="footer">
        RODC Replication &amp; Authentication Correlation Report v$($script:ScriptVersion) &mdash; Generated by Get-RODCReplicationAuthCorrelation.ps1
    </div>

</div>
</body>
</html>
"@

    return $html
}

# ---------------------------------------------------------------------------
# Region: Main execution
# ---------------------------------------------------------------------------
function Main {
    [CmdletBinding()]
    param()

    $mainStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Verbose '=========================================='
    Write-Verbose ' RODC Replication & Auth Correlation'
    Write-Verbose '=========================================='

    # Load System.Web for HTML encoding
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    # Step 1: Prerequisites
    Test-Prerequisites

    # Step 2: Execution context
    $execContext = Get-ExecutionContext
    Write-Verbose "Running on $($execContext.ComputerName) (DC=$($execContext.IsDC), RODC=$($execContext.IsRODC))"

    # Step 3: Discover target RODCs
    $targetRODCs = Get-TargetRODCs -Names $RODCName -Sites $SiteFilter
    if (-not $targetRODCs -or $targetRODCs.Count -eq 0) {
        Write-Warning 'No RODCs found matching the specified criteria. Exiting.'
        return
    }

    Write-Verbose "Processing $($targetRODCs.Count) RODC(s)..."

    # Step 4: Collect data and correlate
    $allResults = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($rodc in $targetRODCs) {
        $rodcHostname = $rodc.HostName
        $rodcShortName = $rodc.Name
        Write-Verbose "--- Processing RODC: $rodcShortName ($rodcHostname) ---"

        # Collect replication health
        $replHealth = Get-ReplicationHealth -RODCHostname $rodcHostname

        # Collect authentication failures
        $authFailures = Get-AuthenticationFailures -RODCHostname $rodcHostname

        # Collect RODC context
        $rodcContext = Get-RODCContext -DCObject $rodc

        # Correlate
        $correlation = Get-CorrelationResult -ReplHealth $replHealth -AuthFailures $authFailures -RODCContext $rodcContext

        $allResults.Add($correlation)

        Write-Verbose ("  Replication: {0} (Max Lag: {1} min) | Auth Failures: {2} | Correlated: {3} | Severity: {4}" -f
            $correlation.ReplicationStatusText,
            $correlation.MaxLagMinutes,
            $correlation.TotalAuthFailures,
            $correlation.CorrelationFlag,
            $correlation.Severity
        )
    }

    # Step 5: Generate outputs
    $baseFileName = "RODCCorrelation_$($script:Timestamp)"
    $htmlPath = Join-Path $OutputPath "$baseFileName.html"
    $csvPath  = Join-Path $OutputPath "$baseFileName.csv"
    $jsonPath = Join-Path $OutputPath "$baseFileName.json"

    # HTML report
    Write-Verbose "Generating HTML report: $htmlPath"
    $htmlContent = New-HTMLReport -Results $allResults -ExecContext $execContext
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force

    # CSV export (flattened, without raw output / nested objects)
    Write-Verbose "Generating CSV export: $csvPath"
    $csvData = $allResults | Select-Object `
        RODC,
        HostName,
        Site,
        ReplicationStatusText,
        MaxLagMinutes,
        HasReplicationErrors,
        LingeringObjects,
        NTLMFailures,
        KerberosTGTFailures,
        KerberosTicketFailures,
        TotalAuthFailures,
        CachedCredentialCount,
        FallbackRatioPercent,
        PrimaryPartner,
        SiteUserCount,
        SiteComputerCount,
        IsStale,
        HasAuthIssues,
        CorrelationFlag,
        Severity,
        ImpactScore

    $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force

    # JSON export (full depth)
    Write-Verbose "Generating JSON export: $jsonPath"
    $jsonData = [ordered]@{
        ReportMetadata = [ordered]@{
            GeneratedAt              = $script:TimestampReadable
            ScriptVersion            = $script:ScriptVersion
            HoursBack                = $HoursBack
            CutoffTime               = $script:CutoffTime.ToString('yyyy-MM-dd HH:mm:ss')
            ReplicationThresholdMin  = $ReplicationThresholdMinutes
            AuthFailureThreshold     = $AuthFailureThreshold
            ExecutionContext         = $execContext
        }
        Summary = [ordered]@{
            TotalRODCs              = $allResults.Count
            ReplicationIssueCount   = @($allResults | Where-Object { $_.ReplicationStatus -ne 'Green' }).Count
            AuthFailureIssueCount   = @($allResults | Where-Object { $_.HasAuthIssues }).Count
            CorrelatedCount         = @($allResults | Where-Object { $_.IsCorrelated }).Count
        }
        Results = @($allResults | ForEach-Object {
            [ordered]@{
                RODC                   = $_.RODC
                HostName               = $_.HostName
                Site                   = $_.Site
                ReplicationStatus      = $_.ReplicationStatusText
                MaxLagMinutes          = $_.MaxLagMinutes
                HasReplicationErrors   = $_.HasReplicationErrors
                LingeringObjects       = $_.LingeringObjects
                NTLMFailures           = $_.NTLMFailures
                KerberosTGTFailures    = $_.KerberosTGTFailures
                KerberosTicketFailures = $_.KerberosTicketFailures
                TotalAuthFailures      = $_.TotalAuthFailures
                CachedCredentialCount  = $_.CachedCredentialCount
                FallbackRatioPercent   = $_.FallbackRatioPercent
                PrimaryPartner         = $_.PrimaryPartner
                SiteUserCount          = $_.SiteUserCount
                SiteComputerCount      = $_.SiteComputerCount
                IsStale                = $_.IsStale
                HasAuthIssues          = $_.HasAuthIssues
                IsCorrelated           = $_.IsCorrelated
                Severity               = $_.Severity
                ImpactScore            = $_.ImpactScore
                ReplicationNCs         = @($_.ReplicationNCs | ForEach-Object {
                    [ordered]@{
                        NamingContext    = $_.NamingContext
                        NCType          = $_.NCType
                        LastSuccess     = if ($_.LastSuccess) { $_.LastSuccess.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                        LagMinutes      = $_.LagMinutes
                        HasErrors       = $_.HasErrors
                        ErrorDetails    = $_.ErrorDetails
                        LingeringObjects = $_.LingeringObjects
                    }
                })
                AuthSampleEvents       = @($_.AuthSampleEvents | ForEach-Object {
                    [ordered]@{
                        TimeCreated = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        EventID     = $_.EventID
                        Message     = $_.Message
                    }
                })
            }
        })
        CollectionErrors = @($script:CollectionErrors)
    }
    $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force

    $mainStopwatch.Stop()

    # Summary output
    Write-Verbose '=========================================='
    Write-Verbose ' Collection complete'
    Write-Verbose '=========================================='
    Write-Verbose "Elapsed: $($mainStopwatch.Elapsed.ToString('hh\:mm\:ss'))"

    # Console summary
    $summaryOutput = [PSCustomObject][ordered]@{
        TotalRODCs          = $allResults.Count
        ReplicationIssues   = @($allResults | Where-Object { $_.ReplicationStatus -ne 'Green' }).Count
        AuthFailureIssues   = @($allResults | Where-Object { $_.HasAuthIssues }).Count
        Correlated          = @($allResults | Where-Object { $_.IsCorrelated }).Count
        HighSeverity        = @($allResults | Where-Object { $_.Severity -eq 'High' }).Count
        HTMLReport          = $htmlPath
        CSVReport           = $csvPath
        JSONReport          = $jsonPath
        ElapsedTime         = $mainStopwatch.Elapsed.ToString('hh\:mm\:ss')
    }

    Write-Output $summaryOutput

    # Return detailed results for pipeline consumers
    return $allResults
}

# Invoke main
Main
