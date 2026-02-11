#Requires -Version 5.1

<#
.SYNOPSIS
    Measures RODC authentication latency patterns (local cache vs hub DC fallback).

.DESCRIPTION
    Get-RODCAuthPerformance.ps1 collects Kerberos authentication events (4768, 4769,
    4649) from one or more Read-Only Domain Controllers and correlates them into
    authentication "transactions" to approximate local-cache vs hub-DC-fallback
    latency.

    The script produces three output artefacts:
      - A self-contained dark-themed HTML report
      - A CSV file suitable for import into Excel or Power BI
      - A JSON file for programmatic consumption

    LIMITATIONS (read carefully):
      - Windows Security event log timestamps have SECOND granularity, not
        millisecond. All latency figures are therefore APPROXIMATE and derived
        from inter-event timing rather than true end-to-end measurements.
      - The script does NOT measure client-to-RODC network latency; it only
        measures RODC-to-hub-DC timing via event correlation and optional
        Test-NetConnection probes.
      - Network connectivity tests (Test-NetConnection) are optional and may
        require specific firewall rules to succeed.

    SAFETY:
      - All queries are strictly read-only.
      - No Active Directory objects are modified.
      - Network tests, when enabled, use standard PowerShell cmdlets that do
        not alter system state.

.PARAMETER RODCName
    Name (or comma-separated list) of the RODC(s) to analyse. If omitted the
    script targets the local machine.

.PARAMETER HoursBack
    Number of hours of event history to examine. Default: 24.

.PARAMETER LocalLatencyThresholdMs
    Latency threshold in milliseconds for local (cache-hit) authentication
    transactions. Transactions exceeding this value are flagged. Default: 200.

.PARAMETER HubLatencyThresholdMs
    Latency threshold in milliseconds for hub-DC-fallback authentication
    transactions. Transactions exceeding this value are flagged. Default: 1000.

.PARAMETER IncludeNetworkTest
    When specified, the script runs Test-NetConnection against the hub DC on
    SMB (445) and LDAP (389) ports to capture a round-trip-time baseline.

.PARAMETER OutputPath
    Directory where reports are written. Default: C:\Reports\RODC.

.EXAMPLE
    .\Get-RODCAuthPerformance.ps1
    Analyses the local RODC over the last 24 hours with default thresholds.

.EXAMPLE
    .\Get-RODCAuthPerformance.ps1 -RODCName "RODC01","RODC02" -HoursBack 48 -IncludeNetworkTest
    Analyses two RODCs over the last 48 hours and includes network baseline tests.

.EXAMPLE
    .\Get-RODCAuthPerformance.ps1 -LocalLatencyThresholdMs 100 -HubLatencyThresholdMs 500 -OutputPath D:\AuditReports
    Uses tighter thresholds and a custom output directory.

.NOTES
    Author  : Active Directory Reporting Toolkit
    Version : 1.0.0
    Requires: Windows PowerShell 5.1+, Security event log read access,
              repadmin.exe on target DCs.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0,
               HelpMessage = 'RODC computer name(s). Defaults to local machine.')]
    [ValidateNotNullOrEmpty()]
    [string[]]$RODCName,

    [Parameter(HelpMessage = 'Hours of event history to examine.')]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 24,

    [Parameter(HelpMessage = 'Local auth latency threshold in ms.')]
    [ValidateRange(1, 60000)]
    [int]$LocalLatencyThresholdMs = 200,

    [Parameter(HelpMessage = 'Hub fallback latency threshold in ms.')]
    [ValidateRange(1, 60000)]
    [int]$HubLatencyThresholdMs = 1000,

    [Parameter(HelpMessage = 'Include Test-NetConnection baseline to hub DCs.')]
    [switch]$IncludeNetworkTest,

    [Parameter(HelpMessage = 'Output directory for reports.')]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = 'C:\Reports\RODC'
)

# ---------------------------------------------------------------------------
# Region: Strict mode and constants
# ---------------------------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptVersion = '1.0.0'
$script:RunTimestamp  = Get-Date
$script:TimestampTag  = $script:RunTimestamp.ToString('yyyyMMdd_HHmmss')
$script:TransactionWindowSeconds = 5   # group events within this window

# ---------------------------------------------------------------------------
# Region: Helper — percentile calculation
# ---------------------------------------------------------------------------
function Get-Percentile {
    <#
    .SYNOPSIS
        Returns the value at the requested percentile from a numeric array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][double[]]$Values,
        [Parameter(Mandatory)][ValidateRange(0,100)][double]$Percentile
    )

    if ($Values.Count -eq 0) { return 0 }

    $sorted = $Values | Sort-Object
    $index  = [math]::Ceiling(($Percentile / 100) * $sorted.Count) - 1
    if ($index -lt 0) { $index = 0 }
    return $sorted[$index]
}

# ---------------------------------------------------------------------------
# Region: Helper — standard deviation
# ---------------------------------------------------------------------------
function Get-StandardDeviation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][double[]]$Values
    )

    if ($Values.Count -le 1) { return 0 }

    $mean = ($Values | Measure-Object -Average).Average
    $sumSquaredDiffs = 0
    foreach ($v in $Values) {
        $sumSquaredDiffs += [math]::Pow($v - $mean, 2)
    }
    return [math]::Sqrt($sumSquaredDiffs / ($Values.Count - 1))
}

# ---------------------------------------------------------------------------
# Region: Helper — status badge from latency
# ---------------------------------------------------------------------------
function Get-LatencyStatus {
    [CmdletBinding()]
    param(
        [double]$MedianLocal,
        [double]$MedianHub,
        [double]$P95Local,
        [double]$P95Hub,
        [int]$OutlierCount,
        [int]$LocalThreshold,
        [int]$HubThreshold
    )

    # Red if P95 exceeds 2x threshold or outlier count > 10
    if ($P95Local -gt ($LocalThreshold * 2) -or
        $P95Hub   -gt ($HubThreshold * 2)   -or
        $OutlierCount -gt 10) {
        return 'Red'
    }

    # Yellow if median exceeds threshold or P95 exceeds threshold
    if ($MedianLocal -gt $LocalThreshold -or
        $MedianHub   -gt $HubThreshold   -or
        $P95Local    -gt $LocalThreshold  -or
        $P95Hub      -gt $HubThreshold) {
        return 'Yellow'
    }

    return 'Green'
}

# ---------------------------------------------------------------------------
# Region: Collect events from a single RODC
# ---------------------------------------------------------------------------
function Get-AuthEvents {
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [int]$Hours
    )

    $startTime = (Get-Date).AddHours(-$Hours)
    $results   = @{
        TGTRequests      = @()
        ServiceTickets   = @()
        CredCacheEvents  = @()
    }

    # --- Event 4768: Kerberos TGT Requests ---
    Write-Verbose "[$ComputerName] Querying Event 4768 (Kerberos TGT requests)..."
    $filterHash4768 = @{
        LogName   = 'Security'
        Id        = 4768
        StartTime = $startTime
    }

    try {
        $params = @{ FilterHashtable = $filterHash4768; ErrorAction = 'Stop' }
        if ($ComputerName -and $ComputerName -ne $env:COMPUTERNAME) {
            $params['ComputerName'] = $ComputerName
        }
        $raw4768 = Get-WinEvent @params
        Write-Verbose "[$ComputerName] Found $($raw4768.Count) Event 4768 entries."
    }
    catch [Exception] {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Verbose "[$ComputerName] No Event 4768 entries in the time window."
            $raw4768 = @()
        }
        else {
            Write-Warning "[$ComputerName] Failed to query Event 4768: $($_.Exception.Message)"
            $raw4768 = @()
        }
    }

    foreach ($evt in $raw4768) {
        try {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($node in $xml.Event.EventData.Data) {
                $data[$node.Name] = $node.'#text'
            }
            $results.TGTRequests += [PSCustomObject]@{
                TimeCreated    = $evt.TimeCreated
                TimeMs         = ([DateTimeOffset]$evt.TimeCreated).ToUnixTimeMilliseconds()
                EventId        = 4768
                TargetUserName = $data['TargetUserName']
                ServiceName    = $data['ServiceName']
                IpAddress      = ($data['IpAddress'] -replace '::ffff:', '')
                TicketOptions  = $data['TicketOptions']
                Status         = $data['Status']
                Computer       = $ComputerName
            }
        }
        catch {
            Write-Verbose "[$ComputerName] Skipping malformed 4768 event: $($_.Exception.Message)"
        }
    }

    # --- Event 4769: Kerberos Service Ticket Requests ---
    Write-Verbose "[$ComputerName] Querying Event 4769 (service ticket requests)..."
    $filterHash4769 = @{
        LogName   = 'Security'
        Id        = 4769
        StartTime = $startTime
    }

    try {
        $params = @{ FilterHashtable = $filterHash4769; ErrorAction = 'Stop' }
        if ($ComputerName -and $ComputerName -ne $env:COMPUTERNAME) {
            $params['ComputerName'] = $ComputerName
        }
        $raw4769 = Get-WinEvent @params
        Write-Verbose "[$ComputerName] Found $($raw4769.Count) Event 4769 entries."
    }
    catch [Exception] {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Verbose "[$ComputerName] No Event 4769 entries in the time window."
            $raw4769 = @()
        }
        else {
            Write-Warning "[$ComputerName] Failed to query Event 4769: $($_.Exception.Message)"
            $raw4769 = @()
        }
    }

    foreach ($evt in $raw4769) {
        try {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($node in $xml.Event.EventData.Data) {
                $data[$node.Name] = $node.'#text'
            }
            $results.ServiceTickets += [PSCustomObject]@{
                TimeCreated    = $evt.TimeCreated
                TimeMs         = ([DateTimeOffset]$evt.TimeCreated).ToUnixTimeMilliseconds()
                EventId        = 4769
                TargetUserName = $data['TargetUserName']
                ServiceName    = $data['ServiceName']
                IpAddress      = ($data['IpAddress'] -replace '::ffff:', '')
                TicketOptions  = $data['TicketOptions']
                Status         = $data['Status']
                Computer       = $ComputerName
            }
        }
        catch {
            Write-Verbose "[$ComputerName] Skipping malformed 4769 event: $($_.Exception.Message)"
        }
    }

    # --- Event 4649: Credential Cache / Replay Detection ---
    Write-Verbose "[$ComputerName] Querying Event 4649 (credential cache requests)..."
    $filterHash4649 = @{
        LogName   = 'Security'
        Id        = 4649
        StartTime = $startTime
    }

    try {
        $params = @{ FilterHashtable = $filterHash4649; ErrorAction = 'Stop' }
        if ($ComputerName -and $ComputerName -ne $env:COMPUTERNAME) {
            $params['ComputerName'] = $ComputerName
        }
        $raw4649 = Get-WinEvent @params
        Write-Verbose "[$ComputerName] Found $($raw4649.Count) Event 4649 entries."
    }
    catch [Exception] {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Verbose "[$ComputerName] No Event 4649 entries in the time window."
            $raw4649 = @()
        }
        else {
            Write-Warning "[$ComputerName] Failed to query Event 4649: $($_.Exception.Message)"
            $raw4649 = @()
        }
    }

    foreach ($evt in $raw4649) {
        try {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($node in $xml.Event.EventData.Data) {
                $data[$node.Name] = $node.'#text'
            }

            # Determine cache hit/miss from status fields
            $cacheStatus = 'Unknown'
            $statusCode = $data['Status']
            if ($null -ne $statusCode) {
                if ($statusCode -eq '0x0') {
                    $cacheStatus = 'CacheHit'
                }
                else {
                    $cacheStatus = 'CacheMiss'
                }
            }

            $results.CredCacheEvents += [PSCustomObject]@{
                TimeCreated    = $evt.TimeCreated
                TimeMs         = ([DateTimeOffset]$evt.TimeCreated).ToUnixTimeMilliseconds()
                EventId        = 4649
                TargetUserName = $data['TargetUserName']
                SubjectUserName = $data['SubjectUserName']
                Status         = $statusCode
                CacheStatus    = $cacheStatus
                Computer       = $ComputerName
            }
        }
        catch {
            Write-Verbose "[$ComputerName] Skipping malformed 4649 event: $($_.Exception.Message)"
        }
    }

    return $results
}

# ---------------------------------------------------------------------------
# Region: Parse repadmin /showrepl for RODC partner hub DC
# ---------------------------------------------------------------------------
function Get-ReplicationTopology {
    [CmdletBinding()]
    param(
        [string]$ComputerName
    )

    Write-Verbose "[$ComputerName] Parsing replication topology via repadmin /showrepl..."

    $topology = [PSCustomObject]@{
        RODC              = $ComputerName
        Site              = 'Unknown'
        PrimaryPartnerDC  = 'Unknown'
        SiteLinkCost      = 'N/A'
        LastReplResult    = 'N/A'
        LastReplTimestamp  = $null
    }

    try {
        $replOutput = $null
        if ($ComputerName -and $ComputerName -ne $env:COMPUTERNAME) {
            $replOutput = & repadmin /showrepl $ComputerName 2>&1
        }
        else {
            $replOutput = & repadmin /showrepl 2>&1
        }

        $replText = $replOutput -join "`n"

        # Extract site name: "DSA Options: ..." often preceded by site info
        # Pattern: "<site>\<DC name>"
        $siteMatch = [regex]::Match($replText, '(?i)Site:\s*(\S+)')
        if ($siteMatch.Success) {
            $topology.Site = $siteMatch.Groups[1].Value
        }
        else {
            # Alternative: look for CN=<site> in DSA path
            $dsaMatch = [regex]::Match($replText, '(?i)CN=([^,]+),CN=Servers,CN=([^,]+),CN=Sites')
            if ($dsaMatch.Success) {
                $topology.Site = $dsaMatch.Groups[2].Value
            }
        }

        # Extract primary replication partner (first "Source:" line)
        $sourceMatches = [regex]::Matches($replText, '(?im)^\s*Source:\s*(\S+)')
        if ($sourceMatches.Count -gt 0) {
            # Use the most frequently occurring source as the primary partner
            $partnerCounts = @{}
            foreach ($m in $sourceMatches) {
                $partner = $m.Groups[1].Value
                if (-not $partnerCounts.ContainsKey($partner)) {
                    $partnerCounts[$partner] = 0
                }
                $partnerCounts[$partner]++
            }
            $topology.PrimaryPartnerDC = ($partnerCounts.GetEnumerator() |
                Sort-Object Value -Descending |
                Select-Object -First 1).Key
        }

        # Extract last successful replication result
        $resultMatch = [regex]::Match($replText, '(?i)Last attempt.*?was successful')
        if ($resultMatch.Success) {
            $topology.LastReplResult = 'Success'
        }
        else {
            $failMatch = [regex]::Match($replText, '(?i)Last attempt.*?result\s+(\d+)')
            if ($failMatch.Success) {
                $topology.LastReplResult = "Error $($failMatch.Groups[1].Value)"
            }
        }

        # Extract last replication timestamp
        $timeMatch = [regex]::Match($replText, '(?i)Last attempt @ (\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})')
        if ($timeMatch.Success) {
            $topology.LastReplTimestamp = [datetime]::Parse($timeMatch.Groups[1].Value)
        }
    }
    catch {
        Write-Warning "[$ComputerName] Failed to parse replication topology: $($_.Exception.Message)"
    }

    return $topology
}

# ---------------------------------------------------------------------------
# Region: Optional network baseline test
# ---------------------------------------------------------------------------
function Get-NetworkBaseline {
    [CmdletBinding()]
    param(
        [string]$SourceRODC,
        [string]$HubDC
    )

    Write-Verbose "[$SourceRODC] Running network baseline tests to hub DC '$HubDC'..."

    $baseline = [PSCustomObject]@{
        SourceRODC     = $SourceRODC
        HubDC          = $HubDC
        LDAP389_RTTms  = $null
        SMB445_RTTms   = $null
        LDAP389_Open   = $false
        SMB445_Open    = $false
        TestTimestamp   = Get-Date
    }

    # Test LDAP port 389
    try {
        $ldapTest = Test-NetConnection -ComputerName $HubDC -Port 389 -WarningAction SilentlyContinue
        $baseline.LDAP389_Open  = $ldapTest.TcpTestSucceeded
        if ($ldapTest.TcpTestSucceeded -and $null -ne $ldapTest.PingReplyDetails) {
            $baseline.LDAP389_RTTms = $ldapTest.PingReplyDetails.RoundtripTime
        }
        elseif ($ldapTest.TcpTestSucceeded) {
            # Fallback: use a simple measurement
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $tcp = New-Object System.Net.Sockets.TcpClient
            try {
                $tcp.Connect($HubDC, 389)
                $sw.Stop()
                $baseline.LDAP389_RTTms = $sw.ElapsedMilliseconds
            }
            catch {
                $sw.Stop()
                $baseline.LDAP389_RTTms = $null
            }
            finally {
                $tcp.Dispose()
            }
        }
    }
    catch {
        Write-Verbose "[$SourceRODC] LDAP test to $HubDC failed: $($_.Exception.Message)"
    }

    # Test SMB port 445
    try {
        $smbTest = Test-NetConnection -ComputerName $HubDC -Port 445 -WarningAction SilentlyContinue
        $baseline.SMB445_Open  = $smbTest.TcpTestSucceeded
        if ($smbTest.TcpTestSucceeded -and $null -ne $smbTest.PingReplyDetails) {
            $baseline.SMB445_RTTms = $smbTest.PingReplyDetails.RoundtripTime
        }
        elseif ($smbTest.TcpTestSucceeded) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $tcp = New-Object System.Net.Sockets.TcpClient
            try {
                $tcp.Connect($HubDC, 445)
                $sw.Stop()
                $baseline.SMB445_RTTms = $sw.ElapsedMilliseconds
            }
            catch {
                $sw.Stop()
                $baseline.SMB445_RTTms = $null
            }
            finally {
                $tcp.Dispose()
            }
        }
    }
    catch {
        Write-Verbose "[$SourceRODC] SMB test to $HubDC failed: $($_.Exception.Message)"
    }

    return $baseline
}

# ---------------------------------------------------------------------------
# Region: Build authentication transactions
# ---------------------------------------------------------------------------
function Build-AuthTransactions {
    [CmdletBinding()]
    param(
        [object]$AuthEvents,
        [string]$ComputerName,
        [int]$WindowSeconds
    )

    Write-Verbose "[$ComputerName] Building authentication transactions (window: ${WindowSeconds}s)..."

    $transactions = [System.Collections.ArrayList]::new()

    # Merge all events into a single sorted timeline
    $allEvents = [System.Collections.ArrayList]::new()
    foreach ($e in $AuthEvents.TGTRequests)     { [void]$allEvents.Add($e) }
    foreach ($e in $AuthEvents.ServiceTickets)   { [void]$allEvents.Add($e) }
    foreach ($e in $AuthEvents.CredCacheEvents)  { [void]$allEvents.Add($e) }

    if ($allEvents.Count -eq 0) {
        Write-Verbose "[$ComputerName] No events to build transactions from."
        return @()
    }

    $sortedEvents = $allEvents | Sort-Object TimeCreated

    # Group by account name within the time window
    $processed = @{}
    foreach ($evt in $sortedEvents) {
        $accountName = if ($evt.PSObject.Properties['TargetUserName'] -and $evt.TargetUserName) {
            $evt.TargetUserName
        }
        elseif ($evt.PSObject.Properties['SubjectUserName'] -and $evt.SubjectUserName) {
            $evt.SubjectUserName
        }
        else {
            'Unknown'
        }

        # Skip machine accounts for cleaner analysis (optional — we include them)
        $key = "$accountName|$($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))"

        if (-not $processed.ContainsKey($key)) {
            $processed[$key] = [System.Collections.ArrayList]::new()
        }
        [void]$processed[$key].Add($evt)
    }

    # Now cluster into transactions: events for the same account within WindowSeconds
    $accountGroups = $sortedEvents | Group-Object {
        if ($_.PSObject.Properties['TargetUserName'] -and $_.TargetUserName) {
            $_.TargetUserName
        }
        elseif ($_.PSObject.Properties['SubjectUserName'] -and $_.SubjectUserName) {
            $_.SubjectUserName
        }
        else {
            'Unknown'
        }
    }

    foreach ($group in $accountGroups) {
        $accountName  = $group.Name
        $events       = $group.Group | Sort-Object TimeCreated
        $currentBatch = [System.Collections.ArrayList]::new()
        $batchStart   = $null

        foreach ($evt in $events) {
            if ($null -eq $batchStart) {
                $batchStart = $evt.TimeCreated
                [void]$currentBatch.Add($evt)
                continue
            }

            $diffSeconds = ($evt.TimeCreated - $batchStart).TotalSeconds
            if ($diffSeconds -le $WindowSeconds) {
                [void]$currentBatch.Add($evt)
            }
            else {
                # Finalize the current batch as a transaction
                $txn = ConvertTo-Transaction -Events $currentBatch -Account $accountName -Computer $ComputerName
                if ($txn) { [void]$transactions.Add($txn) }

                # Start a new batch
                $currentBatch = [System.Collections.ArrayList]::new()
                [void]$currentBatch.Add($evt)
                $batchStart = $evt.TimeCreated
            }
        }

        # Finalize remaining batch
        if ($currentBatch.Count -gt 0) {
            $txn = ConvertTo-Transaction -Events $currentBatch -Account $accountName -Computer $ComputerName
            if ($txn) { [void]$transactions.Add($txn) }
        }
    }

    Write-Verbose "[$ComputerName] Built $($transactions.Count) authentication transactions."
    return $transactions.ToArray()
}

# ---------------------------------------------------------------------------
# Region: Convert a batch of events into a transaction object
# ---------------------------------------------------------------------------
function ConvertTo-Transaction {
    [CmdletBinding()]
    param(
        [System.Collections.ArrayList]$Events,
        [string]$Account,
        [string]$Computer
    )

    $cacheEvent = $Events | Where-Object { $_.EventId -eq 4649 } | Select-Object -First 1
    $tgtEvent   = $Events | Where-Object { $_.EventId -eq 4768 } | Select-Object -First 1
    $svcEvent   = $Events | Where-Object { $_.EventId -eq 4769 } | Select-Object -First 1

    # Determine auth type: if we have a cache event, use its status
    $authType = 'Hub'   # default assumption: hub fallback
    if ($cacheEvent) {
        if ($cacheEvent.CacheStatus -eq 'CacheHit') {
            $authType = 'Local'
        }
        else {
            $authType = 'Hub'
        }
    }

    # Calculate approximate latency in milliseconds
    $latencyMs = 0
    $startEvent = $null
    $endEvent   = $null

    if ($cacheEvent -and $tgtEvent) {
        $startEvent = $cacheEvent
        $endEvent   = $tgtEvent
    }
    elseif ($cacheEvent -and $svcEvent) {
        $startEvent = $cacheEvent
        $endEvent   = $svcEvent
    }
    elseif ($tgtEvent -and $svcEvent) {
        $startEvent = $tgtEvent
        $endEvent   = $svcEvent
        # Without a cache event we cannot distinguish local vs hub reliably;
        # assume hub for safety.
        $authType = 'Hub'
    }
    elseif ($tgtEvent) {
        # Single TGT event — latency unknown; record as 0
        $startEvent = $tgtEvent
        $endEvent   = $tgtEvent
    }
    elseif ($svcEvent) {
        $startEvent = $svcEvent
        $endEvent   = $svcEvent
    }
    else {
        # Only cache events, no ticket issued — skip
        return $null
    }

    if ($startEvent -and $endEvent) {
        $latencyMs = [math]::Abs($endEvent.TimeMs - $startEvent.TimeMs)
    }

    $status = 'Success'
    if ($tgtEvent -and $tgtEvent.Status -and $tgtEvent.Status -ne '0x0') {
        $status = "Failure ($($tgtEvent.Status))"
    }

    $clientIp = ''
    if ($tgtEvent -and $tgtEvent.IpAddress) {
        $clientIp = $tgtEvent.IpAddress
    }
    elseif ($svcEvent -and $svcEvent.IpAddress) {
        $clientIp = $svcEvent.IpAddress
    }

    return [PSCustomObject]@{
        Timestamp     = $startEvent.TimeCreated
        Account       = $Account
        AuthType      = $authType
        LatencyMs     = $latencyMs
        Status        = $status
        ClientIP      = $clientIp
        EventCount    = $Events.Count
        Computer      = $Computer
        HasCacheEvent = [bool]$cacheEvent
        HasTGTEvent   = [bool]$tgtEvent
        HasSvcEvent   = [bool]$svcEvent
    }
}

# ---------------------------------------------------------------------------
# Region: Analyse transactions and produce summary structures
# ---------------------------------------------------------------------------
function Get-TransactionAnalysis {
    [CmdletBinding()]
    param(
        [object[]]$Transactions,
        [int]$LocalThreshold,
        [int]$HubThreshold
    )

    $localTxns = $Transactions | Where-Object { $_.AuthType -eq 'Local' }
    $hubTxns   = $Transactions | Where-Object { $_.AuthType -eq 'Hub' }

    $localLatencies = @(if ($localTxns) { $localTxns | ForEach-Object { $_.LatencyMs } } else { @() })
    $hubLatencies   = @(if ($hubTxns)   { $hubTxns   | ForEach-Object { $_.LatencyMs } } else { @() })

    # Statistics for local
    $localP50  = if ($localLatencies.Count -gt 0) { Get-Percentile -Values $localLatencies -Percentile 50 } else { 0 }
    $localP95  = if ($localLatencies.Count -gt 0) { Get-Percentile -Values $localLatencies -Percentile 95 } else { 0 }
    $localP99  = if ($localLatencies.Count -gt 0) { Get-Percentile -Values $localLatencies -Percentile 99 } else { 0 }
    $localMean = if ($localLatencies.Count -gt 0) { ($localLatencies | Measure-Object -Average).Average } else { 0 }
    $localSD   = if ($localLatencies.Count -gt 0) { Get-StandardDeviation -Values $localLatencies } else { 0 }

    # Statistics for hub
    $hubP50  = if ($hubLatencies.Count -gt 0) { Get-Percentile -Values $hubLatencies -Percentile 50 } else { 0 }
    $hubP95  = if ($hubLatencies.Count -gt 0) { Get-Percentile -Values $hubLatencies -Percentile 95 } else { 0 }
    $hubP99  = if ($hubLatencies.Count -gt 0) { Get-Percentile -Values $hubLatencies -Percentile 99 } else { 0 }
    $hubMean = if ($hubLatencies.Count -gt 0) { ($hubLatencies | Measure-Object -Average).Average } else { 0 }
    $hubSD   = if ($hubLatencies.Count -gt 0) { Get-StandardDeviation -Values $hubLatencies } else { 0 }

    # Identify outliers (> 2 standard deviations from mean)
    $outliers = [System.Collections.ArrayList]::new()

    foreach ($txn in $Transactions) {
        $isOutlier = $false
        $potentialCause = ''

        if ($txn.AuthType -eq 'Local') {
            if ($localSD -gt 0 -and [math]::Abs($txn.LatencyMs - $localMean) -gt (2 * $localSD)) {
                $isOutlier = $true
                if ($txn.LatencyMs -gt $LocalThreshold * 2) {
                    $potentialCause = 'Possible replication lag or RODC overload'
                }
                elseif ($txn.LatencyMs -gt $LocalThreshold) {
                    $potentialCause = 'Elevated local processing time'
                }
                else {
                    $potentialCause = 'Statistical outlier (within threshold)'
                }
            }
        }
        else {
            if ($hubSD -gt 0 -and [math]::Abs($txn.LatencyMs - $hubMean) -gt (2 * $hubSD)) {
                $isOutlier = $true
                if ($txn.LatencyMs -gt $HubThreshold * 2) {
                    $potentialCause = 'Severe network latency or hub DC overloaded'
                }
                elseif ($txn.LatencyMs -gt $HubThreshold) {
                    $potentialCause = 'Network congestion to hub DC'
                }
                else {
                    $potentialCause = 'Statistical outlier (within threshold)'
                }
            }
        }

        if ($isOutlier) {
            [void]$outliers.Add([PSCustomObject]@{
                Timestamp      = $txn.Timestamp
                Account        = $txn.Account
                AuthType       = $txn.AuthType
                LatencyMs      = $txn.LatencyMs
                PotentialCause = $potentialCause
                Computer       = $txn.Computer
            })
        }
    }

    # Threshold exceedances
    $localExceedCount = @($localTxns | Where-Object { $_.LatencyMs -gt $LocalThreshold }).Count
    $hubExceedCount   = @($hubTxns | Where-Object { $_.LatencyMs -gt $HubThreshold }).Count

    return [PSCustomObject]@{
        TotalTransactions    = $Transactions.Count
        LocalCount           = $localLatencies.Count
        HubCount             = $hubLatencies.Count
        LocalP50             = [math]::Round($localP50, 1)
        LocalP95             = [math]::Round($localP95, 1)
        LocalP99             = [math]::Round($localP99, 1)
        LocalMean            = [math]::Round($localMean, 1)
        LocalSD              = [math]::Round($localSD, 1)
        HubP50               = [math]::Round($hubP50, 1)
        HubP95               = [math]::Round($hubP95, 1)
        HubP99               = [math]::Round($hubP99, 1)
        HubMean              = [math]::Round($hubMean, 1)
        HubSD                = [math]::Round($hubSD, 1)
        LocalExceedThreshold = $localExceedCount
        HubExceedThreshold   = $hubExceedCount
        OutlierCount         = $outliers.Count
        Outliers             = $outliers.ToArray()
    }
}

# ---------------------------------------------------------------------------
# Region: Build Hub DC Load Distribution
# ---------------------------------------------------------------------------
function Get-HubDCLoadDistribution {
    [CmdletBinding()]
    param(
        [object[]]$AllTransactions,
        [hashtable]$TopologyMap
    )

    # Map each RODC to its hub DC
    $hubTxns = [System.Collections.ArrayList]::new()
    foreach ($txn in $AllTransactions) {
        if ($txn.AuthType -eq 'Hub') {
            $hubDC = 'Unknown'
            if ($TopologyMap.ContainsKey($txn.Computer)) {
                $hubDC = $TopologyMap[$txn.Computer].PrimaryPartnerDC
            }
            [void]$hubTxns.Add([PSCustomObject]@{
                HubDC     = $hubDC
                LatencyMs = $txn.LatencyMs
                Account   = $txn.Account
                Timestamp = $txn.Timestamp
                RODC      = $txn.Computer
            })
        }
    }

    $distribution = @()
    if ($hubTxns.Count -gt 0) {
        $grouped = $hubTxns | Group-Object HubDC
        foreach ($g in $grouped) {
            $latencies = @($g.Group | ForEach-Object { $_.LatencyMs })
            $avgLatency = if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Average).Average } else { 0 }
            $p95Latency = if ($latencies.Count -gt 0) { Get-Percentile -Values $latencies -Percentile 95 } else { 0 }

            $distribution += [PSCustomObject]@{
                HubDC           = $g.Name
                FallbackCount   = $g.Count
                AvgLatencyMs    = [math]::Round($avgLatency, 1)
                P95LatencyMs    = [math]::Round($p95Latency, 1)
                UniqueAccounts  = ($g.Group | Select-Object -ExpandProperty Account -Unique).Count
                ServicingRODCs  = ($g.Group | Select-Object -ExpandProperty RODC -Unique) -join ', '
            }
        }
        $distribution = $distribution | Sort-Object FallbackCount -Descending
    }

    return $distribution
}

# ---------------------------------------------------------------------------
# Region: HTML report generation
# ---------------------------------------------------------------------------
function Build-HtmlReport {
    [CmdletBinding()]
    param(
        [object[]]$RODCResults,
        [object]$AggregateAnalysis,
        [object[]]$HubDistribution,
        [hashtable]$TopologyMap,
        [hashtable]$NetworkBaselines,
        [int]$Hours,
        [int]$LocalThreshold,
        [int]$HubThreshold
    )

    $reportDate = $script:RunTimestamp.ToString('yyyy-MM-dd HH:mm:ss')

    # Collect top outliers (up to 50) from aggregate analysis
    $topOutliers = @()
    if ($AggregateAnalysis.Outliers) {
        $topOutliers = $AggregateAnalysis.Outliers |
            Sort-Object LatencyMs -Descending |
            Select-Object -First 50
    }

    # Build RODC performance rows
    $rodcTableRows = ''
    foreach ($r in $RODCResults) {
        $rodcName   = $r.RODC
        $topology   = if ($TopologyMap.ContainsKey($rodcName)) { $TopologyMap[$rodcName] } else { $null }
        $site       = if ($topology) { $topology.Site } else { 'N/A' }
        $partnerDC  = if ($topology) { $topology.PrimaryPartnerDC } else { 'N/A' }
        $analysis   = $r.Analysis

        $networkRTT = 'N/A'
        if ($NetworkBaselines.ContainsKey($rodcName)) {
            $nb = $NetworkBaselines[$rodcName]
            if ($null -ne $nb.LDAP389_RTTms) {
                $networkRTT = "$($nb.LDAP389_RTTms)"
            }
        }

        $status = Get-LatencyStatus `
            -MedianLocal $analysis.LocalP50 `
            -MedianHub $analysis.HubP50 `
            -P95Local $analysis.LocalP95 `
            -P95Hub $analysis.HubP95 `
            -OutlierCount $analysis.OutlierCount `
            -LocalThreshold $LocalThreshold `
            -HubThreshold $HubThreshold

        $statusClass = switch ($status) {
            'Green'  { 'status-green' }
            'Yellow' { 'status-yellow' }
            'Red'    { 'status-red' }
        }

        $rodcTableRows += @"
                    <tr>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($rodcName))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($site))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($partnerDC))</td>
                        <td>$networkRTT</td>
                        <td>$($analysis.LocalP50)</td>
                        <td>$($analysis.HubP50)</td>
                        <td>$($analysis.LocalP95)</td>
                        <td>$($analysis.HubP95)</td>
                        <td>$($analysis.OutlierCount)</td>
                        <td><span class="badge $statusClass">$status</span></td>
                    </tr>
"@
    }

    # Build outlier rows
    $outlierRows = ''
    foreach ($o in $topOutliers) {
        $outlierRows += @"
                    <tr>
                        <td>$($o.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($o.Account))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($o.AuthType))</td>
                        <td>$($o.LatencyMs)</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($o.PotentialCause))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($o.Computer))</td>
                    </tr>
"@
    }

    if (-not $outlierRows) {
        $outlierRows = '<tr><td colspan="6" class="text-muted">No outliers detected in this time window.</td></tr>'
    }

    # Build hub distribution rows
    $hubDistRows = ''
    foreach ($h in $HubDistribution) {
        $hubDistRows += @"
                    <tr>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($h.HubDC))</td>
                        <td>$($h.FallbackCount)</td>
                        <td>$($h.AvgLatencyMs)</td>
                        <td>$($h.P95LatencyMs)</td>
                        <td>$($h.UniqueAccounts)</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($h.ServicingRODCs))</td>
                    </tr>
"@
    }

    if (-not $hubDistRows) {
        $hubDistRows = '<tr><td colspan="6" class="text-muted">No hub fallback transactions recorded.</td></tr>'
    }

    # Determine overall health
    $overallHealthClass = 'status-green'
    $overallHealthText  = 'Healthy'
    if ($AggregateAnalysis.LocalExceedThreshold -gt 0 -or $AggregateAnalysis.HubExceedThreshold -gt 0) {
        $overallHealthClass = 'status-yellow'
        $overallHealthText  = 'Warning'
    }
    if ($AggregateAnalysis.OutlierCount -gt 10 -or
        $AggregateAnalysis.LocalP95 -gt ($LocalThreshold * 2) -or
        $AggregateAnalysis.HubP95 -gt ($HubThreshold * 2)) {
        $overallHealthClass = 'status-red'
        $overallHealthText  = 'Critical'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RODC Authentication Performance Report</title>
    <style>
        /* --- Dark Theme --- */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: #0f1419;
            color: #e6edf3;
            line-height: 1.6;
            padding: 24px;
        }
        h1, h2, h3 { color: #e6edf3; margin-bottom: 12px; }
        h1 { font-size: 1.6em; border-bottom: 2px solid #58a6ff; padding-bottom: 8px; margin-bottom: 20px; }
        h2 { font-size: 1.3em; margin-top: 28px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }
        h3 { font-size: 1.1em; color: #8b949e; }
        p, li { color: #8b949e; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }

        .container { max-width: 1400px; margin: 0 auto; }

        .header {
            background-color: #1a2332;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px 24px;
            margin-bottom: 24px;
        }
        .header-meta { color: #8b949e; font-size: 0.85em; margin-top: 8px; }

        .card {
            background-color: #1e2d3d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px 24px;
            margin-bottom: 20px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }
        .summary-item {
            background-color: #1a2332;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }
        .summary-item .value {
            font-size: 1.8em;
            font-weight: 700;
            color: #e6edf3;
            display: block;
            margin-bottom: 4px;
        }
        .summary-item .label {
            font-size: 0.82em;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 0.9em;
        }
        th {
            background-color: #1a2332;
            color: #8b949e;
            text-transform: uppercase;
            font-size: 0.78em;
            letter-spacing: 0.5px;
            padding: 10px 12px;
            text-align: left;
            border-bottom: 2px solid #30363d;
            white-space: nowrap;
        }
        td {
            padding: 8px 12px;
            border-bottom: 1px solid #21262d;
            color: #e6edf3;
        }
        tr:hover { background-color: rgba(88, 166, 255, 0.04); }

        .badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.82em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }
        .status-green  { background-color: rgba(46, 160, 67, 0.15); color: #2ea043; border: 1px solid rgba(46, 160, 67, 0.3); }
        .status-yellow { background-color: rgba(210, 153, 34, 0.15); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.3); }
        .status-red    { background-color: rgba(248, 81, 73, 0.15); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.3); }
        .status-blue   { background-color: rgba(88, 166, 255, 0.15); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.3); }

        .text-muted { color: #484f58; font-style: italic; }
        .text-green  { color: #2ea043; }
        .text-yellow { color: #d29922; }
        .text-red    { color: #f85149; }
        .text-blue   { color: #58a6ff; }

        .limitations {
            background-color: rgba(210, 153, 34, 0.08);
            border: 1px solid rgba(210, 153, 34, 0.25);
            border-radius: 6px;
            padding: 16px 20px;
            margin-top: 20px;
        }
        .limitations h3 { color: #d29922; }
        .limitations li { color: #8b949e; margin-bottom: 6px; margin-left: 20px; }

        .footer {
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid #21262d;
            color: #484f58;
            font-size: 0.8em;
            text-align: center;
        }

        @media print {
            body { background: #fff; color: #000; }
            .card { border-color: #ccc; }
            th { background: #f0f0f0; color: #333; }
            td { color: #000; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RODC Authentication Performance Report</h1>
            <div class="header-meta">
                Generated: $reportDate |
                Time window: Last $Hours hours |
                Thresholds: Local &le; ${LocalThreshold}ms, Hub &le; ${HubThreshold}ms |
                Overall: <span class="badge $overallHealthClass">$overallHealthText</span>
            </div>
        </div>

        <!-- Section 1: Executive Summary -->
        <div class="card">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <span class="value">$($AggregateAnalysis.TotalTransactions)</span>
                    <span class="label">Total Auth Transactions</span>
                </div>
                <div class="summary-item">
                    <span class="value">$($AggregateAnalysis.LocalCount)</span>
                    <span class="label">Local (Cache Hit)</span>
                </div>
                <div class="summary-item">
                    <span class="value">$($AggregateAnalysis.HubCount)</span>
                    <span class="label">Hub Fallback</span>
                </div>
                <div class="summary-item">
                    <span class="value text-green">$($AggregateAnalysis.LocalP50) ms</span>
                    <span class="label">Median Local Latency</span>
                </div>
                <div class="summary-item">
                    <span class="value text-blue">$($AggregateAnalysis.HubP50) ms</span>
                    <span class="label">Median Hub Latency</span>
                </div>
                <div class="summary-item">
                    <span class="value text-yellow">$($AggregateAnalysis.LocalP95) ms</span>
                    <span class="label">P95 Local Latency</span>
                </div>
                <div class="summary-item">
                    <span class="value text-yellow">$($AggregateAnalysis.HubP95) ms</span>
                    <span class="label">P95 Hub Latency</span>
                </div>
                <div class="summary-item">
                    <span class="value text-red">$($AggregateAnalysis.LocalExceedThreshold)</span>
                    <span class="label">Exceeding Local Threshold</span>
                </div>
                <div class="summary-item">
                    <span class="value text-red">$($AggregateAnalysis.HubExceedThreshold)</span>
                    <span class="label">Exceeding Hub Threshold</span>
                </div>
            </div>
        </div>

        <!-- Section 2: RODC Performance Table -->
        <div class="card">
            <h2>RODC Performance</h2>
            <table>
                <thead>
                    <tr>
                        <th>RODC Name</th>
                        <th>Site</th>
                        <th>Primary Hub DC</th>
                        <th>RTT to Hub (ms)</th>
                        <th>Median Local (ms)</th>
                        <th>Median Hub (ms)</th>
                        <th>P95 Local (ms)</th>
                        <th>P95 Hub (ms)</th>
                        <th>Outliers</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
$rodcTableRows
                </tbody>
            </table>
        </div>

        <!-- Section 3: Top Latency Outliers -->
        <div class="card">
            <h2>Top Latency Outliers</h2>
            <p>Transactions exceeding 2 standard deviations from the mean latency for their auth type.</p>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Account</th>
                        <th>Auth Type</th>
                        <th>Latency (ms)</th>
                        <th>Potential Cause</th>
                        <th>RODC</th>
                    </tr>
                </thead>
                <tbody>
$outlierRows
                </tbody>
            </table>
        </div>

        <!-- Section 4: Hub DC Load Distribution -->
        <div class="card">
            <h2>Hub DC Load Distribution</h2>
            <p>Hub DCs handling fallback authentication requests and their associated latency.</p>
            <table>
                <thead>
                    <tr>
                        <th>Hub DC</th>
                        <th>Fallback Requests</th>
                        <th>Avg Latency (ms)</th>
                        <th>P95 Latency (ms)</th>
                        <th>Unique Accounts</th>
                        <th>Servicing RODCs</th>
                    </tr>
                </thead>
                <tbody>
$hubDistRows
                </tbody>
            </table>
        </div>

        <!-- Limitations -->
        <div class="limitations">
            <h3>Limitations and Notes</h3>
            <ul>
                <li>Security log timestamps have <strong>second</strong> granularity (not millisecond). All latency values are approximate inter-event timings, not true end-to-end measurements.</li>
                <li>This report does <strong>not</strong> measure client-to-RODC network latency. Only RODC-to-hub-DC timing is estimated.</li>
                <li>Network connectivity tests (when enabled) may be affected by firewall rules and do not represent sustained throughput.</li>
                <li>Transactions are grouped by account name within a $($script:TransactionWindowSeconds)-second sliding window. Overlapping sessions for the same account may be merged.</li>
                <li>P50/P95/P99 statistics require a meaningful sample size. Small event counts may produce unreliable percentiles.</li>
            </ul>
        </div>

        <div class="footer">
            RODC Authentication Performance Report v$($script:ScriptVersion) |
            Generated by Get-RODCAuthPerformance.ps1 |
            $reportDate
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

try {
    # Ensure System.Web is available for HtmlEncode
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    # Resolve RODC targets
    if (-not $RODCName -or $RODCName.Count -eq 0) {
        $RODCName = @($env:COMPUTERNAME)
        Write-Verbose "No RODCName specified; targeting local machine '$($env:COMPUTERNAME)'."
    }

    # Create output directory
    if (-not (Test-Path -Path $OutputPath -PathType Container)) {
        Write-Verbose "Creating output directory: $OutputPath"
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    # ---------------------------------------------------------------------------
    # Phase 1: Collect data from each RODC
    # ---------------------------------------------------------------------------
    Write-Verbose '=== Phase 1: Collecting authentication events ==='

    $allTransactions   = [System.Collections.ArrayList]::new()
    $rodcResults       = [System.Collections.ArrayList]::new()
    $topologyMap       = @{}
    $networkBaselines  = @{}

    foreach ($rodc in $RODCName) {
        Write-Verbose "Processing RODC: $rodc"

        # Collect events
        try {
            $authEvents = Get-AuthEvents -ComputerName $rodc -Hours $HoursBack
        }
        catch {
            Write-Warning "Failed to collect events from '$rodc': $($_.Exception.Message)"
            continue
        }

        $eventTotal = @($authEvents.TGTRequests).Count +
                      @($authEvents.ServiceTickets).Count +
                      @($authEvents.CredCacheEvents).Count

        Write-Verbose "[$rodc] Total raw events collected: $eventTotal"

        # Parse replication topology
        try {
            $topology = Get-ReplicationTopology -ComputerName $rodc
            $topologyMap[$rodc] = $topology
        }
        catch {
            Write-Warning "[$rodc] Could not retrieve replication topology: $($_.Exception.Message)"
            $topologyMap[$rodc] = [PSCustomObject]@{
                RODC             = $rodc
                Site             = 'Unknown'
                PrimaryPartnerDC = 'Unknown'
                SiteLinkCost     = 'N/A'
                LastReplResult   = 'N/A'
                LastReplTimestamp = $null
            }
        }

        # Optional network baseline
        if ($IncludeNetworkTest -and $topologyMap[$rodc].PrimaryPartnerDC -ne 'Unknown') {
            try {
                $baseline = Get-NetworkBaseline -SourceRODC $rodc -HubDC $topologyMap[$rodc].PrimaryPartnerDC
                $networkBaselines[$rodc] = $baseline
            }
            catch {
                Write-Warning "[$rodc] Network baseline test failed: $($_.Exception.Message)"
            }
        }

        # Build transactions
        $transactions = Build-AuthTransactions -AuthEvents $authEvents -ComputerName $rodc -WindowSeconds $script:TransactionWindowSeconds

        if ($transactions -and @($transactions).Count -gt 0) {
            foreach ($txn in $transactions) {
                [void]$allTransactions.Add($txn)
            }
        }
        else {
            $transactions = @()
        }

        # Per-RODC analysis
        $perRodcAnalysis = $null
        if (@($transactions).Count -gt 0) {
            $perRodcAnalysis = Get-TransactionAnalysis -Transactions $transactions `
                                                       -LocalThreshold $LocalLatencyThresholdMs `
                                                       -HubThreshold $HubLatencyThresholdMs
        }
        else {
            $perRodcAnalysis = [PSCustomObject]@{
                TotalTransactions    = 0
                LocalCount           = 0
                HubCount             = 0
                LocalP50             = 0; LocalP95 = 0; LocalP99 = 0; LocalMean = 0; LocalSD = 0
                HubP50               = 0; HubP95   = 0; HubP99   = 0; HubMean   = 0; HubSD   = 0
                LocalExceedThreshold = 0
                HubExceedThreshold   = 0
                OutlierCount         = 0
                Outliers             = @()
            }
        }

        [void]$rodcResults.Add([PSCustomObject]@{
            RODC         = $rodc
            Analysis     = $perRodcAnalysis
            Transactions = $transactions
        })
    }

    # ---------------------------------------------------------------------------
    # Phase 2: Aggregate analysis
    # ---------------------------------------------------------------------------
    Write-Verbose '=== Phase 2: Aggregate analysis ==='

    $aggregateAnalysis = $null
    if ($allTransactions.Count -gt 0) {
        $aggregateAnalysis = Get-TransactionAnalysis -Transactions $allTransactions.ToArray() `
                                                     -LocalThreshold $LocalLatencyThresholdMs `
                                                     -HubThreshold $HubLatencyThresholdMs
    }
    else {
        Write-Warning 'No authentication transactions were built. The report will show empty results.'
        $aggregateAnalysis = [PSCustomObject]@{
            TotalTransactions    = 0
            LocalCount           = 0
            HubCount             = 0
            LocalP50             = 0; LocalP95 = 0; LocalP99 = 0; LocalMean = 0; LocalSD = 0
            HubP50               = 0; HubP95   = 0; HubP99   = 0; HubMean   = 0; HubSD   = 0
            LocalExceedThreshold = 0
            HubExceedThreshold   = 0
            OutlierCount         = 0
            Outliers             = @()
        }
    }

    # Hub DC load distribution
    $hubDistribution = Get-HubDCLoadDistribution -AllTransactions $allTransactions.ToArray() -TopologyMap $topologyMap

    # ---------------------------------------------------------------------------
    # Phase 3: Generate outputs
    # ---------------------------------------------------------------------------
    Write-Verbose '=== Phase 3: Generating reports ==='

    $baseFileName = "RODCAuthPerformance_$($script:TimestampTag)"

    # --- HTML ---
    $htmlPath = Join-Path -Path $OutputPath -ChildPath "$baseFileName.html"
    Write-Verbose "Generating HTML report: $htmlPath"

    $htmlContent = Build-HtmlReport `
        -RODCResults $rodcResults.ToArray() `
        -AggregateAnalysis $aggregateAnalysis `
        -HubDistribution $hubDistribution `
        -TopologyMap $topologyMap `
        -NetworkBaselines $networkBaselines `
        -Hours $HoursBack `
        -LocalThreshold $LocalLatencyThresholdMs `
        -HubThreshold $HubLatencyThresholdMs

    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Verbose "HTML report written to: $htmlPath"

    # --- CSV ---
    $csvPath = Join-Path -Path $OutputPath -ChildPath "$baseFileName.csv"
    Write-Verbose "Generating CSV report: $csvPath"

    $csvRecords = [System.Collections.ArrayList]::new()
    foreach ($txn in $allTransactions) {
        [void]$csvRecords.Add([PSCustomObject]@{
            Timestamp     = $txn.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            Account       = $txn.Account
            AuthType      = $txn.AuthType
            LatencyMs     = $txn.LatencyMs
            Status        = $txn.Status
            ClientIP      = $txn.ClientIP
            EventCount    = $txn.EventCount
            RODC          = $txn.Computer
            HasCacheEvent = $txn.HasCacheEvent
            HasTGTEvent   = $txn.HasTGTEvent
            HasSvcEvent   = $txn.HasSvcEvent
        })
    }

    if ($csvRecords.Count -gt 0) {
        $csvRecords | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
    }
    else {
        # Write header-only CSV
        [PSCustomObject]@{
            Timestamp = ''; Account = ''; AuthType = ''; LatencyMs = ''
            Status = ''; ClientIP = ''; EventCount = ''; RODC = ''
            HasCacheEvent = ''; HasTGTEvent = ''; HasSvcEvent = ''
        } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
        # Remove the empty data row, keep header only
        $csvHeader = (Get-Content -Path $csvPath -TotalCount 1)
        $csvHeader | Out-File -FilePath $csvPath -Encoding UTF8 -Force
    }
    Write-Verbose "CSV report written to: $csvPath"

    # --- JSON ---
    $jsonPath = Join-Path -Path $OutputPath -ChildPath "$baseFileName.json"
    Write-Verbose "Generating JSON report: $jsonPath"

    $jsonPayload = [ordered]@{
        ReportMetadata = [ordered]@{
            GeneratedAt            = $script:RunTimestamp.ToString('o')
            ScriptVersion          = $script:ScriptVersion
            HoursBack              = $HoursBack
            LocalLatencyThresholdMs = $LocalLatencyThresholdMs
            HubLatencyThresholdMs  = $HubLatencyThresholdMs
            IncludeNetworkTest     = [bool]$IncludeNetworkTest
            TargetRODCs            = $RODCName
        }
        ExecutiveSummary = [ordered]@{
            TotalTransactions    = $aggregateAnalysis.TotalTransactions
            LocalCount           = $aggregateAnalysis.LocalCount
            HubCount             = $aggregateAnalysis.HubCount
            LocalLatency         = [ordered]@{
                P50  = $aggregateAnalysis.LocalP50
                P95  = $aggregateAnalysis.LocalP95
                P99  = $aggregateAnalysis.LocalP99
                Mean = $aggregateAnalysis.LocalMean
                SD   = $aggregateAnalysis.LocalSD
            }
            HubLatency           = [ordered]@{
                P50  = $aggregateAnalysis.HubP50
                P95  = $aggregateAnalysis.HubP95
                P99  = $aggregateAnalysis.HubP99
                Mean = $aggregateAnalysis.HubMean
                SD   = $aggregateAnalysis.HubSD
            }
            LocalExceedThreshold = $aggregateAnalysis.LocalExceedThreshold
            HubExceedThreshold   = $aggregateAnalysis.HubExceedThreshold
            OutlierCount         = $aggregateAnalysis.OutlierCount
        }
        RODCDetails = @(
            foreach ($r in $rodcResults) {
                $topo = if ($topologyMap.ContainsKey($r.RODC)) { $topologyMap[$r.RODC] } else { $null }
                $nb   = if ($networkBaselines.ContainsKey($r.RODC)) { $networkBaselines[$r.RODC] } else { $null }
                [ordered]@{
                    RODC             = $r.RODC
                    Site             = if ($topo) { $topo.Site } else { 'N/A' }
                    PrimaryPartnerDC = if ($topo) { $topo.PrimaryPartnerDC } else { 'N/A' }
                    NetworkBaseline  = if ($nb) {
                        [ordered]@{
                            LDAP389_RTTms = $nb.LDAP389_RTTms
                            LDAP389_Open  = $nb.LDAP389_Open
                            SMB445_RTTms  = $nb.SMB445_RTTms
                            SMB445_Open   = $nb.SMB445_Open
                        }
                    }
                    else { $null }
                    Analysis         = [ordered]@{
                        TotalTransactions    = $r.Analysis.TotalTransactions
                        LocalCount           = $r.Analysis.LocalCount
                        HubCount             = $r.Analysis.HubCount
                        LocalP50             = $r.Analysis.LocalP50
                        LocalP95             = $r.Analysis.LocalP95
                        LocalP99             = $r.Analysis.LocalP99
                        HubP50               = $r.Analysis.HubP50
                        HubP95               = $r.Analysis.HubP95
                        HubP99               = $r.Analysis.HubP99
                        OutlierCount         = $r.Analysis.OutlierCount
                        LocalExceedThreshold = $r.Analysis.LocalExceedThreshold
                        HubExceedThreshold   = $r.Analysis.HubExceedThreshold
                    }
                }
            }
        )
        HubDCLoadDistribution = @(
            foreach ($h in $hubDistribution) {
                [ordered]@{
                    HubDC          = $h.HubDC
                    FallbackCount  = $h.FallbackCount
                    AvgLatencyMs   = $h.AvgLatencyMs
                    P95LatencyMs   = $h.P95LatencyMs
                    UniqueAccounts = $h.UniqueAccounts
                    ServicingRODCs = $h.ServicingRODCs
                }
            }
        )
        Outliers = @(
            if ($aggregateAnalysis.Outliers) {
                foreach ($o in ($aggregateAnalysis.Outliers | Sort-Object LatencyMs -Descending | Select-Object -First 100)) {
                    [ordered]@{
                        Timestamp      = $o.Timestamp.ToString('o')
                        Account        = $o.Account
                        AuthType       = $o.AuthType
                        LatencyMs      = $o.LatencyMs
                        PotentialCause = $o.PotentialCause
                        RODC           = $o.Computer
                    }
                }
            }
        )
        Transactions = @(
            foreach ($txn in $allTransactions) {
                [ordered]@{
                    Timestamp     = $txn.Timestamp.ToString('o')
                    Account       = $txn.Account
                    AuthType      = $txn.AuthType
                    LatencyMs     = $txn.LatencyMs
                    Status        = $txn.Status
                    ClientIP      = $txn.ClientIP
                    EventCount    = $txn.EventCount
                    RODC          = $txn.Computer
                    HasCacheEvent = $txn.HasCacheEvent
                    HasTGTEvent   = $txn.HasTGTEvent
                    HasSvcEvent   = $txn.HasSvcEvent
                }
            }
        )
    }

    $jsonPayload | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
    Write-Verbose "JSON report written to: $jsonPath"

    # ---------------------------------------------------------------------------
    # Phase 4: Summary output
    # ---------------------------------------------------------------------------
    Write-Output ''
    Write-Output '======================================================'
    Write-Output '  RODC Authentication Performance Report — Summary'
    Write-Output '======================================================'
    Write-Output ''
    Write-Output "  Time window         : Last $HoursBack hours"
    Write-Output "  RODCs analysed      : $($RODCName -join ', ')"
    Write-Output "  Total transactions  : $($aggregateAnalysis.TotalTransactions)"
    Write-Output "  Local (cache hit)   : $($aggregateAnalysis.LocalCount)"
    Write-Output "  Hub fallback        : $($aggregateAnalysis.HubCount)"
    Write-Output ''
    Write-Output "  Median local latency  : $($aggregateAnalysis.LocalP50) ms"
    Write-Output "  Median hub latency    : $($aggregateAnalysis.HubP50) ms"
    Write-Output "  P95 local latency     : $($aggregateAnalysis.LocalP95) ms"
    Write-Output "  P95 hub latency       : $($aggregateAnalysis.HubP95) ms"
    Write-Output "  P99 local latency     : $($aggregateAnalysis.LocalP99) ms"
    Write-Output "  P99 hub latency       : $($aggregateAnalysis.HubP99) ms"
    Write-Output ''
    Write-Output "  Exceeding local threshold (${LocalLatencyThresholdMs}ms) : $($aggregateAnalysis.LocalExceedThreshold)"
    Write-Output "  Exceeding hub threshold (${HubLatencyThresholdMs}ms)   : $($aggregateAnalysis.HubExceedThreshold)"
    Write-Output "  Outliers (>2 SD)    : $($aggregateAnalysis.OutlierCount)"
    Write-Output ''
    Write-Output "  Reports written to  : $OutputPath"
    Write-Output "    HTML : $htmlPath"
    Write-Output "    CSV  : $csvPath"
    Write-Output "    JSON : $jsonPath"
    Write-Output ''
    Write-Output '======================================================'

}
catch {
    Write-Error "Get-RODCAuthPerformance encountered a fatal error: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    throw
}
