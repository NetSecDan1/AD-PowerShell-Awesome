#Requires -Version 5.1

<#
.SYNOPSIS
    Recommends accounts to add to RODC Password Replication Policy based on authentication usage patterns.

.DESCRIPTION
    Get-RODCPRPRecommendations.ps1 performs a read-only analysis of RODC authentication events
    (Event ID 4649) and current Password Replication Policy configuration to generate actionable
    recommendations for optimizing RODC password caching.

    The script collects authentication telemetry over a configurable time window, correlates it
    with current PRP allow/deny lists, evaluates account risk metadata (privileged group membership,
    service principal names, account type), and produces a scored recommendation report.

    Output is generated in three formats: a self-contained HTML report with dark-theme styling,
    a CSV file for spreadsheet analysis, and a JSON file for programmatic consumption.

    This script is strictly read-only. It does NOT modify any PRP groups, AD attributes, or
    group memberships. Implementation commands are provided in the report for manual review
    and execution after testing in a non-production environment.

.PARAMETER RODCName
    The name of a specific RODC to analyze. If omitted, all RODCs in the domain are analyzed.

.PARAMETER DaysBack
    The number of days to look back for authentication event analysis. Default is 7.

.PARAMETER MinRequestThreshold
    The minimum average requests per day an account must have to be recommended for the
    PRP allow list. Default is 10.

.PARAMETER ExcludePrivileged
    When set (default), accounts in privileged groups (Domain Admins, Enterprise Admins,
    Schema Admins, etc.) are excluded from allow-list recommendations and flagged as
    high-risk exclusions. Use -ExcludePrivileged:$false to include them (not recommended).

.PARAMETER OutputPath
    The directory where report files are written. Default is C:\Reports\RODC.
    The directory is created if it does not exist.

.EXAMPLE
    .\Get-RODCPRPRecommendations.ps1

    Analyzes all RODCs in the domain using default settings (7-day window, threshold of 10).

.EXAMPLE
    .\Get-RODCPRPRecommendations.ps1 -RODCName "RODC-BRANCH01" -DaysBack 14 -MinRequestThreshold 5

    Analyzes a specific RODC with a 14-day lookback and a lower request threshold.

.EXAMPLE
    .\Get-RODCPRPRecommendations.ps1 -OutputPath "D:\AuditReports" -Verbose

    Analyzes all RODCs with verbose output, writing reports to a custom path.

.NOTES
    Author  : Active Directory Reporting Team
    Version : 1.0.0
    Date    : 2026-02-08
    Requires: ActiveDirectory PowerShell module, Event log read access on target RODCs.
    Safety  : READ-ONLY. No AD modifications are performed.
#>

[CmdletBinding()]
param(
    [Parameter(
        HelpMessage = "Name of a specific RODC to analyze. Omit to analyze all RODCs."
    )]
    [ValidateNotNullOrEmpty()]
    [string]$RODCName,

    [Parameter(
        HelpMessage = "Number of days to look back for event analysis."
    )]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 7,

    [Parameter(
        HelpMessage = "Minimum average requests per day to recommend for PRP allow list."
    )]
    [ValidateRange(1, 10000)]
    [int]$MinRequestThreshold = 10,

    [Parameter(
        HelpMessage = "Exclude privileged accounts from allow-list recommendations."
    )]
    [bool]$ExcludePrivileged = $true,

    [Parameter(
        HelpMessage = "Output directory for report files."
    )]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "C:\Reports\RODC"
)

# ---------------------------------------------------------------------------
# Region: Initialization
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date
$script:Timestamp = $script:StartTime.ToString('yyyyMMdd_HHmmss')

# Privileged group list used for risk evaluation
$script:PrivilegedGroupNames = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Account Operators'
    'Server Operators'
    'Backup Operators'
    'Print Operators'
    'Cert Publishers'
    'Key Admins'
    'Enterprise Key Admins'
)

# Sensitive SPN service prefixes that flag service accounts as higher risk
$script:SensitiveSPNPrefixes = @(
    'MSSQL'
    'MSSQLSvc'
    'HTTP'
    'HTTPS'
    'exchangeMDB'
    'exchangeRFR'
    'exchangeAB'
    'SMTP'
    'ldap'
    'DNS'
    'FIMService'
)

Write-Verbose "Get-RODCPRPRecommendations started at $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Verbose "Parameters: DaysBack=$DaysBack, MinRequestThreshold=$MinRequestThreshold, ExcludePrivileged=$ExcludePrivileged"

# ---------------------------------------------------------------------------
# Region: Module and Environment Validation
# ---------------------------------------------------------------------------

function Test-Prerequisites {
    [CmdletBinding()]
    param()

    Write-Verbose "Validating prerequisites..."

    # Check for ActiveDirectory module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "The ActiveDirectory PowerShell module is not installed. Install RSAT or run from a Domain Controller."
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
        Write-Verbose "ActiveDirectory module imported successfully."
    }
    catch {
        throw "Failed to import ActiveDirectory module: $($_.Exception.Message)"
    }

    # Verify domain connectivity
    try {
        $script:DomainInfo = Get-ADDomain -ErrorAction Stop
        $script:ForestInfo = Get-ADForest -ErrorAction Stop
        Write-Verbose "Connected to domain: $($script:DomainInfo.DNSRoot)"
    }
    catch {
        throw "Cannot connect to Active Directory domain: $($_.Exception.Message)"
    }

    # Ensure output directory exists
    if (-not (Test-Path -Path $OutputPath -PathType Container)) {
        try {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created output directory: $OutputPath"
        }
        catch {
            throw "Cannot create output directory '$OutputPath': $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------------------
# Region: RODC Discovery
# ---------------------------------------------------------------------------

function Get-TargetRODCs {
    [CmdletBinding()]
    param()

    Write-Verbose "Discovering RODCs..."

    $rodcList = @()

    try {
        if ($RODCName) {
            Write-Verbose "Targeting specific RODC: $RODCName"
            $dc = Get-ADDomainController -Identity $RODCName -ErrorAction Stop
            if (-not $dc.IsReadOnly) {
                Write-Warning "'$RODCName' is not a Read-Only Domain Controller. Analyzing anyway, but PRP data may not be applicable."
            }
            $rodcList += $dc
        }
        else {
            $allDCs = Get-ADDomainController -Filter * -ErrorAction Stop
            $rodcList = @($allDCs | Where-Object { $_.IsReadOnly -eq $true })
            if ($rodcList.Count -eq 0) {
                Write-Warning "No RODCs found in the domain. The script will generate an empty report."
            }
            else {
                Write-Verbose "Found $($rodcList.Count) RODC(s): $($rodcList.Name -join ', ')"
            }
        }
    }
    catch {
        throw "Failed to discover RODCs: $($_.Exception.Message)"
    }

    return $rodcList
}

# ---------------------------------------------------------------------------
# Region: Event 4649 Collection
# ---------------------------------------------------------------------------

function Get-AuthenticationEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$RODCs
    )

    Write-Verbose "Collecting Event ID 4649 (RODC authentication requests) over the last $DaysBack day(s)..."

    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    $allEvents = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($rodc in $RODCs) {
        $rodcHostname = $rodc.HostName
        $rodcSite = $rodc.Site
        Write-Verbose "  Querying events on $rodcHostname (site: $rodcSite)..."

        try {
            $online = Test-Connection -ComputerName $rodc.Name -Count 1 -Quiet -ErrorAction SilentlyContinue
            if (-not $online) {
                Write-Warning "RODC '$($rodc.Name)' is not reachable. Skipping event collection."
                continue
            }

            $filterHash = @{
                LogName   = 'Security'
                Id        = 4649
                StartTime = $cutoffDate
            }

            $events = Get-WinEvent -ComputerName $rodc.Name -FilterHashtable $filterHash -ErrorAction SilentlyContinue

            if ($null -eq $events -or $events.Count -eq 0) {
                Write-Verbose "  No Event 4649 entries found on $($rodc.Name) in the specified window."
                continue
            }

            Write-Verbose "  Retrieved $($events.Count) event(s) from $($rodc.Name)."

            foreach ($evt in $events) {
                try {
                    $xml = [xml]$evt.ToXml()
                    $dataNodes = $xml.Event.EventData.Data

                    $accountName = ($dataNodes | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    $accountDomain = ($dataNodes | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'

                    if ([string]::IsNullOrWhiteSpace($accountName)) {
                        continue
                    }

                    $eventRecord = [PSCustomObject]@{
                        TimeCreated   = $evt.TimeCreated
                        RODCName      = $rodc.Name
                        RODCSite      = $rodcSite
                        AccountName   = $accountName
                        AccountDomain = $accountDomain
                        DayOfWeek     = $evt.TimeCreated.DayOfWeek.ToString()
                        HourOfDay     = $evt.TimeCreated.Hour
                    }

                    $allEvents.Add($eventRecord)
                }
                catch {
                    Write-Verbose "  Skipped malformed event record: $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Warning "Failed to query events on '$($rodc.Name)': $($_.Exception.Message)"
        }
    }

    Write-Verbose "Total authentication events collected: $($allEvents.Count)"
    return $allEvents
}

# ---------------------------------------------------------------------------
# Region: PRP Configuration Collection
# ---------------------------------------------------------------------------

function Get-PRPConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$RODCs
    )

    Write-Verbose "Collecting current PRP configuration from each RODC..."

    $prpData = @{}

    foreach ($rodc in $RODCs) {
        Write-Verbose "  Reading PRP for $($rodc.Name)..."

        $entry = @{
            RODCName     = $rodc.Name
            RODCSite     = $rodc.Site
            AllowList    = [System.Collections.Generic.List[string]]::new()
            DenyList     = [System.Collections.Generic.List[string]]::new()
            RevealedList = [System.Collections.Generic.List[string]]::new()
        }

        try {
            $rodcADObj = Get-ADDomainController -Identity $rodc.Name -ErrorAction Stop
            $rodcComputerDN = $rodcADObj.ComputerObjectDN

            $rodcComputer = Get-ADObject -Identity $rodcComputerDN -Properties `
                'msDS-RevealOnDemandGroup', 'msDS-NeverRevealGroup', 'msDS-RevealedList' -ErrorAction Stop

            # Allow list (msDS-RevealOnDemandGroup)
            $allowDNs = $rodcComputer.'msDS-RevealOnDemandGroup'
            if ($allowDNs) {
                foreach ($dn in $allowDNs) {
                    try {
                        $members = Get-ADGroupMember -Identity $dn -Recursive -ErrorAction SilentlyContinue
                        foreach ($m in $members) {
                            if (-not $entry.AllowList.Contains($m.SamAccountName)) {
                                $entry.AllowList.Add($m.SamAccountName)
                            }
                        }
                        # Also add the group DN itself for reference
                        $grpObj = Get-ADObject -Identity $dn -Properties SamAccountName -ErrorAction SilentlyContinue
                        if ($grpObj.SamAccountName -and -not $entry.AllowList.Contains($grpObj.SamAccountName)) {
                            $entry.AllowList.Add($grpObj.SamAccountName)
                        }
                    }
                    catch {
                        Write-Verbose "  Could not resolve allow-list entry '$dn': $($_.Exception.Message)"
                    }
                }
            }

            # Deny list (msDS-NeverRevealGroup)
            $denyDNs = $rodcComputer.'msDS-NeverRevealGroup'
            if ($denyDNs) {
                foreach ($dn in $denyDNs) {
                    try {
                        $members = Get-ADGroupMember -Identity $dn -Recursive -ErrorAction SilentlyContinue
                        foreach ($m in $members) {
                            if (-not $entry.DenyList.Contains($m.SamAccountName)) {
                                $entry.DenyList.Add($m.SamAccountName)
                            }
                        }
                        $grpObj = Get-ADObject -Identity $dn -Properties SamAccountName -ErrorAction SilentlyContinue
                        if ($grpObj.SamAccountName -and -not $entry.DenyList.Contains($grpObj.SamAccountName)) {
                            $entry.DenyList.Add($grpObj.SamAccountName)
                        }
                    }
                    catch {
                        Write-Verbose "  Could not resolve deny-list entry '$dn': $($_.Exception.Message)"
                    }
                }
            }

            # Revealed / cached list (msDS-RevealedList)
            $revealedDNs = $rodcComputer.'msDS-RevealedList'
            if ($revealedDNs) {
                foreach ($dn in $revealedDNs) {
                    try {
                        # msDS-RevealedList entries are in the format <prefix>:<DN>
                        $actualDN = $dn
                        if ($dn -match ':(.+)$') {
                            $actualDN = $Matches[1]
                        }
                        $obj = Get-ADObject -Identity $actualDN -Properties SamAccountName -ErrorAction SilentlyContinue
                        if ($obj.SamAccountName -and -not $entry.RevealedList.Contains($obj.SamAccountName)) {
                            $entry.RevealedList.Add($obj.SamAccountName)
                        }
                    }
                    catch {
                        Write-Verbose "  Could not resolve revealed-list entry '$dn': $($_.Exception.Message)"
                    }
                }
            }

            Write-Verbose "  $($rodc.Name): Allow=$($entry.AllowList.Count), Deny=$($entry.DenyList.Count), Cached=$($entry.RevealedList.Count)"
        }
        catch {
            Write-Warning "Failed to read PRP configuration for '$($rodc.Name)': $($_.Exception.Message)"
        }

        $prpData[$rodc.Name] = $entry
    }

    return $prpData
}

# ---------------------------------------------------------------------------
# Region: Account Risk Metadata
# ---------------------------------------------------------------------------

function Get-AccountRiskMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$AccountNames
    )

    Write-Verbose "Collecting risk metadata for $($AccountNames.Count) unique account(s)..."

    $metadata = @{}

    foreach ($acct in $AccountNames) {
        Write-Verbose "  Analyzing account: $acct"

        $info = [PSCustomObject]@{
            SamAccountName     = $acct
            DistinguishedName  = $null
            AccountType        = 'Unknown'
            ObjectClass        = $null
            Enabled            = $null
            PasswordLastSet    = $null
            AdminCount         = $null
            MemberOf           = @()
            IsPrivileged       = $false
            PrivilegedGroups   = @()
            SPNs               = @()
            HasSensitiveSPN    = $false
            SensitiveSPNList   = @()
        }

        try {
            # Try as user first, then computer, then general object
            $adObj = $null
            $properties = @(
                'SamAccountName', 'DistinguishedName', 'ObjectClass', 'Enabled',
                'PasswordLastSet', 'AdminCount', 'MemberOf', 'servicePrincipalName',
                'msDS-GroupManagedServiceAccount', 'objectCategory'
            )

            # Attempt user lookup
            try {
                $adObj = Get-ADUser -Identity $acct -Properties $properties -ErrorAction Stop
            }
            catch {
                # Attempt computer lookup
                try {
                    $adObj = Get-ADComputer -Identity $acct -Properties $properties -ErrorAction Stop
                }
                catch {
                    # Attempt generic object lookup
                    try {
                        $adObj = Get-ADObject -Filter "SamAccountName -eq '$acct'" -Properties $properties -ErrorAction Stop |
                            Select-Object -First 1
                    }
                    catch {
                        Write-Verbose "  Could not resolve account '$acct' in AD."
                    }
                }
            }

            if ($null -ne $adObj) {
                $info.DistinguishedName = $adObj.DistinguishedName
                $info.ObjectClass = $adObj.ObjectClass
                $info.Enabled = $adObj.Enabled
                $info.PasswordLastSet = $adObj.PasswordLastSet
                $info.AdminCount = $adObj.AdminCount

                # Determine account type
                $objClass = $adObj.ObjectClass
                if ($objClass -is [array]) { $objClass = $objClass[-1] }

                if ($adObj.DistinguishedName -match 'CN=Managed Service Accounts' -or
                    $objClass -eq 'msDS-GroupManagedServiceAccount') {
                    $info.AccountType = 'gMSA'
                }
                elseif ($objClass -eq 'computer') {
                    $info.AccountType = 'Computer'
                }
                elseif ($objClass -eq 'user') {
                    $info.AccountType = 'User'
                }
                else {
                    $info.AccountType = $objClass
                }

                # Group membership and privilege check
                $memberOfDNs = @($adObj.MemberOf)
                $info.MemberOf = $memberOfDNs

                foreach ($groupDN in $memberOfDNs) {
                    try {
                        $grp = Get-ADGroup -Identity $groupDN -ErrorAction SilentlyContinue
                        if ($grp.Name -in $script:PrivilegedGroupNames) {
                            $info.IsPrivileged = $true
                            $info.PrivilegedGroups += $grp.Name
                        }
                    }
                    catch {
                        # Fallback: check by DN pattern
                        foreach ($pg in $script:PrivilegedGroupNames) {
                            if ($groupDN -match "CN=$([regex]::Escape($pg)),") {
                                $info.IsPrivileged = $true
                                $info.PrivilegedGroups += $pg
                            }
                        }
                    }
                }

                # Also flag if AdminCount is 1
                if ($adObj.AdminCount -eq 1) {
                    $info.IsPrivileged = $true
                }

                # SPN analysis
                $spns = @($adObj.servicePrincipalName)
                $info.SPNs = $spns

                foreach ($spn in $spns) {
                    $svcPrefix = ($spn -split '/')[0]
                    if ($svcPrefix -in $script:SensitiveSPNPrefixes) {
                        $info.HasSensitiveSPN = $true
                        $info.SensitiveSPNList += $spn
                    }
                }
            }
        }
        catch {
            Write-Verbose "  Error processing account '$acct': $($_.Exception.Message)"
        }

        $metadata[$acct] = $info
    }

    return $metadata
}

# ---------------------------------------------------------------------------
# Region: Usage Pattern Analysis
# ---------------------------------------------------------------------------

function Get-UsagePatterns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Events
    )

    Write-Verbose "Analyzing usage patterns..."

    $patterns = @{}

    if ($Events.Count -eq 0) {
        return $patterns
    }

    $grouped = $Events | Group-Object -Property AccountName

    foreach ($group in $grouped) {
        $acctName = $group.Name
        $acctEvents = $group.Group

        $rodcBreakdown = $acctEvents | Group-Object -Property RODCName
        $siteBreakdown = $acctEvents | Group-Object -Property RODCSite

        $totalRequests = $acctEvents.Count
        $avgPerDay = [math]::Round($totalRequests / $DaysBack, 2)

        # Pattern detection
        $businessHourEvents = @($acctEvents | Where-Object { $_.HourOfDay -ge 8 -and $_.HourOfDay -le 18 })
        $offHourEvents = @($acctEvents | Where-Object { $_.HourOfDay -lt 8 -or $_.HourOfDay -gt 18 })
        $weekendEvents = @($acctEvents | Where-Object { $_.DayOfWeek -in @('Saturday', 'Sunday') })
        $weekdayEvents = @($acctEvents | Where-Object { $_.DayOfWeek -notin @('Saturday', 'Sunday') })

        $pattern = 'Unknown'
        $businessHourRatio = if ($totalRequests -gt 0) { $businessHourEvents.Count / $totalRequests } else { 0 }
        $weekendRatio = if ($totalRequests -gt 0) { $weekendEvents.Count / $totalRequests } else { 0 }

        if ($businessHourRatio -ge 0.80) {
            $pattern = 'Business Hours Only'
        }
        elseif ($weekendRatio -ge 0.40) {
            $pattern = 'Weekend Spikes'
        }
        elseif ($offHourEvents.Count -gt 0 -and $businessHourEvents.Count -gt 0) {
            $pattern = '24/7'
        }
        elseif ($businessHourEvents.Count -gt 0) {
            $pattern = 'Primarily Business Hours'
        }
        else {
            $pattern = 'Off-Hours Only'
        }

        $rodcDetails = @{}
        foreach ($rb in $rodcBreakdown) {
            $rodcDetails[$rb.Name] = @{
                RequestCount = $rb.Count
                AvgPerDay    = [math]::Round($rb.Count / $DaysBack, 2)
            }
        }

        $siteNames = @($siteBreakdown | ForEach-Object { $_.Name } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        $patterns[$acctName] = [PSCustomObject]@{
            AccountName       = $acctName
            TotalRequests     = $totalRequests
            AvgRequestsPerDay = $avgPerDay
            RODCCount         = $rodcBreakdown.Count
            RODCDetails       = $rodcDetails
            SiteCount         = $siteNames.Count
            Sites             = $siteNames -join ', '
            Pattern           = $pattern
            BusinessHourPct   = [math]::Round($businessHourRatio * 100, 1)
            WeekendPct        = [math]::Round($weekendRatio * 100, 1)
        }
    }

    return $patterns
}

# ---------------------------------------------------------------------------
# Region: Recommendation Engine
# ---------------------------------------------------------------------------

function Build-Recommendations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$UsagePatterns,

        [Parameter(Mandatory)]
        [hashtable]$AccountMetadata,

        [Parameter(Mandatory)]
        [hashtable]$PRPConfig
    )

    Write-Verbose "Building recommendations..."

    $recommendations = [System.Collections.Generic.List[PSObject]]::new()
    $conflicts = [System.Collections.Generic.List[PSObject]]::new()

    # Build aggregated PRP state across all RODCs
    $globalAllowSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $globalDenySet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $globalCachedSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($key in $PRPConfig.Keys) {
        $prp = $PRPConfig[$key]
        foreach ($a in $prp.AllowList) { [void]$globalAllowSet.Add($a) }
        foreach ($d in $prp.DenyList) { [void]$globalDenySet.Add($d) }
        foreach ($c in $prp.RevealedList) { [void]$globalCachedSet.Add($c) }
    }

    # Detect conflicts: accounts in both allow and deny lists
    foreach ($acct in $globalAllowSet) {
        if ($globalDenySet.Contains($acct)) {
            $conflicts.Add([PSCustomObject]@{
                Type        = 'Allow/Deny Conflict'
                AccountName = $acct
                Description = "Account '$acct' appears in both the PRP allow list and deny list. The deny list takes precedence."
                Severity    = 'Warning'
            })
        }
    }

    foreach ($acctName in $UsagePatterns.Keys) {
        $usage = $UsagePatterns[$acctName]
        $meta = $AccountMetadata[$acctName]

        $recommendation = 'No Action'
        $reason = ''
        $riskLevel = 'Low'
        $riskScore = 0

        # ---- Risk scoring ----
        # Account type factor
        switch ($meta.AccountType) {
            'User'     { $riskScore += 0 }
            'Computer' { $riskScore += 10 }
            'gMSA'     { $riskScore += 10 }
            default    { $riskScore += 5 }
        }

        # Request volume factor
        if ($usage.AvgRequestsPerDay -gt 200) {
            $riskScore += 30
        }
        elseif ($usage.AvgRequestsPerDay -ge 50) {
            $riskScore += 15
        }

        # Multi-site factor
        if ($usage.SiteCount -ge 3) {
            $riskScore += 30
        }
        elseif ($usage.SiteCount -eq 2) {
            $riskScore += 10
        }

        # Privilege factor
        if ($meta.IsPrivileged) {
            $riskScore += 50
        }

        # Sensitive SPN factor
        if ($meta.HasSensitiveSPN) {
            $riskScore += 20
        }

        # Determine risk level from score
        if ($riskScore -ge 50) {
            $riskLevel = 'High'
        }
        elseif ($riskScore -ge 20) {
            $riskLevel = 'Medium'
        }
        else {
            $riskLevel = 'Low'
        }

        # ---- Determine PRP status ----
        $prpStatus = 'Not Configured'
        if ($globalCachedSet.Contains($acctName)) {
            $prpStatus = 'Cached (Revealed)'
        }
        elseif ($globalAllowSet.Contains($acctName)) {
            $prpStatus = 'In Allow List'
        }

        if ($globalDenySet.Contains($acctName)) {
            $prpStatus = 'In Deny List'
        }

        # ---- Recommendation logic ----

        # FLAG: privileged accounts with high request volume
        if ($meta.IsPrivileged -and $usage.AvgRequestsPerDay -ge $MinRequestThreshold) {
            $recommendation = 'Exclude (High-Risk)'
            $reason = "Privileged account (groups: $($meta.PrivilegedGroups -join ', ')). High request volume ($($usage.AvgRequestsPerDay)/day) indicates dependency but caching is a security risk."

            $conflicts.Add([PSCustomObject]@{
                Type        = 'Privileged High Volume'
                AccountName = $acctName
                Description = "Privileged account '$acctName' has $($usage.AvgRequestsPerDay) avg requests/day. Review authentication architecture."
                Severity    = 'Critical'
            })
        }
        # FLAG: sensitive SPN service accounts
        elseif ($meta.HasSensitiveSPN) {
            $recommendation = 'Exclude (High-Risk)'
            $reason = "Service account with sensitive SPNs ($($meta.SensitiveSPNList -join ', ')). Caching credentials on RODC increases attack surface."

            if ($usage.AvgRequestsPerDay -ge $MinRequestThreshold) {
                $conflicts.Add([PSCustomObject]@{
                    Type        = 'Sensitive Service Account'
                    AccountName = $acctName
                    Description = "Sensitive service account '$acctName' (SPNs: $($meta.SensitiveSPNList -join ', ')) has $($usage.AvgRequestsPerDay) avg requests/day across $($usage.RODCCount) RODC(s)."
                    Severity    = 'Warning'
                })
            }
        }
        # FLAG: centralized strategy needed
        elseif ($usage.SiteCount -gt 3) {
            $recommendation = 'Centralized Strategy'
            $reason = "Account authenticates across $($usage.SiteCount) sites ($($usage.Sites)). Consider dedicated service RODC or hub-based authentication instead of per-RODC PRP."

            $conflicts.Add([PSCustomObject]@{
                Type        = 'Multi-Site Service Account'
                AccountName = $acctName
                Description = "Account '$acctName' hits $($usage.RODCCount) RODCs across $($usage.SiteCount) sites. Evaluate centralized caching strategy."
                Severity    = 'Info'
            })
        }
        # RECOMMEND for allow list
        elseif ($usage.AvgRequestsPerDay -ge $MinRequestThreshold) {
            if ($globalDenySet.Contains($acctName)) {
                $recommendation = 'Review Deny List'
                $reason = "Account meets request threshold ($($usage.AvgRequestsPerDay)/day) but is in the deny list. Review if denial is still appropriate."
            }
            elseif ($globalCachedSet.Contains($acctName)) {
                $recommendation = 'Already Cached'
                $reason = "Account is already cached on RODC. No action needed."
            }
            elseif ($ExcludePrivileged -and $meta.IsPrivileged) {
                $recommendation = 'Exclude (Privileged)'
                $reason = "Account meets request threshold but is in privileged groups ($($meta.PrivilegedGroups -join ', ')). Excluded by policy."
            }
            elseif ($meta.AdminCount -eq 1 -and $ExcludePrivileged) {
                $recommendation = 'Exclude (AdminCount)'
                $reason = "Account has AdminCount=1, indicating current or former privileged status. Review before allowing."
            }
            else {
                $recommendation = 'Add to Allow List'
                $reason = "Account has $($usage.AvgRequestsPerDay) avg requests/day (threshold: $MinRequestThreshold). Pattern: $($usage.Pattern). Adding to PRP will reduce hub DC fallback latency."
            }
        }
        else {
            $recommendation = 'Below Threshold'
            $reason = "Average requests/day ($($usage.AvgRequestsPerDay)) is below the threshold of $MinRequestThreshold."
        }

        # Impact score: requests/day weighted by a notional hub latency penalty (50ms per fallback)
        $impactScore = [math]::Round($usage.AvgRequestsPerDay * 50, 0)

        $recommendations.Add([PSCustomObject]@{
            AccountName       = $acctName
            AccountType       = $meta.AccountType
            AvgRequestsPerDay = $usage.AvgRequestsPerDay
            TotalRequests     = $usage.TotalRequests
            RODCCount         = $usage.RODCCount
            SiteCount         = $usage.SiteCount
            Sites             = $usage.Sites
            Pattern           = $usage.Pattern
            PRPStatus         = $prpStatus
            RiskLevel         = $riskLevel
            RiskScore         = $riskScore
            Recommendation    = $recommendation
            Reason            = $reason
            ImpactScore       = $impactScore
            IsPrivileged      = $meta.IsPrivileged
            PrivilegedGroups  = ($meta.PrivilegedGroups -join ', ')
            HasSensitiveSPN   = $meta.HasSensitiveSPN
            SensitiveSPNs     = ($meta.SensitiveSPNList -join ', ')
            PasswordLastSet   = $meta.PasswordLastSet
            AdminCount        = $meta.AdminCount
        })
    }

    # Sort recommendations by impact score descending
    $sortedRecommendations = $recommendations | Sort-Object -Property ImpactScore -Descending

    # Assign rank
    $rank = 1
    foreach ($rec in $sortedRecommendations) {
        $rec | Add-Member -NotePropertyName 'Rank' -NotePropertyValue $rank -Force
        $rank++
    }

    return @{
        Recommendations = $sortedRecommendations
        Conflicts       = $conflicts
    }
}

# ---------------------------------------------------------------------------
# Region: HTML Report Generation
# ---------------------------------------------------------------------------

function Build-HTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Recommendations,

        [Parameter(Mandatory)]
        [object[]]$Conflicts,

        [Parameter(Mandatory)]
        [object[]]$RODCs,

        [Parameter(Mandatory)]
        [hashtable]$PRPConfig
    )

    Write-Verbose "Generating HTML report..."

    # Executive summary calculations
    $totalAnalyzed = $Recommendations.Count
    $recommendedAdditions = @($Recommendations | Where-Object { $_.Recommendation -eq 'Add to Allow List' })
    $highRiskExclusions = @($Recommendations | Where-Object { $_.Recommendation -like 'Exclude*' })
    $alreadyCached = @($Recommendations | Where-Object { $_.Recommendation -eq 'Already Cached' })
    $centralizedStrategy = @($Recommendations | Where-Object { $_.Recommendation -eq 'Centralized Strategy' })
    $belowThreshold = @($Recommendations | Where-Object { $_.Recommendation -eq 'Below Threshold' })

    # Estimate hub fallback reduction
    $totalCurrentFallbackRequests = ($Recommendations |
        Where-Object { $_.PRPStatus -notin @('Cached (Revealed)', 'In Allow List') } |
        Measure-Object -Property TotalRequests -Sum).Sum

    $recommendedFallbackReduction = ($recommendedAdditions |
        Measure-Object -Property TotalRequests -Sum).Sum

    $fallbackReductionPct = if ($totalCurrentFallbackRequests -gt 0) {
        [math]::Round(($recommendedFallbackReduction / $totalCurrentFallbackRequests) * 100, 1)
    } else { 0 }

    # Build implementation commands
    $implCommands = [System.Text.StringBuilder]::new()
    foreach ($rec in $recommendedAdditions) {
        [void]$implCommands.AppendLine("# Add $($rec.AccountName) to PRP Allow Group for applicable RODC(s)")
        [void]$implCommands.AppendLine("# Risk Level: $($rec.RiskLevel) | Avg Requests/Day: $($rec.AvgRequestsPerDay)")
        [void]$implCommands.AppendLine("Get-ADDomainController -Filter { IsReadOnly -eq `$true } | ForEach-Object {")
        [void]$implCommands.AppendLine("    # Replace 'Allowed RODC Password Replication Group' with your actual PRP allow group if different")
        [void]$implCommands.AppendLine("    Add-ADGroupMember -Identity 'Allowed RODC Password Replication Group' -Members '$($rec.AccountName)' -WhatIf")
        [void]$implCommands.AppendLine("}")
        [void]$implCommands.AppendLine("")
    }

    # Build Recommendations table rows
    $recRows = [System.Text.StringBuilder]::new()
    foreach ($rec in $Recommendations) {
        $riskClass = switch ($rec.RiskLevel) {
            'Low'    { 'status-pass' }
            'Medium' { 'status-warn' }
            'High'   { 'status-fail' }
            default  { 'status-info' }
        }

        $recClass = switch -Wildcard ($rec.Recommendation) {
            'Add to Allow List'   { 'status-pass' }
            'Already Cached'      { 'status-info' }
            'Exclude*'            { 'status-fail' }
            'Centralized*'        { 'status-warn' }
            'Review*'             { 'status-warn' }
            'Below Threshold'     { 'status-secondary' }
            default               { '' }
        }

        [void]$recRows.AppendLine("<tr>")
        [void]$recRows.AppendLine("  <td>$($rec.Rank)</td>")
        [void]$recRows.AppendLine("  <td><strong>$([System.Web.HttpUtility]::HtmlEncode($rec.AccountName))</strong></td>")
        [void]$recRows.AppendLine("  <td>$([System.Web.HttpUtility]::HtmlEncode($rec.AccountType))</td>")
        [void]$recRows.AppendLine("  <td>$($rec.AvgRequestsPerDay)</td>")
        [void]$recRows.AppendLine("  <td>$($rec.SiteCount)</td>")
        [void]$recRows.AppendLine("  <td>$([System.Web.HttpUtility]::HtmlEncode($rec.PRPStatus))</td>")
        [void]$recRows.AppendLine("  <td><span class=`"badge $riskClass`">$($rec.RiskLevel)</span></td>")
        [void]$recRows.AppendLine("  <td><span class=`"badge $recClass`">$([System.Web.HttpUtility]::HtmlEncode($rec.Recommendation))</span></td>")
        [void]$recRows.AppendLine("  <td class=`"reason-cell`">$([System.Web.HttpUtility]::HtmlEncode($rec.Reason))</td>")
        [void]$recRows.AppendLine("</tr>")
    }

    # Build Conflicts table rows
    $conflictRows = [System.Text.StringBuilder]::new()
    foreach ($c in $Conflicts) {
        $sevClass = switch ($c.Severity) {
            'Critical' { 'status-fail' }
            'Warning'  { 'status-warn' }
            'Info'     { 'status-info' }
            default    { '' }
        }

        [void]$conflictRows.AppendLine("<tr>")
        [void]$conflictRows.AppendLine("  <td><span class=`"badge $sevClass`">$([System.Web.HttpUtility]::HtmlEncode($c.Severity))</span></td>")
        [void]$conflictRows.AppendLine("  <td>$([System.Web.HttpUtility]::HtmlEncode($c.Type))</td>")
        [void]$conflictRows.AppendLine("  <td><strong>$([System.Web.HttpUtility]::HtmlEncode($c.AccountName))</strong></td>")
        [void]$conflictRows.AppendLine("  <td>$([System.Web.HttpUtility]::HtmlEncode($c.Description))</td>")
        [void]$conflictRows.AppendLine("</tr>")
    }

    $conflictSection = if ($Conflicts.Count -gt 0) {
        @"
        <div class="card">
            <h2>Conflicts &amp; Warnings</h2>
            <p class="text-secondary">Issues requiring manual review before implementing recommendations.</p>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Account</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        $($conflictRows.ToString())
                    </tbody>
                </table>
            </div>
        </div>
"@
    }
    else {
        @"
        <div class="card">
            <h2>Conflicts &amp; Warnings</h2>
            <p class="text-secondary">No conflicts or warnings detected.</p>
        </div>
"@
    }

    $noDataNotice = if ($Recommendations.Count -eq 0) {
        '<div class="card"><p class="text-secondary" style="text-align:center;padding:2rem;">No authentication events (Event ID 4649) were found in the specified time window. Ensure auditing is enabled on the target RODCs and try increasing the -DaysBack parameter.</p></div>'
    }
    else { '' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RODC PRP Recommendations - $($script:Timestamp)</title>
    <style>
        /* ---- Reset & Base ---- */
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: #0f1419;
            color: #e6edf3;
            line-height: 1.6;
            padding: 0;
            margin: 0;
        }

        /* ---- Layout ---- */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }

        header {
            background: linear-gradient(135deg, #1a2332 0%, #1e2d3d 100%);
            border-bottom: 1px solid #30363d;
            padding: 2rem 1.5rem;
        }

        header h1 {
            font-size: 1.75rem;
            font-weight: 600;
            color: #e6edf3;
        }

        header p {
            color: #8b949e;
            margin-top: 0.25rem;
            font-size: 0.95rem;
        }

        .meta-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 1.5rem;
            margin-top: 1rem;
            font-size: 0.85rem;
            color: #8b949e;
        }

        .meta-bar span { display: inline-flex; align-items: center; gap: 0.35rem; }

        /* ---- Cards ---- */
        .card {
            background-color: #1e2d3d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .card h2 {
            font-size: 1.25rem;
            font-weight: 600;
            color: #e6edf3;
            margin-bottom: 0.75rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #30363d;
        }

        /* ---- Summary Grid ---- */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .summary-item {
            background-color: #1a2332;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem;
            text-align: center;
        }

        .summary-item .value {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1.2;
        }

        .summary-item .label {
            color: #8b949e;
            font-size: 0.85rem;
            margin-top: 0.25rem;
        }

        .value-green  { color: #2ea043; }
        .value-yellow { color: #d29922; }
        .value-red    { color: #f85149; }
        .value-blue   { color: #58a6ff; }

        /* ---- Tables ---- */
        .table-wrapper {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }

        thead th {
            background-color: #1a2332;
            color: #8b949e;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 2px solid #30363d;
            position: sticky;
            top: 0;
            white-space: nowrap;
        }

        tbody td {
            padding: 0.65rem 1rem;
            border-bottom: 1px solid #21262d;
            color: #e6edf3;
            vertical-align: top;
        }

        tbody tr:hover { background-color: rgba(88, 166, 255, 0.04); }

        .reason-cell {
            max-width: 350px;
            font-size: 0.8rem;
            color: #8b949e;
        }

        /* ---- Badges ---- */
        .badge {
            display: inline-block;
            padding: 0.2em 0.65em;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            white-space: nowrap;
        }

        .status-pass { background-color: rgba(46, 160, 67, 0.15); color: #2ea043; border: 1px solid rgba(46, 160, 67, 0.3); }
        .status-warn { background-color: rgba(210, 153, 34, 0.15); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.3); }
        .status-fail { background-color: rgba(248, 81, 73, 0.15); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.3); }
        .status-info { background-color: rgba(88, 166, 255, 0.15); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.3); }
        .status-secondary { background-color: rgba(139, 148, 158, 0.10); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.2); }

        /* ---- Code Block ---- */
        .code-block {
            background-color: #0f1419;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1rem 1.25rem;
            font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
            font-size: 0.8rem;
            line-height: 1.7;
            overflow-x: auto;
            white-space: pre;
            color: #e6edf3;
            max-height: 500px;
            overflow-y: auto;
        }

        .warning-banner {
            background-color: rgba(210, 153, 34, 0.12);
            border: 1px solid rgba(210, 153, 34, 0.4);
            border-radius: 6px;
            padding: 0.85rem 1.25rem;
            margin-bottom: 1rem;
            color: #d29922;
            font-weight: 500;
            font-size: 0.9rem;
        }

        .text-secondary { color: #8b949e; }

        footer {
            text-align: center;
            color: #484f58;
            font-size: 0.8rem;
            padding: 2rem 0;
            border-top: 1px solid #21262d;
            margin-top: 2rem;
        }

        /* ---- Responsive ---- */
        @media (max-width: 768px) {
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            header h1 { font-size: 1.35rem; }
            .container { padding: 1rem; }
        }
    </style>
</head>
<body>

<header>
    <div class="container" style="padding-top:0;padding-bottom:0;">
        <h1>RODC Password Replication Policy Recommendations</h1>
        <p>Automated analysis of authentication patterns and PRP optimization opportunities</p>
        <div class="meta-bar">
            <span>Domain: <strong>$([System.Web.HttpUtility]::HtmlEncode($script:DomainInfo.DNSRoot))</strong></span>
            <span>Analysis Window: <strong>$DaysBack day(s)</strong></span>
            <span>RODCs Analyzed: <strong>$($RODCs.Count)</strong></span>
            <span>Min Threshold: <strong>$MinRequestThreshold req/day</strong></span>
            <span>Generated: <strong>$($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC</strong></span>
        </div>
    </div>
</header>

<div class="container">

    <!-- Executive Summary -->
    <div class="card">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="value value-blue">$totalAnalyzed</div>
                <div class="label">Unique Accounts Analyzed</div>
            </div>
            <div class="summary-item">
                <div class="value value-green">$($recommendedAdditions.Count)</div>
                <div class="label">Recommended Additions</div>
            </div>
            <div class="summary-item">
                <div class="value value-red">$($highRiskExclusions.Count)</div>
                <div class="label">High-Risk Exclusions</div>
            </div>
            <div class="summary-item">
                <div class="value value-yellow">$($centralizedStrategy.Count)</div>
                <div class="label">Centralized Strategy</div>
            </div>
            <div class="summary-item">
                <div class="value value-blue">$($alreadyCached.Count)</div>
                <div class="label">Already Cached</div>
            </div>
            <div class="summary-item">
                <div class="value value-green">$fallbackReductionPct%</div>
                <div class="label">Est. Hub Fallback Reduction</div>
            </div>
        </div>
    </div>

    $noDataNotice

    <!-- Recommendations Table -->
    <div class="card">
        <h2>Recommendations</h2>
        <p class="text-secondary" style="margin-bottom:1rem;">Ranked by estimated impact (requests/day &times; hub latency penalty). Higher impact accounts benefit most from local caching.</p>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Account Name</th>
                        <th>Account Type</th>
                        <th>Req/Day (Avg)</th>
                        <th>Sites</th>
                        <th>PRP Status</th>
                        <th>Risk Level</th>
                        <th>Recommendation</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>
                    $($recRows.ToString())
                </tbody>
            </table>
        </div>
    </div>

    <!-- Conflicts & Warnings -->
    $conflictSection

    <!-- Implementation Commands -->
    <div class="card">
        <h2>Implementation Commands</h2>
        <div class="warning-banner">
            WARNING: Test all changes in a non-production environment first. Review each recommendation before execution. Remove the -WhatIf parameter only after thorough validation.
        </div>
        <div class="code-block">$([System.Web.HttpUtility]::HtmlEncode($implCommands.ToString()))</div>
    </div>

</div>

<footer>
    RODC PRP Recommendations Report &mdash; Generated $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) &mdash; Read-Only Analysis &mdash; No AD Modifications Made
</footer>

</body>
</html>
"@

    return $html
}

# ---------------------------------------------------------------------------
# Region: Export Functions
# ---------------------------------------------------------------------------

function Export-Reports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HTML,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Recommendations,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Conflicts,

        [Parameter(Mandatory)]
        [hashtable]$PRPConfig
    )

    $baseName = "RODC_PRP_Recommendations_$($script:Timestamp)"

    # ---- HTML ----
    $htmlPath = Join-Path -Path $OutputPath -ChildPath "$baseName.html"
    try {
        $HTML | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
        Write-Verbose "HTML report saved: $htmlPath"
    }
    catch {
        Write-Warning "Failed to write HTML report to '$htmlPath': $($_.Exception.Message)"
    }

    # ---- CSV ----
    $csvPath = Join-Path -Path $OutputPath -ChildPath "$baseName.csv"
    try {
        $csvData = $Recommendations | Select-Object `
            Rank, AccountName, AccountType, AvgRequestsPerDay, TotalRequests,
            RODCCount, SiteCount, Sites, Pattern, PRPStatus, RiskLevel, RiskScore,
            Recommendation, Reason, ImpactScore, IsPrivileged, PrivilegedGroups,
            HasSensitiveSPN, SensitiveSPNs, PasswordLastSet, AdminCount

        $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Verbose "CSV report saved: $csvPath"
    }
    catch {
        Write-Warning "Failed to write CSV report to '$csvPath': $($_.Exception.Message)"
    }

    # ---- JSON ----
    $jsonPath = Join-Path -Path $OutputPath -ChildPath "$baseName.json"
    try {
        $jsonPayload = [ordered]@{
            ReportMetadata     = [ordered]@{
                GeneratedAt          = $script:StartTime.ToString('o')
                Domain               = $script:DomainInfo.DNSRoot
                DaysBack             = $DaysBack
                MinRequestThreshold  = $MinRequestThreshold
                ExcludePrivileged    = $ExcludePrivileged
                RODCsAnalyzed        = @($script:TargetRODCs | ForEach-Object { $_.Name })
            }
            ExecutiveSummary   = [ordered]@{
                TotalAccountsAnalyzed      = $Recommendations.Count
                RecommendedAdditions       = @($Recommendations | Where-Object { $_.Recommendation -eq 'Add to Allow List' }).Count
                HighRiskExclusions         = @($Recommendations | Where-Object { $_.Recommendation -like 'Exclude*' }).Count
                CentralizedStrategy        = @($Recommendations | Where-Object { $_.Recommendation -eq 'Centralized Strategy' }).Count
                AlreadyCached              = @($Recommendations | Where-Object { $_.Recommendation -eq 'Already Cached' }).Count
                EstimatedFallbackReduction = $(
                    $addToAllowSum = ($Recommendations | Where-Object { $_.Recommendation -eq 'Add to Allow List' } | Measure-Object -Property TotalRequests -Sum).Sum
                    $nonCachedSum  = ($Recommendations | Where-Object { $_.PRPStatus -notin @('Cached (Revealed)', 'In Allow List') } | Measure-Object -Property TotalRequests -Sum).Sum
                    $reductionPct  = [math]::Round(($addToAllowSum / [math]::Max(1, $nonCachedSum)) * 100, 1)
                    "$reductionPct%"
                )
            }
            Recommendations    = @($Recommendations | ForEach-Object {
                [ordered]@{
                    Rank              = $_.Rank
                    AccountName       = $_.AccountName
                    AccountType       = $_.AccountType
                    AvgRequestsPerDay = $_.AvgRequestsPerDay
                    TotalRequests     = $_.TotalRequests
                    RODCCount         = $_.RODCCount
                    SiteCount         = $_.SiteCount
                    Sites             = $_.Sites
                    Pattern           = $_.Pattern
                    PRPStatus         = $_.PRPStatus
                    RiskLevel         = $_.RiskLevel
                    RiskScore         = $_.RiskScore
                    Recommendation    = $_.Recommendation
                    Reason            = $_.Reason
                    ImpactScore       = $_.ImpactScore
                    IsPrivileged      = $_.IsPrivileged
                    PrivilegedGroups  = $_.PrivilegedGroups
                    HasSensitiveSPN   = $_.HasSensitiveSPN
                    SensitiveSPNs     = $_.SensitiveSPNs
                    PasswordLastSet   = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('o') } else { $null }
                    AdminCount        = $_.AdminCount
                }
            })
            ConflictsWarnings  = @($Conflicts | ForEach-Object {
                [ordered]@{
                    Severity    = $_.Severity
                    Type        = $_.Type
                    AccountName = $_.AccountName
                    Description = $_.Description
                }
            })
            PRPConfiguration   = @($PRPConfig.Keys | ForEach-Object {
                $prp = $PRPConfig[$_]
                [ordered]@{
                    RODCName     = $prp.RODCName
                    RODCSite     = $prp.RODCSite
                    AllowCount   = $prp.AllowList.Count
                    DenyCount    = $prp.DenyList.Count
                    CachedCount  = $prp.RevealedList.Count
                }
            })
        }

        $jsonPayload | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
        Write-Verbose "JSON report saved: $jsonPath"
    }
    catch {
        Write-Warning "Failed to write JSON report to '$jsonPath': $($_.Exception.Message)"
    }

    return @{
        HTMLPath = $htmlPath
        CSVPath  = $csvPath
        JSONPath = $jsonPath
    }
}

# ---------------------------------------------------------------------------
# Region: Main Execution
# ---------------------------------------------------------------------------

try {
    # Step 1: Validate prerequisites
    Write-Verbose "Step 1/7: Validating prerequisites..."
    Test-Prerequisites

    # Step 2: Discover target RODCs
    Write-Verbose "Step 2/7: Discovering RODCs..."
    $script:TargetRODCs = @(Get-TargetRODCs)

    if ($script:TargetRODCs.Count -eq 0) {
        Write-Warning "No RODCs to analyze. Generating empty report."
        $authEvents = @()
        $prpConfig = @{}
        $usagePatterns = @{}
        $accountMetadata = @{}
    }
    else {
        # Step 3: Collect authentication events
        Write-Verbose "Step 3/7: Collecting authentication events..."
        $authEvents = @(Get-AuthenticationEvents -RODCs $script:TargetRODCs)

        # Step 4: Collect PRP configuration
        Write-Verbose "Step 4/7: Collecting PRP configuration..."
        $prpConfig = Get-PRPConfiguration -RODCs $script:TargetRODCs

        # Step 5: Analyze usage patterns
        Write-Verbose "Step 5/7: Analyzing usage patterns..."
        $usagePatterns = Get-UsagePatterns -Events $authEvents

        # Step 6: Collect account risk metadata
        Write-Verbose "Step 6/7: Collecting account risk metadata..."
        $uniqueAccounts = @($usagePatterns.Keys)
        if ($uniqueAccounts.Count -gt 0) {
            $accountMetadata = Get-AccountRiskMetadata -AccountNames $uniqueAccounts
        }
        else {
            $accountMetadata = @{}
        }
    }

    # Step 7: Build recommendations and generate reports
    Write-Verbose "Step 7/7: Building recommendations and generating reports..."

    if ($usagePatterns.Count -gt 0 -and $accountMetadata.Count -gt 0) {
        $results = Build-Recommendations -UsagePatterns $usagePatterns -AccountMetadata $accountMetadata -PRPConfig $prpConfig
        $allRecommendations = @($results.Recommendations)
        $allConflicts = @($results.Conflicts)
    }
    else {
        $allRecommendations = @()
        $allConflicts = @()
    }

    # Generate HTML
    $htmlContent = Build-HTMLReport `
        -Recommendations $allRecommendations `
        -Conflicts $allConflicts `
        -RODCs $script:TargetRODCs `
        -PRPConfig $prpConfig

    # Export all formats
    $reportPaths = Export-Reports `
        -HTML $htmlContent `
        -Recommendations $allRecommendations `
        -Conflicts $allConflicts `
        -PRPConfig $prpConfig

    # Summary output
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  RODC PRP Recommendations - Analysis Complete" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Domain:              $($script:DomainInfo.DNSRoot)" -ForegroundColor White
    Write-Host "  RODCs Analyzed:      $($script:TargetRODCs.Count)" -ForegroundColor White
    Write-Host "  Analysis Window:     $DaysBack day(s)" -ForegroundColor White
    Write-Host "  Accounts Analyzed:   $($allRecommendations.Count)" -ForegroundColor White
    Write-Host ""

    $addCount = @($allRecommendations | Where-Object { $_.Recommendation -eq 'Add to Allow List' }).Count
    $exclCount = @($allRecommendations | Where-Object { $_.Recommendation -like 'Exclude*' }).Count
    $warnCount = $allConflicts.Count

    if ($addCount -gt 0) {
        Write-Host "  Recommended Additions: $addCount" -ForegroundColor Green
    }
    else {
        Write-Host "  Recommended Additions: 0" -ForegroundColor Gray
    }

    if ($exclCount -gt 0) {
        Write-Host "  High-Risk Exclusions:  $exclCount" -ForegroundColor Red
    }
    else {
        Write-Host "  High-Risk Exclusions:  0" -ForegroundColor Gray
    }

    if ($warnCount -gt 0) {
        Write-Host "  Conflicts/Warnings:    $warnCount" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Conflicts/Warnings:    0" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "  Reports Generated:" -ForegroundColor White
    Write-Host "    HTML: $($reportPaths.HTMLPath)" -ForegroundColor Gray
    Write-Host "    CSV:  $($reportPaths.CSVPath)" -ForegroundColor Gray
    Write-Host "    JSON: $($reportPaths.JSONPath)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Duration: $($duration.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NOTE: This was a READ-ONLY analysis. No PRP groups were modified." -ForegroundColor Yellow
    Write-Host "  Review the HTML report for implementation commands." -ForegroundColor Yellow
    Write-Host ""

    # Return paths for pipeline consumption
    [PSCustomObject]@{
        HTMLPath              = $reportPaths.HTMLPath
        CSVPath               = $reportPaths.CSVPath
        JSONPath              = $reportPaths.JSONPath
        TotalAccountsAnalyzed = $allRecommendations.Count
        RecommendedAdditions  = $addCount
        HighRiskExclusions    = $exclCount
        ConflictsWarnings     = $warnCount
        DurationSeconds       = [math]::Round($duration.TotalSeconds, 1)
    }
}
catch {
    Write-Error "RODC PRP Recommendations failed: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    throw
}
