#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies RODC DNS SRV record registration in AD-integrated DNS zones.

.DESCRIPTION
    Performs read-only DNS validation for all Read-Only Domain Controllers (RODCs)
    in the Active Directory environment. For each RODC, the script checks:

      - Required SRV records (site-specific and domain-wide _kerberos and _ldap)
      - Global Catalog SRV records (if the RODC is a GC)
      - Host (A) record in the forward lookup zone
      - PTR record in the reverse lookup zone
      - Incorrect SRV records that should NOT exist on an RODC (writable-DC-only
        records such as _kerberos._tcp.<Domain> and PDC emulator records)
      - DNS scavenging configuration protecting RODC records

    Outputs are generated with timestamps in the filename:
      - HTML report with executive summary dashboard and styled findings table
      - CSV export of all findings for downstream processing
      - Optional PowerShell remediation script (.ps1) containing Add-DnsServerResourceRecord
        commands for any missing records (never auto-executed)

    This script is SAFE BY DESIGN: it performs read-only DNS queries only. The
    remediation script is a separate output file that must be reviewed and
    executed manually by an administrator.

.PARAMETER RODCName
    Optional. One or more RODC hostnames to check. If omitted, all RODCs in the
    domain are discovered via Get-ADDomainController -Filter {IsReadOnly -eq $true}.

.PARAMETER DnsServer
    DNS server to query for record validation. Defaults to the PDC Emulator of
    the current domain.

.PARAMETER OutputPath
    Directory for output files (HTML, CSV, remediation script). Created if it
    does not exist. Defaults to C:\Reports\RODC.

.PARAMETER GenerateRemediationScript
    Switch. When specified, a PowerShell .ps1 file is generated containing
    Add-DnsServerResourceRecord commands to create any missing DNS records.
    The script is NOT auto-executed.

.EXAMPLE
    .\Test-RODCDnsRegistration.ps1
    Checks all RODCs, queries the PDC Emulator, writes output to C:\Reports\RODC.

.EXAMPLE
    .\Test-RODCDnsRegistration.ps1 -RODCName "RODC01" -DnsServer "DC01.corp.contoso.com" -OutputPath "D:\Audits\RODC" -GenerateRemediationScript
    Checks only RODC01 against DC01, outputs to D:\Audits\RODC, and generates a
    remediation script for any missing records.

.EXAMPLE
    .\Test-RODCDnsRegistration.ps1 -RODCName "RODC01","RODC02" -Verbose
    Checks two named RODCs with verbose diagnostic output.

.NOTES
    Author  : AD Health Check Framework
    Version : 1.0.0
    Safety  : Read-only. No Set-*, New-*, Remove-* commands are executed.
              The remediation script is output only and must be run manually.
    Requires: ActiveDirectory module, DnsServer module
    Run from: A domain controller or management server with DNS management access.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true,
               HelpMessage = "One or more RODC hostnames. Omit to check all RODCs.")]
    [Alias("ComputerName", "Name")]
    [string[]]$RODCName,

    [Parameter(Mandatory = $false,
               HelpMessage = "DNS server to query. Defaults to PDC Emulator.")]
    [string]$DnsServer,

    [Parameter(Mandatory = $false,
               HelpMessage = "Output directory for reports. Defaults to C:\Reports\RODC.")]
    [string]$OutputPath = "C:\Reports\RODC",

    [Parameter(Mandatory = $false,
               HelpMessage = "Generate a remediation .ps1 script for missing records.")]
    [switch]$GenerateRemediationScript
)

# ---------------------------------------------------------------------------
# Region: Initialization
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$scriptStartTime = Get-Date

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  RODC DNS SRV Record Registration Check" -ForegroundColor Cyan
Write-Host "  Safe by Design -- Read-Only Queries Only" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# Verify required modules
$requiredModules = @('ActiveDirectory', 'DnsServer')
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Error "Required module '$mod' is not available. Install RSAT features and retry."
        return
    }
    Import-Module $mod -ErrorAction Stop -Verbose:$false
    Write-Verbose "Module loaded: $mod"
}

# Resolve domain and forest information
try {
    $domainInfo  = Get-ADDomain -ErrorAction Stop
    $forestInfo  = Get-ADForest -ErrorAction Stop
    $domainDN    = $domainInfo.DistinguishedName
    $domainFQDN  = $domainInfo.DNSRoot
    $forestRoot  = $forestInfo.RootDomain
    $pdcEmulator = $domainInfo.PDCEmulator
    Write-Verbose "Domain FQDN  : $domainFQDN"
    Write-Verbose "Forest Root  : $forestRoot"
    Write-Verbose "PDC Emulator : $pdcEmulator"
}
catch {
    Write-Error "Failed to query Active Directory domain/forest information: $($_.Exception.Message)"
    return
}

# Resolve DNS server target
if (-not $DnsServer) {
    $DnsServer = $pdcEmulator
    Write-Verbose "DnsServer defaulted to PDC Emulator: $DnsServer"
}
Write-Host "DNS Server   : $DnsServer" -ForegroundColor White

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Verbose "Created output directory: $OutputPath"
    }
    catch {
        Write-Error "Cannot create output directory '$OutputPath': $($_.Exception.Message)"
        return
    }
}

$htmlFile        = Join-Path $OutputPath "RODC-DNS-Report_$timestamp.html"
$csvFile         = Join-Path $OutputPath "RODC-DNS-Report_$timestamp.csv"
$jsonFile        = Join-Path $OutputPath "RODC-DNS-Report_$timestamp.json"
$remediationFile = Join-Path $OutputPath "RODC-DNS-Remediation_$timestamp.ps1"

Write-Host "Output Path  : $OutputPath" -ForegroundColor White
Write-Host ""

# ---------------------------------------------------------------------------
# Region: RODC Discovery
# ---------------------------------------------------------------------------

Write-Host "[*] Discovering RODCs..." -ForegroundColor Yellow

if ($RODCName) {
    # Validate provided RODC names
    $rodcList = [System.Collections.ArrayList]::new()
    foreach ($name in $RODCName) {
        try {
            $dc = Get-ADDomainController -Identity $name -ErrorAction Stop
            if ($dc.IsReadOnly) {
                $null = $rodcList.Add($dc)
                Write-Verbose "Validated RODC: $($dc.HostName)"
            }
            else {
                Write-Warning "'$name' is not a Read-Only Domain Controller. Skipping."
            }
        }
        catch {
            Write-Warning "Cannot find domain controller '$name': $($_.Exception.Message)"
        }
    }
}
else {
    try {
        $rodcList = [System.Collections.ArrayList]@(
            Get-ADDomainController -Filter { IsReadOnly -eq $true } -ErrorAction Stop
        )
    }
    catch {
        Write-Error "Failed to enumerate RODCs: $($_.Exception.Message)"
        return
    }
}

if ($rodcList.Count -eq 0) {
    Write-Warning "No RODCs found to check. Exiting."
    return
}

Write-Host "[+] Found $($rodcList.Count) RODC(s) to check" -ForegroundColor Green
foreach ($rodc in $rodcList) {
    Write-Host "    - $($rodc.HostName) (Site: $($rodc.Site))" -ForegroundColor Gray
}
Write-Host ""

# ---------------------------------------------------------------------------
# Region: DNS Check Functions
# ---------------------------------------------------------------------------

function Test-DnsRecordExists {
    <#
    .SYNOPSIS
        Tests whether a specific DNS resource record exists on the target DNS server.
    .DESCRIPTION
        Queries the specified DNS server for a record in the given zone. Returns a
        PSCustomObject with Exists (bool), Records (array), and Error (string).
        This is a read-only query; no records are created or modified.
    .PARAMETER ZoneName
        The DNS zone to query.
    .PARAMETER Name
        The record name within the zone.
    .PARAMETER RRType
        The resource record type (SRV, A, PTR, etc.).
    .PARAMETER Server
        The DNS server to query.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ZoneName,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$RRType,
        [Parameter(Mandatory)][string]$Server
    )

    $result = [PSCustomObject]@{
        Exists  = $false
        Records = @()
        Error   = $null
    }

    try {
        $records = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $Name `
                       -RRType $RRType -ComputerName $Server -ErrorAction Stop
        if ($records) {
            $result.Exists  = $true
            $result.Records = @($records)
        }
    }
    catch [Microsoft.Management.Infrastructure.CimException] {
        # Record not found -- this is expected for missing records
        $result.Error = $_.Exception.Message
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Test-DnsSrvRecordForHost {
    <#
    .SYNOPSIS
        Checks if a specific SRV record points to the specified RODC hostname.
    .DESCRIPTION
        Queries the DNS zone for SRV records at the given name, then filters to
        see if the target RODC hostname is among the registered servers.
    .PARAMETER ZoneName
        The DNS zone to query.
    .PARAMETER SrvName
        The SRV record name (e.g., _kerberos._tcp.SiteName._sites.dc._msdcs).
    .PARAMETER TargetHost
        The RODC FQDN expected in the SRV record data (with trailing dot).
    .PARAMETER Server
        The DNS server to query.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ZoneName,
        [Parameter(Mandatory)][string]$SrvName,
        [Parameter(Mandatory)][string]$TargetHost,
        [Parameter(Mandatory)][string]$Server
    )

    $result = [PSCustomObject]@{
        Exists      = $false
        HostFound   = $false
        Records     = @()
        Error       = $null
    }

    try {
        $records = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $SrvName `
                       -RRType SRV -ComputerName $Server -ErrorAction Stop
        if ($records) {
            $result.Exists  = $true
            $result.Records = @($records)

            # Normalize target host for comparison (ensure trailing dot consistency)
            $normalizedTarget = $TargetHost.TrimEnd('.').ToLower()

            foreach ($rec in $records) {
                $srvTarget = $rec.RecordData.DomainName.TrimEnd('.').ToLower()
                if ($srvTarget -eq $normalizedTarget) {
                    $result.HostFound = $true
                    break
                }
            }
        }
    }
    catch [Microsoft.Management.Infrastructure.CimException] {
        $result.Error = $_.Exception.Message
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-DnsScavengingInfo {
    <#
    .SYNOPSIS
        Retrieves DNS zone scavenging configuration.
    .DESCRIPTION
        Returns the aging/scavenging settings (NoRefresh interval, Refresh interval,
        and whether aging is enabled) for the specified zone. Read-only query.
    .PARAMETER ZoneName
        The DNS zone to query.
    .PARAMETER Server
        The DNS server to query.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ZoneName,
        [Parameter(Mandatory)][string]$Server
    )

    $info = [PSCustomObject]@{
        AgingEnabled    = $false
        NoRefreshInterval = $null
        RefreshInterval   = $null
        Error             = $null
    }

    try {
        $zone = Get-DnsServerZoneAging -Name $ZoneName -ComputerName $Server -ErrorAction Stop
        $info.AgingEnabled      = $zone.AgingEnabled
        $info.NoRefreshInterval = $zone.NoRefreshInterval
        $info.RefreshInterval   = $zone.RefreshInterval
    }
    catch {
        $info.Error = $_.Exception.Message
    }

    return $info
}

function Get-ReverseZoneName {
    <#
    .SYNOPSIS
        Derives the reverse lookup zone name from an IP address.
    .DESCRIPTION
        For a given IPv4 address, computes the likely reverse lookup zone name
        (Class C /24 assumption). Returns $null if the IP is invalid.
    .PARAMETER IPAddress
        The IPv4 address string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IPAddress
    )

    try {
        $octets = $IPAddress.Split('.')
        if ($octets.Count -eq 4) {
            return "$($octets[2]).$($octets[1]).$($octets[0]).in-addr.arpa"
        }
    }
    catch {
        Write-Verbose "Cannot parse IP address '$IPAddress' for reverse zone: $($_.Exception.Message)"
    }

    return $null
}

# ---------------------------------------------------------------------------
# Region: Main Check Loop
# ---------------------------------------------------------------------------

Write-Host "[*] Running DNS record checks..." -ForegroundColor Yellow

$allFindings = [System.Collections.ArrayList]::new()
$remediationCommands = [System.Collections.ArrayList]::new()

# Add header to remediation script
$null = $remediationCommands.Add(@"
#Requires -Version 5.1
#Requires -Modules DnsServer
<#
.SYNOPSIS
    RODC DNS Remediation Script -- Generated $timestamp
.DESCRIPTION
    This script contains Add-DnsServerResourceRecord commands to create
    missing DNS records for RODCs. REVIEW CAREFULLY before executing.

    Generated by: Test-RODCDnsRegistration.ps1
    Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    DNS Server  : $DnsServer

    WARNING: This script MODIFIES DNS records. Run in a test environment first.
.NOTES
    Each command is commented with the RODC name and record type for traceability.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]`$TargetDnsServer = '$DnsServer'
)

Write-Host "RODC DNS Remediation Script" -ForegroundColor Cyan
Write-Host "Target DNS Server: `$TargetDnsServer" -ForegroundColor White
Write-Host ""

"@)

foreach ($rodc in $rodcList) {
    $rodcHostName  = $rodc.HostName
    $rodcShortName = $rodc.Name
    $rodcSite      = $rodc.Site
    $rodcIP        = ($rodc.IPv4Address)
    $rodcIsGC      = $rodc.IsGlobalCatalog

    Write-Host "`n  Checking: $rodcHostName (Site: $rodcSite, IP: $rodcIP, GC: $rodcIsGC)" -ForegroundColor White

    $rodcFinding = [PSCustomObject]@{
        RODCName            = $rodcHostName
        RODCShortName       = $rodcShortName
        Site                = $rodcSite
        IPAddress           = $rodcIP
        IsGlobalCatalog     = $rodcIsGC
        MissingSRVRecords   = [System.Collections.ArrayList]::new()
        IncorrectSRVRecords = [System.Collections.ArrayList]::new()
        ARecordStatus       = 'Unknown'
        PTRRecordStatus     = 'Unknown'
        ScavengingStatus    = 'Unknown'
        ScavengingDetails   = ''
        OverallStatus       = 'Pass'
    }

    # ------------------------------------------------------------------
    # Check 1: Required SRV Records
    # ------------------------------------------------------------------
    Write-Verbose "  Checking required SRV records for $rodcHostName..."

    # Build the list of required SRV records for this RODC
    $requiredSRV = @(
        @{
            Description = "_kerberos._tcp.<Site>._sites.dc._msdcs.<Domain>"
            Zone        = $domainFQDN
            Name        = "_kerberos._tcp.$rodcSite._sites.dc._msdcs"
            FullName    = "_kerberos._tcp.$rodcSite._sites.dc._msdcs.$domainFQDN"
        },
        @{
            Description = "_kerberos._tcp.dc._msdcs.<Domain>"
            Zone        = $domainFQDN
            Name        = "_kerberos._tcp.dc._msdcs"
            FullName    = "_kerberos._tcp.dc._msdcs.$domainFQDN"
        },
        @{
            Description = "_ldap._tcp.<Site>._sites.dc._msdcs.<Domain>"
            Zone        = $domainFQDN
            Name        = "_ldap._tcp.$rodcSite._sites.dc._msdcs"
            FullName    = "_ldap._tcp.$rodcSite._sites.dc._msdcs.$domainFQDN"
        },
        @{
            Description = "_ldap._tcp.dc._msdcs.<Domain>"
            Zone        = $domainFQDN
            Name        = "_ldap._tcp.dc._msdcs"
            FullName    = "_ldap._tcp.dc._msdcs.$domainFQDN"
        },
        @{
            Description = "_kerberos._tcp.<Site>._sites.<Domain>"
            Zone        = $domainFQDN
            Name        = "_kerberos._tcp.$rodcSite._sites"
            FullName    = "_kerberos._tcp.$rodcSite._sites.$domainFQDN"
        },
        @{
            Description = "_ldap._tcp.<Site>._sites.<Domain>"
            Zone        = $domainFQDN
            Name        = "_ldap._tcp.$rodcSite._sites"
            FullName    = "_ldap._tcp.$rodcSite._sites.$domainFQDN"
        }
    )

    # Add GC record if RODC is a Global Catalog
    if ($rodcIsGC) {
        $requiredSRV += @{
            Description = "_gc._tcp.<Site>._sites.<ForestRoot>"
            Zone        = $forestRoot
            Name        = "_gc._tcp.$rodcSite._sites"
            FullName    = "_gc._tcp.$rodcSite._sites.$forestRoot"
        }
    }

    foreach ($srv in $requiredSRV) {
        Write-Verbose "    Checking SRV: $($srv.FullName)"

        $check = Test-DnsSrvRecordForHost -ZoneName $srv.Zone -SrvName $srv.Name `
                     -TargetHost $rodcHostName -Server $DnsServer

        if (-not $check.HostFound) {
            $null = $rodcFinding.MissingSRVRecords.Add($srv.FullName)
            Write-Verbose "    [MISSING] $($srv.FullName) -- RODC not found in SRV data"

            # Build remediation command
            $null = $remediationCommands.Add(@"

# [$rodcShortName] Missing SRV: $($srv.Description)
# Full record: $($srv.FullName) -> $rodcHostName
Add-DnsServerResourceRecord -ZoneName '$($srv.Zone)' ``
    -Name '$($srv.Name)' ``
    -Srv -DomainName '$rodcHostName.' ``
    -Priority 0 -Weight 100 -Port 389 ``
    -ComputerName `$TargetDnsServer ``
    -ErrorAction Stop
"@)
        }
        else {
            Write-Verbose "    [OK] $($srv.FullName)"
        }
    }

    # ------------------------------------------------------------------
    # Check 2: Host A Record
    # ------------------------------------------------------------------
    Write-Verbose "  Checking A record for $rodcHostName..."

    $aRecordCheck = Test-DnsRecordExists -ZoneName $domainFQDN -Name $rodcShortName `
                        -RRType A -Server $DnsServer

    if ($aRecordCheck.Exists) {
        $rodcFinding.ARecordStatus = 'OK'
        Write-Verbose "    [OK] A record exists for $rodcShortName"
    }
    else {
        $rodcFinding.ARecordStatus = 'Missing'
        Write-Verbose "    [MISSING] A record for $rodcShortName"

        $null = $remediationCommands.Add(@"

# [$rodcShortName] Missing A record in forward lookup zone
Add-DnsServerResourceRecordA -ZoneName '$domainFQDN' ``
    -Name '$rodcShortName' ``
    -IPv4Address '$rodcIP' ``
    -ComputerName `$TargetDnsServer ``
    -ErrorAction Stop
"@)
    }

    # ------------------------------------------------------------------
    # Check 3: PTR Record
    # ------------------------------------------------------------------
    Write-Verbose "  Checking PTR record for $rodcHostName ($rodcIP)..."

    if ($rodcIP) {
        $reverseZone = Get-ReverseZoneName -IPAddress $rodcIP
        if ($reverseZone) {
            $lastOctet = $rodcIP.Split('.')[-1]
            $ptrCheck = Test-DnsRecordExists -ZoneName $reverseZone -Name $lastOctet `
                            -RRType PTR -Server $DnsServer

            if ($ptrCheck.Exists) {
                $rodcFinding.PTRRecordStatus = 'OK'
                Write-Verbose "    [OK] PTR record exists"
            }
            elseif ($ptrCheck.Error -and $ptrCheck.Error -match 'Zone.*not found|does not exist') {
                $rodcFinding.PTRRecordStatus = 'N/A'
                Write-Verbose "    [N/A] Reverse zone '$reverseZone' not configured"
            }
            else {
                $rodcFinding.PTRRecordStatus = 'Missing'
                Write-Verbose "    [MISSING] PTR record for $rodcIP"

                $null = $remediationCommands.Add(@"

# [$rodcShortName] Missing PTR record in reverse lookup zone
Add-DnsServerResourceRecordPtr -ZoneName '$reverseZone' ``
    -Name '$lastOctet' ``
    -PtrDomainName '$rodcHostName.' ``
    -ComputerName `$TargetDnsServer ``
    -ErrorAction Stop
"@)
            }
        }
        else {
            $rodcFinding.PTRRecordStatus = 'N/A'
            Write-Verbose "    [N/A] Cannot determine reverse zone for $rodcIP"
        }
    }
    else {
        $rodcFinding.PTRRecordStatus = 'N/A'
        Write-Verbose "    [N/A] No IPv4 address available for PTR check"
    }

    # ------------------------------------------------------------------
    # Check 4: Incorrect SRV Records (writable-DC-only records on RODC)
    # ------------------------------------------------------------------
    Write-Verbose "  Checking for incorrect SRV records on $rodcHostName..."

    $incorrectSRV = @(
        @{
            Description = "_kerberos._tcp.<Domain> (writable DC only)"
            Zone        = $domainFQDN
            Name        = "_kerberos._tcp"
            FullName    = "_kerberos._tcp.$domainFQDN"
        },
        @{
            Description = "_ldap._tcp.pdc._msdcs.<Domain> (PDC Emulator only)"
            Zone        = $domainFQDN
            Name        = "_ldap._tcp.pdc._msdcs"
            FullName    = "_ldap._tcp.pdc._msdcs.$domainFQDN"
        },
        @{
            Description = "_kerberos._tcp.pdc._msdcs.<Domain> (PDC Emulator only)"
            Zone        = $domainFQDN
            Name        = "_kerberos._tcp.pdc._msdcs"
            FullName    = "_kerberos._tcp.pdc._msdcs.$domainFQDN"
        }
    )

    foreach ($bad in $incorrectSRV) {
        Write-Verbose "    Checking for incorrect: $($bad.FullName)"

        $check = Test-DnsSrvRecordForHost -ZoneName $bad.Zone -SrvName $bad.Name `
                     -TargetHost $rodcHostName -Server $DnsServer

        if ($check.HostFound) {
            $null = $rodcFinding.IncorrectSRVRecords.Add($bad.FullName)
            Write-Verbose "    [INCORRECT] $rodcHostName found in $($bad.FullName) -- should NOT be registered"
        }
        else {
            Write-Verbose "    [OK] $rodcHostName correctly absent from $($bad.FullName)"
        }
    }

    # ------------------------------------------------------------------
    # Check 5: DNS Scavenging Configuration
    # ------------------------------------------------------------------
    Write-Verbose "  Checking DNS scavenging configuration for zone $domainFQDN..."

    $scavengingInfo = Get-DnsScavengingInfo -ZoneName $domainFQDN -Server $DnsServer

    if ($scavengingInfo.Error) {
        $rodcFinding.ScavengingStatus  = 'Error'
        $rodcFinding.ScavengingDetails = "Unable to query scavenging: $($scavengingInfo.Error)"
    }
    elseif ($scavengingInfo.AgingEnabled) {
        $noRefresh = $scavengingInfo.NoRefreshInterval
        $refresh   = $scavengingInfo.RefreshInterval

        # Check if intervals are reasonable (default is 7 days each)
        if ($noRefresh -and $refresh) {
            $noRefreshDays = $noRefresh.TotalDays
            $refreshDays   = $refresh.TotalDays

            if ($noRefreshDays -lt 1 -or $refreshDays -lt 1) {
                $rodcFinding.ScavengingStatus  = 'Warning'
                $rodcFinding.ScavengingDetails = "Aging enabled. NoRefresh: $noRefreshDays day(s), Refresh: $refreshDays day(s). Aggressive intervals may scavenge RODC records prematurely."
            }
            else {
                $rodcFinding.ScavengingStatus  = 'OK'
                $rodcFinding.ScavengingDetails = "Aging enabled. NoRefresh: $noRefreshDays day(s), Refresh: $refreshDays day(s). Intervals are within normal range."
            }
        }
        else {
            $rodcFinding.ScavengingStatus  = 'OK'
            $rodcFinding.ScavengingDetails = "Aging enabled. NoRefresh: $noRefresh, Refresh: $refresh."
        }
    }
    else {
        $rodcFinding.ScavengingStatus  = 'OK'
        $rodcFinding.ScavengingDetails = "Aging/scavenging is disabled on zone $domainFQDN. RODC records are not at risk of being scavenged."
    }

    # ------------------------------------------------------------------
    # Determine overall status
    # ------------------------------------------------------------------
    if ($rodcFinding.MissingSRVRecords.Count -gt 0 -or
        $rodcFinding.IncorrectSRVRecords.Count -gt 0 -or
        $rodcFinding.ARecordStatus -eq 'Missing' -or
        $rodcFinding.PTRRecordStatus -eq 'Missing') {
        $rodcFinding.OverallStatus = 'Fail'
    }
    elseif ($rodcFinding.ScavengingStatus -eq 'Warning') {
        $rodcFinding.OverallStatus = 'Warning'
    }

    $statusColor = switch ($rodcFinding.OverallStatus) {
        'Pass'    { 'Green' }
        'Warning' { 'Yellow' }
        'Fail'    { 'Red' }
        default   { 'Gray' }
    }
    Write-Host "    Result: $($rodcFinding.OverallStatus)" -ForegroundColor $statusColor

    $null = $allFindings.Add($rodcFinding)
}

Write-Host "`n[+] All RODC checks complete.`n" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Region: Summary Calculations
# ---------------------------------------------------------------------------

$totalRODCs         = $allFindings.Count
$rodcsWithMissing   = ($allFindings | Where-Object { $_.MissingSRVRecords.Count -gt 0 }).Count
$rodcsWithIncorrect = ($allFindings | Where-Object { $_.IncorrectSRVRecords.Count -gt 0 }).Count
$rodcsPassed        = ($allFindings | Where-Object { $_.OverallStatus -eq 'Pass' }).Count
$rodcsFailed        = ($allFindings | Where-Object { $_.OverallStatus -eq 'Fail' }).Count
$rodcsWarning       = ($allFindings | Where-Object { $_.OverallStatus -eq 'Warning' }).Count
$totalMissing       = ($allFindings | ForEach-Object { $_.MissingSRVRecords.Count } | Measure-Object -Sum).Sum
$totalIncorrect     = ($allFindings | ForEach-Object { $_.IncorrectSRVRecords.Count } | Measure-Object -Sum).Sum

$healthPct = if ($totalRODCs -gt 0) { [math]::Round(($rodcsPassed / $totalRODCs) * 100) } else { 0 }

# ---------------------------------------------------------------------------
# Region: CSV Export
# ---------------------------------------------------------------------------

Write-Host "[*] Exporting CSV..." -ForegroundColor Yellow

$csvData = $allFindings | ForEach-Object {
    [PSCustomObject]@{
        RODCName            = $_.RODCName
        Site                = $_.Site
        IPAddress           = $_.IPAddress
        IsGlobalCatalog     = $_.IsGlobalCatalog
        MissingSRVRecords   = ($_.MissingSRVRecords -join '; ')
        MissingSRVCount     = $_.MissingSRVRecords.Count
        IncorrectSRVRecords = ($_.IncorrectSRVRecords -join '; ')
        IncorrectSRVCount   = $_.IncorrectSRVRecords.Count
        ARecordStatus       = $_.ARecordStatus
        PTRRecordStatus     = $_.PTRRecordStatus
        ScavengingStatus    = $_.ScavengingStatus
        ScavengingDetails   = $_.ScavengingDetails
        OverallStatus       = $_.OverallStatus
    }
}

$csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
Write-Host "[+] CSV exported: $csvFile" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Region: JSON Export
# ---------------------------------------------------------------------------

Write-Host "[*] Exporting JSON..." -ForegroundColor Yellow

$jsonExport = @{
    ReportMetadata = @{
        ReportType     = 'RODC DNS SRV Record Registration'
        GeneratedAt    = (Get-Date -Format 'o')
        GeneratedBy    = $env:USERNAME
        DnsServer      = $DnsServer
        Domain         = $domainFQDN
        ForestRoot     = $forestRoot
        TotalRODCs     = $totalRODCs
        PassedCount    = $rodcsPassed
        FailedCount    = $rodcsFailed
        WarningCount   = $rodcsWarning
    }
    Findings = $allFindings | ForEach-Object {
        @{
            RODCName            = $_.RODCName
            RODCShortName       = $_.RODCShortName
            Site                = $_.Site
            IPAddress           = $_.IPAddress
            IsGlobalCatalog     = $_.IsGlobalCatalog
            MissingSRVRecords   = @($_.MissingSRVRecords)
            IncorrectSRVRecords = @($_.IncorrectSRVRecords)
            ARecordStatus       = $_.ARecordStatus
            PTRRecordStatus     = $_.PTRRecordStatus
            ScavengingStatus    = $_.ScavengingStatus
            ScavengingDetails   = $_.ScavengingDetails
            OverallStatus       = $_.OverallStatus
        }
    }
}

$jsonExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8 -Force
Write-Host "[+] JSON exported: $jsonFile" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Region: Remediation Script Output
# ---------------------------------------------------------------------------

if ($GenerateRemediationScript) {
    Write-Host "[*] Generating remediation script..." -ForegroundColor Yellow

    # Add footer to remediation script
    $null = $remediationCommands.Add(@"

# ---------------------------------------------------------------------------
# End of remediation commands
# Total missing records addressed: $totalMissing
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Remediation complete. Verify records with:" -ForegroundColor Cyan
Write-Host "  .\Test-RODCDnsRegistration.ps1 -DnsServer '$DnsServer'" -ForegroundColor White
"@)

    $remediationContent = $remediationCommands -join "`n"
    $remediationContent | Out-File -FilePath $remediationFile -Encoding UTF8 -Force
    Write-Host "[+] Remediation script: $remediationFile" -ForegroundColor Green
    Write-Host "    WARNING: Review the script before execution. It modifies DNS records." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Region: HTML Report Generation
# ---------------------------------------------------------------------------

Write-Host "[*] Generating HTML report..." -ForegroundColor Yellow

$ringColor = switch ($true) {
    ($healthPct -ge 90) { '#2ea043' }
    ($healthPct -ge 70) { '#d29922' }
    ($healthPct -ge 50) { '#f0883e' }
    default             { '#f85149' }
}

$circumference = [math]::Round(2 * [math]::PI * 68, 2)
$ringOffset    = [math]::Round($circumference * (1 - ($healthPct / 100)), 2)

$reportTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss 'UTC'K"
$executionTime  = [math]::Round(((Get-Date) - $scriptStartTime).TotalSeconds, 1)

# Build findings table rows
$tableRows = ""
foreach ($f in $allFindings) {
    $statusClass = switch ($f.OverallStatus) {
        'Pass'    { 'pass' }
        'Warning' { 'warn' }
        'Fail'    { 'fail' }
        default   { 'info' }
    }

    $aClass = switch ($f.ARecordStatus) {
        'OK'      { 'pass' }
        'Missing' { 'fail' }
        default   { 'info' }
    }

    $ptrClass = switch ($f.PTRRecordStatus) {
        'OK'      { 'pass' }
        'Missing' { 'fail' }
        'N/A'     { 'info' }
        default   { 'info' }
    }

    $missingList = if ($f.MissingSRVRecords.Count -gt 0) {
        $items = ($f.MissingSRVRecords | ForEach-Object {
            "<li>$([System.Net.WebUtility]::HtmlEncode($_))</li>"
        }) -join ""
        "<ul class=`"record-list fail-list`">$items</ul>"
    }
    else {
        "<span class=`"text-pass`">None</span>"
    }

    $incorrectList = if ($f.IncorrectSRVRecords.Count -gt 0) {
        $items = ($f.IncorrectSRVRecords | ForEach-Object {
            "<li>$([System.Net.WebUtility]::HtmlEncode($_))</li>"
        }) -join ""
        "<ul class=`"record-list warn-list`">$items</ul>"
    }
    else {
        "<span class=`"text-pass`">None</span>"
    }

    $gcBadge = if ($f.IsGlobalCatalog) { '<span class="badge info">GC</span>' } else { '' }

    $tableRows += @"
                        <tr data-status="$statusClass">
                            <td class="mono">$([System.Net.WebUtility]::HtmlEncode($f.RODCName)) $gcBadge</td>
                            <td>$([System.Net.WebUtility]::HtmlEncode($f.Site))</td>
                            <td class="mono">$([System.Net.WebUtility]::HtmlEncode($f.IPAddress))</td>
                            <td>$missingList</td>
                            <td>$incorrectList</td>
                            <td><span class="badge $aClass">$([System.Net.WebUtility]::HtmlEncode($f.ARecordStatus))</span></td>
                            <td><span class="badge $ptrClass">$([System.Net.WebUtility]::HtmlEncode($f.PTRRecordStatus))</span></td>
                            <td><span class="badge $statusClass">$([System.Net.WebUtility]::HtmlEncode($f.OverallStatus))</span></td>
                        </tr>
"@
}

# Build scavenging detail rows
$scavengingRows = ""
foreach ($f in $allFindings) {
    $scavClass = switch ($f.ScavengingStatus) {
        'OK'      { 'pass' }
        'Warning' { 'warn' }
        'Error'   { 'fail' }
        default   { 'info' }
    }

    $scavengingRows += @"
                        <tr>
                            <td class="mono">$([System.Net.WebUtility]::HtmlEncode($f.RODCName))</td>
                            <td><span class="badge $scavClass">$([System.Net.WebUtility]::HtmlEncode($f.ScavengingStatus))</span></td>
                            <td>$([System.Net.WebUtility]::HtmlEncode($f.ScavengingDetails))</td>
                        </tr>
"@
}

# Build evidence section: per-RODC detail blocks
$evidenceBlocks = ""
foreach ($f in $allFindings) {
    $detailStatusClass = switch ($f.OverallStatus) {
        'Pass'    { 'pass' }
        'Warning' { 'warn' }
        'Fail'    { 'fail' }
        default   { 'info' }
    }

    $openAttr = if ($f.OverallStatus -eq 'Fail') { ' open' } else { '' }

    $missingEvidence = if ($f.MissingSRVRecords.Count -gt 0) {
        $lines = ($f.MissingSRVRecords | ForEach-Object { "  [MISSING] $_" }) -join "`n"
        [System.Net.WebUtility]::HtmlEncode($lines)
    }
    else {
        "  All required SRV records are present."
    }

    $incorrectEvidence = if ($f.IncorrectSRVRecords.Count -gt 0) {
        $lines = ($f.IncorrectSRVRecords | ForEach-Object { "  [INCORRECT] $_ -- RODC should NOT be registered here" }) -join "`n"
        [System.Net.WebUtility]::HtmlEncode($lines)
    }
    else {
        "  No incorrect records found. RODC is correctly absent from writable-DC-only SRV records."
    }

    $evidenceBlocks += @"
                <details class="check-card" data-status="$detailStatusClass"$openAttr>
                    <summary class="check-summary">
                        <span class="status-dot $detailStatusClass"></span>
                        <span class="check-name">$([System.Net.WebUtility]::HtmlEncode($f.RODCName))</span>
                        <span class="check-target text-mono">Site: $([System.Net.WebUtility]::HtmlEncode($f.Site)) | IP: $([System.Net.WebUtility]::HtmlEncode($f.IPAddress))</span>
                        <span class="badge $detailStatusClass">$([System.Net.WebUtility]::HtmlEncode($f.OverallStatus))</span>
                    </summary>
                    <div class="check-detail">
                        <div class="detail-grid">
                            <div class="detail-block">
                                <h4>Missing SRV Records ($($f.MissingSRVRecords.Count))</h4>
                                <div class="evidence-block">$missingEvidence</div>
                            </div>
                            <div class="detail-block">
                                <h4>Incorrect SRV Records ($($f.IncorrectSRVRecords.Count))</h4>
                                <div class="evidence-block">$incorrectEvidence</div>
                            </div>
                        </div>
                        <div class="detail-grid">
                            <div class="detail-block">
                                <h4>A Record</h4>
                                <p>Status: <span class="badge $(if ($f.ARecordStatus -eq 'OK') { 'pass' } else { 'fail' })">$($f.ARecordStatus)</span></p>
                            </div>
                            <div class="detail-block">
                                <h4>PTR Record</h4>
                                <p>Status: <span class="badge $(switch ($f.PTRRecordStatus) { 'OK' { 'pass' } 'Missing' { 'fail' } default { 'info' } })">$($f.PTRRecordStatus)</span></p>
                            </div>
                        </div>
                        <div class="detail-block full-width">
                            <h4>DNS Scavenging</h4>
                            <p>$([System.Net.WebUtility]::HtmlEncode($f.ScavengingDetails))</p>
                        </div>
                    </div>
                </details>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>RODC DNS SRV Record Registration Report</title>
    <style>
/* ============================================================
   RODC DNS Registration Report -- Embedded Stylesheet
   Zero external dependencies. Fully offline renderable.
   ============================================================ */

:root {
    /* Palette */
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

    /* Typography */
    --font-sans:        'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
    --font-mono:        'Cascadia Code', 'Fira Code', 'JetBrains Mono', Consolas, 'Courier New', monospace;

    /* Spacing */
    --radius-sm:        4px;
    --radius-md:        8px;
    --radius-lg:        12px;

    --shadow-sm:        0 1px 3px rgba(0,0,0,0.3);
    --shadow-md:        0 4px 12px rgba(0,0,0,0.4);
    --shadow-lg:        0 8px 24px rgba(0,0,0,0.5);
}

/* ---- Reset & Base ---- */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html {
    font-size: 15px;
    scroll-behavior: smooth;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

body {
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
}

/* ---- Layout ---- */
.report-wrapper {
    max-width: 1400px;
    margin: 0 auto;
    padding: 24px 32px 64px;
}

/* ---- Header ---- */
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
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    margin-bottom: 8px;
    color: var(--text-primary);
}

.report-header .subtitle {
    font-size: 1.05rem;
    color: var(--text-secondary);
    font-weight: 400;
}

.report-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 24px;
    margin-top: 24px;
    padding-top: 20px;
    border-top: 1px solid var(--border-default);
}

.meta-item {
    display: flex;
    flex-direction: column;
    gap: 2px;
}

.meta-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    font-weight: 600;
}

.meta-value {
    font-size: 0.95rem;
    color: var(--text-primary);
    font-family: var(--font-mono);
}

/* ---- Score Dashboard ---- */
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
    padding: 24px;
    text-align: center;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}

.score-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
}

.score-card .score-value {
    font-size: 2.5rem;
    font-weight: 800;
    font-family: var(--font-mono);
    line-height: 1.1;
}

.score-card .score-label {
    font-size: 0.85rem;
    color: var(--text-secondary);
    margin-top: 6px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 600;
}

.score-card.total     .score-value { color: var(--info); }
.score-card.pass      .score-value { color: var(--pass); }
.score-card.warn      .score-value { color: var(--warn); }
.score-card.fail      .score-value { color: var(--fail); }

/* Score ring */
.score-ring-container {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 32px;
    background: var(--bg-card);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md);
    padding: 32px;
    margin-bottom: 32px;
}

.score-ring {
    position: relative;
    width: 160px;
    height: 160px;
}

.score-ring svg {
    transform: rotate(-90deg);
    width: 160px;
    height: 160px;
}

.score-ring .ring-bg {
    fill: none;
    stroke: var(--border-default);
    stroke-width: 12;
}

.score-ring .ring-fill {
    fill: none;
    stroke-width: 12;
    stroke-linecap: round;
    transition: stroke-dashoffset 0.6s ease;
}

.score-ring .ring-text {
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}

.score-ring .ring-text .pct {
    font-size: 2.2rem;
    font-weight: 800;
    font-family: var(--font-mono);
}

.score-ring .ring-text .ring-label {
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

.score-legend {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 0.9rem;
}

.legend-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    flex-shrink: 0;
}

.legend-dot.pass { background: var(--pass); }
.legend-dot.warn { background: var(--warn); }
.legend-dot.fail { background: var(--fail); }

.legend-count {
    font-family: var(--font-mono);
    font-weight: 600;
    min-width: 28px;
}

/* ---- Section ---- */
.report-section {
    margin-bottom: 28px;
}

.section-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px 20px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md) var(--radius-md) 0 0;
    cursor: default;
}

.section-icon {
    width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-sm);
    font-size: 1.1rem;
    flex-shrink: 0;
}

.section-icon.dns     { background: rgba(88,166,255,0.15); color: var(--info); }
.section-icon.rodc    { background: rgba(210,153,34,0.15); color: var(--warn); }
.section-icon.scav    { background: rgba(46,160,67,0.15); color: var(--pass); }

.section-title {
    font-size: 1.15rem;
    font-weight: 700;
    flex: 1;
}

.section-badge {
    display: flex;
    gap: 8px;
}

/* ---- Check Cards ---- */
.checks-container {
    border: 1px solid var(--border-default);
    border-top: none;
    border-radius: 0 0 var(--radius-md) var(--radius-md);
    overflow: hidden;
}

.check-card {
    border-bottom: 1px solid var(--border-muted);
    background: var(--bg-card);
    transition: background 0.1s ease;
}

.check-card:last-child {
    border-bottom: none;
}

.check-card:hover {
    background: var(--bg-card-hover);
}

.check-summary {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 14px 20px;
    cursor: pointer;
    list-style: none;
    user-select: none;
}

.check-summary::-webkit-details-marker { display: none; }

.check-summary::before {
    content: '\25B6';
    font-size: 0.65rem;
    color: var(--text-muted);
    transition: transform 0.15s ease;
    flex-shrink: 0;
}

details[open] > .check-summary::before {
    transform: rotate(90deg);
}

.status-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
}

.status-dot.pass { background: var(--pass); box-shadow: 0 0 6px var(--pass); }
.status-dot.warn { background: var(--warn); box-shadow: 0 0 6px var(--warn); }
.status-dot.fail { background: var(--fail); box-shadow: 0 0 6px var(--fail); }
.status-dot.info { background: var(--info); box-shadow: 0 0 6px var(--info); }

.check-name {
    font-weight: 600;
    flex: 1;
}

.check-target {
    font-family: var(--font-mono);
    font-size: 0.82rem;
    color: var(--text-secondary);
}

/* ---- Badge ---- */
.badge {
    display: inline-flex;
    align-items: center;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    flex-shrink: 0;
    white-space: nowrap;
}

.badge.pass { background: var(--pass-bg); color: var(--pass); border: 1px solid var(--pass-border); }
.badge.warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn-border); }
.badge.fail { background: var(--fail-bg); color: var(--fail); border: 1px solid var(--fail-border); }
.badge.info { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }

/* ---- Detail Panel ---- */
.check-detail {
    padding: 0 20px 20px 58px;
}

.detail-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
}

.detail-block {
    background: var(--bg-primary);
    border: 1px solid var(--border-muted);
    border-radius: var(--radius-sm);
    padding: 14px 16px;
}

.detail-block.full-width {
    grid-column: 1 / -1;
}

.detail-block h4 {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 8px;
    font-weight: 700;
}

.detail-block p {
    font-size: 0.9rem;
    color: var(--text-secondary);
    line-height: 1.65;
}

.evidence-block {
    background: var(--bg-input);
    border: 1px solid var(--border-muted);
    border-radius: var(--radius-sm);
    padding: 14px 18px;
    font-family: var(--font-mono);
    font-size: 0.82rem;
    color: var(--text-secondary);
    line-height: 1.7;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
}

/* ---- Data Tables ---- */
.data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    margin-bottom: 16px;
}

.data-table thead th {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: 0.72rem;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 2px solid var(--border-default);
    position: sticky;
    top: 0;
    z-index: 1;
}

.data-table tbody td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border-muted);
    color: var(--text-primary);
    vertical-align: top;
}

.data-table tbody tr:hover {
    background: var(--bg-card-hover);
}

.data-table .mono {
    font-family: var(--font-mono);
    font-size: 0.82rem;
}

/* Record lists inside table cells */
.record-list {
    list-style: none;
    padding: 0;
    margin: 0;
}

.record-list li {
    font-family: var(--font-mono);
    font-size: 0.78rem;
    padding: 3px 0;
    line-height: 1.4;
    word-break: break-all;
}

.record-list li::before {
    content: '\2022';
    margin-right: 6px;
}

.fail-list li::before { color: var(--fail); }
.warn-list li::before { color: var(--warn); }

/* ---- Summary Cards ---- */
.summary-card {
    background: var(--bg-card);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md);
    padding: 20px 24px;
    margin-bottom: 16px;
}

.summary-card h3 {
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    margin-bottom: 12px;
    font-weight: 700;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
}

.summary-metric {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    background: var(--bg-primary);
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-muted);
}

.summary-metric .metric-label {
    font-size: 0.85rem;
    color: var(--text-secondary);
}

.summary-metric .metric-value {
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 1.1rem;
}

/* ---- Footer ---- */
.report-footer {
    margin-top: 48px;
    padding: 24px 32px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md);
    text-align: center;
    color: var(--text-muted);
    font-size: 0.82rem;
}

.report-footer .disclaimer {
    margin-top: 8px;
    font-size: 0.75rem;
    color: var(--text-muted);
    font-style: italic;
}

/* ---- Utility ---- */
.text-pass { color: var(--pass) !important; }
.text-warn { color: var(--warn) !important; }
.text-fail { color: var(--fail) !important; }
.text-info { color: var(--info) !important; }
.text-muted { color: var(--text-muted) !important; }
.text-mono { font-family: var(--font-mono) !important; }

.mt-1 { margin-top: 8px; }
.mt-2 { margin-top: 16px; }
.mt-3 { margin-top: 24px; }
.mb-1 { margin-bottom: 8px; }
.mb-2 { margin-bottom: 16px; }
.mb-3 { margin-bottom: 24px; }

/* ---- Print ---- */
@media print {
    body { background: #fff; color: #1a1a1a; }
    .report-wrapper { max-width: 100%; padding: 12px; }
    .report-header { background: #f5f5f5; border-color: #ddd; }
    .report-header::before { background: #333; }
    .score-card, .check-card, .detail-block, .evidence-block {
        break-inside: avoid;
    }
    details { open: true; }
    details[open] > .check-detail { display: block; }
    .score-card:hover { transform: none; box-shadow: none; }
}

/* ---- Responsive ---- */
@media (max-width: 768px) {
    .report-wrapper { padding: 12px 16px 48px; }
    .report-header { padding: 24px; }
    .report-header h1 { font-size: 1.5rem; }
    .score-dashboard { grid-template-columns: repeat(2, 1fr); }
    .detail-grid { grid-template-columns: 1fr; }
    .report-meta { gap: 16px; }
    .score-ring-container { flex-direction: column; }
    .check-summary { padding: 12px 14px; gap: 10px; }
    .check-detail { padding-left: 36px; }
    .data-table { font-size: 0.78rem; }
    .data-table thead th,
    .data-table tbody td { padding: 8px 10px; }
}
    </style>
</head>
<body>
<div class="report-wrapper">

    <!-- ============================================================ -->
    <!-- Header                                                       -->
    <!-- ============================================================ -->
    <div class="report-header">
        <h1>RODC DNS SRV Record Registration Report</h1>
        <div class="subtitle">Read-Only Domain Controller DNS validation &mdash; $([System.Net.WebUtility]::HtmlEncode($domainFQDN))</div>
        <div class="report-meta">
            <div class="meta-item">
                <span class="meta-label">Generated</span>
                <span class="meta-value">$reportTimestamp</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Generated By</span>
                <span class="meta-value">$([System.Net.WebUtility]::HtmlEncode($env:USERNAME))</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Domain</span>
                <span class="meta-value">$([System.Net.WebUtility]::HtmlEncode($domainFQDN))</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Forest Root</span>
                <span class="meta-value">$([System.Net.WebUtility]::HtmlEncode($forestRoot))</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">DNS Server</span>
                <span class="meta-value">$([System.Net.WebUtility]::HtmlEncode($DnsServer))</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Execution Time</span>
                <span class="meta-value">${executionTime}s</span>
            </div>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Executive Summary Dashboard                                  -->
    <!-- ============================================================ -->
    <div class="score-ring-container">
        <div class="score-ring">
            <svg viewBox="0 0 160 160">
                <circle class="ring-bg" cx="80" cy="80" r="68"/>
                <circle class="ring-fill" cx="80" cy="80" r="68"
                        stroke="$ringColor"
                        stroke-dasharray="$circumference"
                        stroke-dashoffset="$ringOffset"/>
            </svg>
            <div class="ring-text">
                <div class="pct" style="color:$ringColor">$healthPct%</div>
                <div class="ring-label">RODC Health</div>
            </div>
        </div>
        <div class="score-legend">
            <div class="legend-item"><span class="legend-dot pass"></span><span class="legend-count">$rodcsPassed</span> Passed</div>
            <div class="legend-item"><span class="legend-dot warn"></span><span class="legend-count">$rodcsWarning</span> Warnings</div>
            <div class="legend-item"><span class="legend-dot fail"></span><span class="legend-count">$rodcsFailed</span> Failed</div>
        </div>
    </div>

    <div class="score-dashboard">
        <div class="score-card total"><div class="score-value">$totalRODCs</div><div class="score-label">Total RODCs</div></div>
        <div class="score-card pass"><div class="score-value">$rodcsPassed</div><div class="score-label">Passed</div></div>
        <div class="score-card warn"><div class="score-value">$rodcsWarning</div><div class="score-label">Warnings</div></div>
        <div class="score-card fail"><div class="score-value">$rodcsFailed</div><div class="score-label">Failed</div></div>
        <div class="score-card fail"><div class="score-value">$rodcsWithMissing</div><div class="score-label">Missing Records</div></div>
        <div class="score-card warn"><div class="score-value">$rodcsWithIncorrect</div><div class="score-label">Incorrect Records</div></div>
    </div>

    <div class="summary-card">
        <h3>Executive Summary</h3>
        <div class="summary-grid">
            <div class="summary-metric">
                <span class="metric-label">Total SRV Missing</span>
                <span class="metric-value $(if ($totalMissing -gt 0) { 'text-fail' } else { 'text-pass' })">$totalMissing</span>
            </div>
            <div class="summary-metric">
                <span class="metric-label">Total SRV Incorrect</span>
                <span class="metric-value $(if ($totalIncorrect -gt 0) { 'text-warn' } else { 'text-pass' })">$totalIncorrect</span>
            </div>
            <div class="summary-metric">
                <span class="metric-label">A Records Missing</span>
                <span class="metric-value $(if (($allFindings | Where-Object { $_.ARecordStatus -eq 'Missing' }).Count -gt 0) { 'text-fail' } else { 'text-pass' })">$(($allFindings | Where-Object { $_.ARecordStatus -eq 'Missing' }).Count)</span>
            </div>
            <div class="summary-metric">
                <span class="metric-label">PTR Records Missing</span>
                <span class="metric-value $(if (($allFindings | Where-Object { $_.PTRRecordStatus -eq 'Missing' }).Count -gt 0) { 'text-fail' } else { 'text-pass' })">$(($allFindings | Where-Object { $_.PTRRecordStatus -eq 'Missing' }).Count)</span>
            </div>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Findings Table                                               -->
    <!-- ============================================================ -->
    <div class="report-section">
        <div class="section-header">
            <div class="section-icon dns">&#9737;</div>
            <span class="section-title">RODC DNS Registration Findings</span>
            <div class="section-badge">
                $(if ($rodcsPassed -gt 0)  { "<span class=`"badge pass`">$rodcsPassed Pass</span>" })
                $(if ($rodcsWarning -gt 0) { "<span class=`"badge warn`">$rodcsWarning Warn</span>" })
                $(if ($rodcsFailed -gt 0)  { "<span class=`"badge fail`">$rodcsFailed Fail</span>" })
            </div>
        </div>
        <div class="checks-container" style="overflow-x:auto;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>RODC Name</th>
                        <th>Site</th>
                        <th>IP Address</th>
                        <th>Missing SRV Records</th>
                        <th>Incorrect SRV Records</th>
                        <th>A Record</th>
                        <th>PTR Record</th>
                        <th>Overall</th>
                    </tr>
                </thead>
                <tbody>
$tableRows
                </tbody>
            </table>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- DNS Scavenging Configuration                                 -->
    <!-- ============================================================ -->
    <div class="report-section">
        <div class="section-header">
            <div class="section-icon scav">&#9881;</div>
            <span class="section-title">DNS Scavenging Configuration</span>
        </div>
        <div class="checks-container" style="overflow-x:auto;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>RODC Name</th>
                        <th>Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
$scavengingRows
                </tbody>
            </table>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Evidence: Per-RODC Detail                                    -->
    <!-- ============================================================ -->
    <div class="report-section">
        <div class="section-header">
            <div class="section-icon rodc">&#128274;</div>
            <span class="section-title">Evidence: Per-RODC Detail</span>
        </div>
        <div class="checks-container">
$evidenceBlocks
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Footer                                                       -->
    <!-- ============================================================ -->
    <div class="report-footer">
        <div>RODC DNS SRV Record Registration Report &mdash; Generated $reportTimestamp</div>
        <div class="disclaimer">Read-only assessment. No modifications were made to DNS zones, records, or Active Directory objects. Remediation script (if generated) must be reviewed and executed separately.</div>
    </div>

</div>
</body>
</html>
"@

$html | Out-File -FilePath $htmlFile -Encoding UTF8 -Force
Write-Host "[+] HTML report: $htmlFile" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Region: Final Summary
# ---------------------------------------------------------------------------

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  RODC DNS Registration Check Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Total RODCs Checked  : $totalRODCs" -ForegroundColor White
Write-Host "  Passed               : $rodcsPassed" -ForegroundColor Green
Write-Host "  Warnings             : $rodcsWarning" -ForegroundColor Yellow
Write-Host "  Failed               : $rodcsFailed" -ForegroundColor Red
Write-Host "  Missing SRV Records  : $totalMissing" -ForegroundColor $(if ($totalMissing -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Incorrect SRV Records: $totalIncorrect" -ForegroundColor $(if ($totalIncorrect -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  HTML Report          : $htmlFile" -ForegroundColor White
Write-Host "  CSV Export           : $csvFile" -ForegroundColor White
Write-Host "  JSON Export          : $jsonFile" -ForegroundColor White
if ($GenerateRemediationScript) {
    Write-Host "  Remediation Script   : $remediationFile" -ForegroundColor White
}
Write-Host "  Execution Time       : ${executionTime}s" -ForegroundColor Gray
Write-Host "============================================================`n" -ForegroundColor Cyan
