#Requires -Version 5.1
<#
.SYNOPSIS
    Validates RODC security hardening against best practices.

.DESCRIPTION
    Test-RODCSecurityPosture.ps1 performs a comprehensive, read-only security
    assessment of all Read-Only Domain Controllers (RODCs) in the Active Directory
    environment. For each RODC, the script evaluates ten security hardening checks:

      1. BitLocker Encryption Status   - C: drive encryption via WMI/WinRM
      2. Local Administrator Membership - Excessive local admin accounts
      3. Delegated Admin Rights         - managedBy attribute validation
      4. PRP Deny List Coverage         - High-privilege group protection
      5. Cached Credential Count        - msDS-RevealedList threshold check
      6. RODC Account Password Age      - PasswordLastSet staleness detection
      7. NTDS Database Path Security    - Database volume validation via WinRM
      8. Event Log Retention            - Security log size and retention policy
      9. Replication Encryption         - LDAP signing requirement verification
     10. Physical Security Indicator    - AD site documentation completeness

    The script produces two output artefacts with timestamped filenames:
      - A self-contained dark-themed HTML report with executive summary dashboard,
        score ring, checklist table, and detailed per-RODC findings with remediation
      - A CSV file suitable for import into Excel or Power BI

    SAFETY:
      - All queries are strictly read-only.
      - No Active Directory objects are modified.
      - No Set-*, New-*, Remove-* commands are executed against targets.
      - WinRM queries are read-only (Get-* only).

.PARAMETER RODCName
    Optional. One or more RODC hostnames to check. If omitted, all RODCs in the
    domain are discovered via Get-ADDomainController -Filter {IsReadOnly -eq $true}.

.PARAMETER SiteFilter
    Optional. Limit the assessment to RODCs in a specific AD site name.

.PARAMETER MaxCachedCredThreshold
    Maximum number of cached credentials before a warning is raised. Default: 500.

.PARAMETER PasswordAgeThresholdDays
    Maximum password age in days for the RODC computer account before a warning
    is raised. Default: 180.

.PARAMETER OutputPath
    Directory for output files (HTML, CSV). Created if it does not exist.
    Defaults to C:\Reports\RODC.

.EXAMPLE
    .\Test-RODCSecurityPosture.ps1
    Checks all RODCs with default thresholds, writes output to C:\Reports\RODC.

.EXAMPLE
    .\Test-RODCSecurityPosture.ps1 -RODCName "RODC01" -OutputPath "D:\Audits\RODC"
    Checks only RODC01, outputs to D:\Audits\RODC.

.EXAMPLE
    .\Test-RODCSecurityPosture.ps1 -SiteFilter "BranchOffice-NYC" -MaxCachedCredThreshold 250
    Checks RODCs in the BranchOffice-NYC site with a tighter cached credential threshold.

.EXAMPLE
    .\Test-RODCSecurityPosture.ps1 -RODCName "RODC01","RODC02" -PasswordAgeThresholdDays 90 -Verbose
    Checks two named RODCs with a stricter password age policy and verbose output.

.NOTES
    Author  : AD Health Check Framework
    Version : 1.0.0
    Safety  : Read-only. No Set-*, New-*, Remove-* commands are executed.
    Requires: ActiveDirectory module, WinRM access to RODCs for remote checks.
    Run from: A domain controller or management server with RSAT and WinRM access.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true,
               HelpMessage = "One or more RODC hostnames. Omit to check all RODCs.")]
    [Alias("ComputerName", "Name")]
    [string[]]$RODCName,

    [Parameter(Mandatory = $false,
               HelpMessage = "Limit assessment to RODCs in a specific AD site.")]
    [string]$SiteFilter,

    [Parameter(Mandatory = $false,
               HelpMessage = "Max cached credentials before warning. Default: 500.")]
    [ValidateRange(1, 100000)]
    [int]$MaxCachedCredThreshold = 500,

    [Parameter(Mandatory = $false,
               HelpMessage = "Max password age in days before warning. Default: 180.")]
    [ValidateRange(1, 3650)]
    [int]$PasswordAgeThresholdDays = 180,

    [Parameter(Mandatory = $false,
               HelpMessage = "Output directory for reports. Defaults to C:\\Reports\\RODC.")]
    [string]$OutputPath = "C:\Reports\RODC"
)

# ---------------------------------------------------------------------------
# Region: Initialization
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$scriptStartTime = Get-Date

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  RODC Security Posture Assessment" -ForegroundColor Cyan
Write-Host "  Safe by Design -- Read-Only Queries Only" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# Verify required modules
$requiredModules = @('ActiveDirectory')
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
    Write-Verbose "Domain DN    : $domainDN"
    Write-Verbose "Forest Root  : $forestRoot"
    Write-Verbose "PDC Emulator : $pdcEmulator"
}
catch {
    Write-Error "Failed to query Active Directory domain/forest information: $($_.Exception.Message)"
    return
}

Write-Host "Domain       : $domainFQDN" -ForegroundColor White
Write-Host "Forest Root  : $forestRoot" -ForegroundColor White
Write-Host "PDC Emulator : $pdcEmulator" -ForegroundColor White

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

$htmlFile = Join-Path $OutputPath "RODC-SecurityPosture_$timestamp.html"
$csvFile  = Join-Path $OutputPath "RODC-SecurityPosture_$timestamp.csv"

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
                if ($SiteFilter -and $dc.Site -ne $SiteFilter) {
                    Write-Warning "'$name' is not in site '$SiteFilter'. Skipping."
                    continue
                }
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
        $allRODCs = @(Get-ADDomainController -Filter { IsReadOnly -eq $true } -ErrorAction Stop)
        if ($SiteFilter) {
            $rodcList = [System.Collections.ArrayList]@(
                $allRODCs | Where-Object { $_.Site -eq $SiteFilter }
            )
            if ($rodcList.Count -eq 0) {
                Write-Warning "No RODCs found in site '$SiteFilter'. Available sites with RODCs: $(($allRODCs | Select-Object -ExpandProperty Site -Unique) -join ', ')"
            }
        }
        else {
            $rodcList = [System.Collections.ArrayList]@($allRODCs)
        }
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

Write-Host "[+] Found $($rodcList.Count) RODC(s) to assess" -ForegroundColor Green
foreach ($rodc in $rodcList) {
    Write-Host "    - $($rodc.HostName) (Site: $($rodc.Site))" -ForegroundColor Gray
}
Write-Host ""

# ---------------------------------------------------------------------------
# Region: Helper Functions
# ---------------------------------------------------------------------------

function Test-WinRMConnectivity {
    <#
    .SYNOPSIS
        Tests whether WinRM is accessible on a remote host.
    .DESCRIPTION
        Performs a read-only Test-WSMan call to verify WinRM connectivity.
        Returns $true if reachable, $false otherwise. No modifications made.
    .PARAMETER ComputerName
        The target hostname to test.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName
    )

    try {
        $null = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
        return $true
    }
    catch {
        Write-Verbose "WinRM not reachable on '$ComputerName': $($_.Exception.Message)"
        return $false
    }
}

function Get-RemoteBitLockerStatus {
    <#
    .SYNOPSIS
        Queries BitLocker encryption status on a remote machine via WinRM.
    .DESCRIPTION
        Uses Invoke-Command to query Win32_EncryptableVolume WMI class for the
        C: drive. Returns a PSCustomObject with encryption status details.
        This is a read-only WMI query; no changes are made.
    .PARAMETER ComputerName
        The target RODC hostname.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName
    )

    $result = [PSCustomObject]@{
        IsEncrypted       = $false
        ProtectionStatus  = 'Unknown'
        EncryptionMethod  = 'Unknown'
        VolumeStatus      = 'Unknown'
        Error             = $null
    }

    try {
        $bitlockerData = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $vol = Get-WmiObject -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' `
                           -Class Win32_EncryptableVolume -Filter "DriveLetter='C:'" -ErrorAction Stop
                if ($vol) {
                    $protStatus = $vol.GetProtectionStatus().ProtectionStatus
                    $encMethod  = $vol.GetEncryptionMethod().EncryptionMethod
                    $convStatus = $vol.GetConversionStatus().ConversionStatus

                    $protLabel = switch ($protStatus) {
                        0 { 'Off' }
                        1 { 'On' }
                        2 { 'Unknown' }
                        default { "Code: $protStatus" }
                    }

                    $methodLabel = switch ($encMethod) {
                        0 { 'None' }
                        1 { 'AES-128-Diffuser' }
                        2 { 'AES-256-Diffuser' }
                        3 { 'AES-128' }
                        4 { 'AES-256' }
                        5 { 'Hardware' }
                        6 { 'XTS-AES-128' }
                        7 { 'XTS-AES-256' }
                        default { "Code: $encMethod" }
                    }

                    $convLabel = switch ($convStatus) {
                        0 { 'FullyDecrypted' }
                        1 { 'FullyEncrypted' }
                        2 { 'EncryptionInProgress' }
                        3 { 'DecryptionInProgress' }
                        4 { 'EncryptionPaused' }
                        5 { 'DecryptionPaused' }
                        default { "Code: $convStatus" }
                    }

                    return @{
                        IsEncrypted      = ($protStatus -eq 1)
                        ProtectionStatus = $protLabel
                        EncryptionMethod = $methodLabel
                        VolumeStatus     = $convLabel
                        Error            = $null
                    }
                }
                else {
                    return @{
                        IsEncrypted      = $false
                        ProtectionStatus = 'NotAvailable'
                        EncryptionMethod = 'N/A'
                        VolumeStatus     = 'N/A'
                        Error            = 'Win32_EncryptableVolume not found for C: drive'
                    }
                }
            }
            catch {
                return @{
                    IsEncrypted      = $false
                    ProtectionStatus = 'Error'
                    EncryptionMethod = 'Error'
                    VolumeStatus     = 'Error'
                    Error            = $_.Exception.Message
                }
            }
        } -ErrorAction Stop

        $result.IsEncrypted      = $bitlockerData.IsEncrypted
        $result.ProtectionStatus = $bitlockerData.ProtectionStatus
        $result.EncryptionMethod = $bitlockerData.EncryptionMethod
        $result.VolumeStatus     = $bitlockerData.VolumeStatus
        $result.Error            = $bitlockerData.Error
    }
    catch {
        $result.Error = "WinRM query failed: $($_.Exception.Message)"
    }

    return $result
}

function Get-RemoteLocalAdmins {
    <#
    .SYNOPSIS
        Queries the local Administrators group membership on a remote machine via WinRM.
    .DESCRIPTION
        Uses Invoke-Command to enumerate local Administrators group members.
        Read-only query; no modifications are made to group membership.
    .PARAMETER ComputerName
        The target RODC hostname.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName
    )

    $result = [PSCustomObject]@{
        Members    = @()
        MemberCount = 0
        Error       = $null
    }

    try {
        $adminData = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Try Get-LocalGroupMember first (Windows 10+ / Server 2016+)
                $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
                return @{
                    Members = @($members | ForEach-Object {
                        @{
                            Name          = $_.Name
                            ObjectClass   = $_.ObjectClass
                            PrincipalSource = "$($_.PrincipalSource)"
                        }
                    })
                    Error = $null
                }
            }
            catch {
                # Fallback to net localgroup
                try {
                    $output = net localgroup Administrators 2>&1
                    $members = @()
                    $capture = $false
                    foreach ($line in $output) {
                        if ($line -match '^---') { $capture = $true; continue }
                        if ($line -match '^The command completed') { $capture = $false; continue }
                        if ($capture -and $line.Trim()) {
                            $members += @{
                                Name          = $line.Trim()
                                ObjectClass   = 'Unknown'
                                PrincipalSource = 'NetLocalGroup'
                            }
                        }
                    }
                    return @{
                        Members = $members
                        Error   = $null
                    }
                }
                catch {
                    return @{
                        Members = @()
                        Error   = $_.Exception.Message
                    }
                }
            }
        } -ErrorAction Stop

        $result.Members     = @($adminData.Members)
        $result.MemberCount = $result.Members.Count
        $result.Error       = $adminData.Error
    }
    catch {
        $result.Error = "WinRM query failed: $($_.Exception.Message)"
    }

    return $result
}

function Get-RODCDelegatedAdmin {
    <#
    .SYNOPSIS
        Checks the managedBy attribute on an RODC computer object.
    .DESCRIPTION
        Reads the managedBy attribute from the RODC's AD computer object to
        determine delegated administration. Read-only AD query.
    .PARAMETER RODCDistinguishedName
        The distinguished name of the RODC computer object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RODCDistinguishedName
    )

    $result = [PSCustomObject]@{
        ManagedBy     = $null
        ManagedByName = $null
        IsDelegated   = $false
        Error         = $null
    }

    try {
        $computerObj = Get-ADComputer -Identity $RODCDistinguishedName `
                           -Properties managedBy -ErrorAction Stop
        if ($computerObj.managedBy) {
            $result.ManagedBy   = $computerObj.managedBy
            $result.IsDelegated = $true
            try {
                $managerObj = Get-ADObject -Identity $computerObj.managedBy `
                                  -Properties Name -ErrorAction Stop
                $result.ManagedByName = $managerObj.Name
            }
            catch {
                $result.ManagedByName = $computerObj.managedBy
                Write-Verbose "Could not resolve managedBy DN: $($_.Exception.Message)"
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Test-PRPDenyListCoverage {
    <#
    .SYNOPSIS
        Validates that the Password Replication Policy deny list includes
        all required high-privilege groups.
    .DESCRIPTION
        Reads the msDS-NeverRevealGroup attribute from the RODC computer object
        and checks for the presence of Domain Admins, Enterprise Admins,
        Schema Admins, Account Operators, and Server Operators.
        Read-only AD query only.
    .PARAMETER RODCHostName
        The RODC hostname to check.
    .PARAMETER DomainDN
        The domain distinguished name for group DN construction.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RODCHostName,
        [Parameter(Mandatory)][string]$DomainDN
    )

    $requiredGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Account Operators',
        'Server Operators'
    )

    $result = [PSCustomObject]@{
        DenyListEntries   = @()
        MissingGroups     = @()
        PresentGroups     = @()
        RequiredGroups    = $requiredGroups
        TotalDenyEntries  = 0
        IsCompliant       = $false
        Error             = $null
    }

    try {
        $rodcDC = Get-ADDomainController -Identity $RODCHostName -ErrorAction Stop
        $rodcComputer = Get-ADComputer -Identity $rodcDC.ComputerObjectDN `
                            -Properties 'msDS-NeverRevealGroup' -ErrorAction Stop

        $denyList = @($rodcComputer.'msDS-NeverRevealGroup')
        $result.DenyListEntries  = $denyList
        $result.TotalDenyEntries = $denyList.Count

        # Resolve each deny list entry to check for required groups
        $resolvedNames = @()
        foreach ($dn in $denyList) {
            try {
                $grpObj = Get-ADObject -Identity $dn -Properties Name -ErrorAction Stop
                $resolvedNames += $grpObj.Name
            }
            catch {
                # Try to extract CN from DN as fallback
                if ($dn -match '^CN=([^,]+),') {
                    $resolvedNames += $Matches[1]
                }
                Write-Verbose "Could not resolve deny list entry '$dn': $($_.Exception.Message)"
            }
        }

        foreach ($reqGroup in $requiredGroups) {
            $found = $false
            foreach ($resolvedName in $resolvedNames) {
                if ($resolvedName -eq $reqGroup) {
                    $found = $true
                    break
                }
            }
            # Also check raw DNs for partial match
            if (-not $found) {
                foreach ($dn in $denyList) {
                    if ($dn -match "CN=$([regex]::Escape($reqGroup)),") {
                        $found = $true
                        break
                    }
                }
            }

            if ($found) {
                $result.PresentGroups += $reqGroup
            }
            else {
                $result.MissingGroups += $reqGroup
            }
        }

        $result.IsCompliant = ($result.MissingGroups.Count -eq 0)
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-CachedCredentialCount {
    <#
    .SYNOPSIS
        Counts the number of cached (revealed) credentials on an RODC.
    .DESCRIPTION
        Reads the msDS-RevealedList attribute from the RODC computer object
        to determine how many credentials are currently cached.
        Read-only AD query only.
    .PARAMETER RODCHostName
        The RODC hostname to check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RODCHostName
    )

    $result = [PSCustomObject]@{
        CachedCount     = 0
        CachedAccounts  = @()
        Error           = $null
    }

    try {
        $rodcDC = Get-ADDomainController -Identity $RODCHostName -ErrorAction Stop
        $rodcComputer = Get-ADComputer -Identity $rodcDC.ComputerObjectDN `
                            -Properties 'msDS-RevealedList' -ErrorAction Stop

        $revealedList = @($rodcComputer.'msDS-RevealedList')
        # Each entry is a DN of a revealed user; filter unique accounts
        $uniqueAccounts = @()
        foreach ($entry in $revealedList) {
            if ($entry -and $entry -notin $uniqueAccounts) {
                $uniqueAccounts += $entry
            }
        }

        $result.CachedCount    = $uniqueAccounts.Count
        $result.CachedAccounts = $uniqueAccounts
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-RODCPasswordAge {
    <#
    .SYNOPSIS
        Checks the password age of an RODC computer account.
    .DESCRIPTION
        Reads the PasswordLastSet attribute from the RODC computer object
        and calculates the age in days. Read-only AD query.
    .PARAMETER RODCDistinguishedName
        The distinguished name of the RODC computer object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RODCDistinguishedName
    )

    $result = [PSCustomObject]@{
        PasswordLastSet = $null
        AgeDays         = -1
        Error           = $null
    }

    try {
        $computerObj = Get-ADComputer -Identity $RODCDistinguishedName `
                           -Properties PasswordLastSet -ErrorAction Stop
        if ($computerObj.PasswordLastSet) {
            $result.PasswordLastSet = $computerObj.PasswordLastSet
            $result.AgeDays = [math]::Round(((Get-Date) - $computerObj.PasswordLastSet).TotalDays, 0)
        }
        else {
            $result.AgeDays = -1
            $result.Error   = 'PasswordLastSet is null'
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-RemoteNTDSPath {
    <#
    .SYNOPSIS
        Queries the NTDS database path on a remote RODC via WinRM registry read.
    .DESCRIPTION
        Uses Invoke-Command to read the NTDS Parameters registry key and retrieve
        the database file path (DSA Database file). Read-only registry query.
    .PARAMETER ComputerName
        The target RODC hostname.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName
    )

    $result = [PSCustomObject]@{
        DatabasePath   = $null
        LogPath        = $null
        Volume         = $null
        IsDefaultPath  = $false
        Error          = $null
    }

    try {
        $ntdsData = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                $dbFile  = (Get-ItemProperty -Path $regPath -Name 'DSA Database file' -ErrorAction Stop).'DSA Database file'
                $logDir  = (Get-ItemProperty -Path $regPath -Name 'Database log files path' -ErrorAction Stop).'Database log files path'

                $volume = if ($dbFile -match '^([A-Z]:)') { $Matches[1] } else { 'Unknown' }
                $isDefault = ($dbFile -like '*\NTDS\ntds.dit' -or $dbFile -like '*\Windows\NTDS\ntds.dit')

                return @{
                    DatabasePath  = $dbFile
                    LogPath       = $logDir
                    Volume        = $volume
                    IsDefaultPath = $isDefault
                    Error         = $null
                }
            }
            catch {
                return @{
                    DatabasePath  = $null
                    LogPath       = $null
                    Volume        = $null
                    IsDefaultPath = $false
                    Error         = $_.Exception.Message
                }
            }
        } -ErrorAction Stop

        $result.DatabasePath  = $ntdsData.DatabasePath
        $result.LogPath       = $ntdsData.LogPath
        $result.Volume        = $ntdsData.Volume
        $result.IsDefaultPath = $ntdsData.IsDefaultPath
        $result.Error         = $ntdsData.Error
    }
    catch {
        $result.Error = "WinRM query failed: $($_.Exception.Message)"
    }

    return $result
}

function Get-RemoteEventLogConfig {
    <#
    .SYNOPSIS
        Queries the Security event log configuration on a remote RODC via WinRM.
    .DESCRIPTION
        Uses Invoke-Command to read the Security event log max size and retention
        settings. Read-only query; no log settings are changed.
    .PARAMETER ComputerName
        The target RODC hostname.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName
    )

    $result = [PSCustomObject]@{
        MaxSizeMB       = 0
        RetentionDays   = 0
        OverflowAction  = 'Unknown'
        RecordCount     = 0
        Error           = $null
    }

    try {
        $logData = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $log = Get-WinEvent -ListLog Security -ErrorAction Stop
                $maxSizeBytes = $log.MaximumSizeInBytes
                $maxSizeMB    = [math]::Round($maxSizeBytes / 1MB, 0)
                $retention    = $log.LogRetentionInDays
                if ($null -eq $retention) { $retention = 0 }

                # Get record count
                $recordCount = 0
                try {
                    $recordCount = $log.RecordCount
                }
                catch { $recordCount = 0 }

                # Determine overflow action
                $overflowAction = 'Unknown'
                try {
                    if ($log.IsLogFull) { $overflowAction = 'LogFull' }
                    elseif ($log.LogMode -eq 'Circular') { $overflowAction = 'OverwriteAsNeeded' }
                    elseif ($log.LogMode -eq 'Retain') { $overflowAction = 'DoNotOverwrite' }
                    elseif ($log.LogMode -eq 'AutoBackup') { $overflowAction = 'OverwriteOlder' }
                    else { $overflowAction = "$($log.LogMode)" }
                }
                catch { $overflowAction = 'Unknown' }

                return @{
                    MaxSizeMB      = $maxSizeMB
                    RetentionDays  = $retention
                    OverflowAction = $overflowAction
                    RecordCount    = $recordCount
                    Error          = $null
                }
            }
            catch {
                return @{
                    MaxSizeMB      = 0
                    RetentionDays  = 0
                    OverflowAction = 'Error'
                    RecordCount    = 0
                    Error          = $_.Exception.Message
                }
            }
        } -ErrorAction Stop

        $result.MaxSizeMB      = $logData.MaxSizeMB
        $result.RetentionDays  = $logData.RetentionDays
        $result.OverflowAction = $logData.OverflowAction
        $result.RecordCount    = $logData.RecordCount
        $result.Error          = $logData.Error
    }
    catch {
        $result.Error = "WinRM query failed: $($_.Exception.Message)"
    }

    return $result
}

function Get-RemoteLDAPSigningConfig {
    <#
    .SYNOPSIS
        Queries the LDAP signing requirement on a remote RODC via WinRM registry read.
    .DESCRIPTION
        Reads the 'LDAPServerIntegrity' registry value from NTDS Parameters
        and the 'ldapserverintegrity' value from the LSA key. Read-only query.
    .PARAMETER ComputerName
        The target RODC hostname.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName
    )

    $result = [PSCustomObject]@{
        LDAPSigningLevel    = 'Unknown'
        LDAPSigningValue    = -1
        ChannelBindingLevel = 'Unknown'
        Error               = $null
    }

    try {
        $signingData = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Check NTDS Parameters for LDAP server signing requirements
                $ntdsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                $ldapSigning = $null

                try {
                    $ldapSigning = (Get-ItemProperty -Path $ntdsPath `
                                       -Name 'ldap server signing requirements' `
                                       -ErrorAction Stop).'ldap server signing requirements'
                }
                catch {
                    # Key may not exist; check LSA path
                    try {
                        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
                        $ldapSigning = (Get-ItemProperty -Path $lsaPath `
                                           -Name 'LDAPServerIntegrity' `
                                           -ErrorAction Stop).LDAPServerIntegrity
                    }
                    catch {
                        $ldapSigning = $null
                    }
                }

                $signingLabel = switch ($ldapSigning) {
                    0       { 'None' }
                    1       { 'Require signing' }
                    2       { 'Require signing' }
                    $null   { 'Not configured (default)' }
                    default { "Unknown ($ldapSigning)" }
                }

                # Check channel binding token
                $cbtLevel = 'Unknown'
                try {
                    $cbtVal = (Get-ItemProperty -Path $ntdsPath `
                                  -Name 'LdapEnforceChannelBinding' `
                                  -ErrorAction Stop).LdapEnforceChannelBinding
                    $cbtLevel = switch ($cbtVal) {
                        0       { 'Never' }
                        1       { 'When supported' }
                        2       { 'Always' }
                        default { "Unknown ($cbtVal)" }
                    }
                }
                catch {
                    $cbtLevel = 'Not configured'
                }

                return @{
                    LDAPSigningLevel    = $signingLabel
                    LDAPSigningValue    = if ($null -ne $ldapSigning) { $ldapSigning } else { -1 }
                    ChannelBindingLevel = $cbtLevel
                    Error               = $null
                }
            }
            catch {
                return @{
                    LDAPSigningLevel    = 'Error'
                    LDAPSigningValue    = -1
                    ChannelBindingLevel = 'Error'
                    Error               = $_.Exception.Message
                }
            }
        } -ErrorAction Stop

        $result.LDAPSigningLevel    = $signingData.LDAPSigningLevel
        $result.LDAPSigningValue    = $signingData.LDAPSigningValue
        $result.ChannelBindingLevel = $signingData.ChannelBindingLevel
        $result.Error               = $signingData.Error
    }
    catch {
        $result.Error = "WinRM query failed: $($_.Exception.Message)"
    }

    return $result
}

function Get-ADSiteInfo {
    <#
    .SYNOPSIS
        Retrieves AD site information including description and location fields.
    .DESCRIPTION
        Queries the Sites container in Configuration partition for site metadata.
        Read-only AD query to check physical security documentation.
    .PARAMETER SiteName
        The AD site name to query.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteName
    )

    $result = [PSCustomObject]@{
        SiteName    = $SiteName
        Description = $null
        Location    = $null
        IsDocumented = $false
        Error        = $null
    }

    try {
        $configDN = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $siteDN   = "CN=$SiteName,CN=Sites,$configDN"

        $siteObj = Get-ADObject -Identity $siteDN `
                       -Properties Description, Location -ErrorAction Stop
        $result.Description  = $siteObj.Description
        $result.Location     = $siteObj.Location
        $result.IsDocumented = (
            (-not [string]::IsNullOrWhiteSpace($siteObj.Description)) -or
            (-not [string]::IsNullOrWhiteSpace($siteObj.Location))
        )
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function New-CheckResult {
    <#
    .SYNOPSIS
        Creates a standardized security check result object.
    .DESCRIPTION
        Factory function for consistent result objects across all ten checks.
    .PARAMETER CheckName
        The name of the security check.
    .PARAMETER Status
        The result status: Pass, Warn, Fail, or Unknown.
    .PARAMETER Details
        Human-readable description of findings.
    .PARAMETER Remediation
        Recommended remediation steps.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckName,
        [Parameter(Mandatory)][ValidateSet('Pass','Warn','Fail','Unknown')][string]$Status,
        [Parameter(Mandatory)][string]$Details,
        [string]$Remediation = 'No action required.'
    )

    return [PSCustomObject]@{
        CheckName   = $CheckName
        Status      = $Status
        Details     = $Details
        Remediation = $Remediation
    }
}

# ---------------------------------------------------------------------------
# Region: Main Security Assessment Loop
# ---------------------------------------------------------------------------

Write-Host "[*] Running security posture checks..." -ForegroundColor Yellow

$allFindings = [System.Collections.ArrayList]::new()

foreach ($rodc in $rodcList) {
    $rodcHostName  = $rodc.HostName
    $rodcShortName = $rodc.Name
    $rodcSite      = $rodc.Site
    $rodcIP        = $rodc.IPv4Address
    $rodcDN        = $rodc.ComputerObjectDN

    Write-Host "`n  Assessing: $rodcHostName (Site: $rodcSite, IP: $rodcIP)" -ForegroundColor White

    $rodcFinding = [PSCustomObject]@{
        RODCName          = $rodcHostName
        RODCShortName     = $rodcShortName
        Site              = $rodcSite
        IPAddress         = $rodcIP
        DistinguishedName = $rodcDN
        WinRMReachable    = $false
        Checks            = [System.Collections.ArrayList]::new()
        OverallStatus     = 'Pass'
        PassCount         = 0
        WarnCount         = 0
        FailCount         = 0
        UnknownCount      = 0
    }

    # Test WinRM connectivity first (needed for checks 1, 2, 7, 8, 9)
    Write-Verbose "  Testing WinRM connectivity to $rodcHostName..."
    $rodcFinding.WinRMReachable = Test-WinRMConnectivity -ComputerName $rodcHostName
    if ($rodcFinding.WinRMReachable) {
        Write-Verbose "  WinRM: Reachable"
    }
    else {
        Write-Verbose "  WinRM: Not reachable -- remote checks will return Unknown"
    }

    # ------------------------------------------------------------------
    # Check 1: BitLocker Encryption Status
    # ------------------------------------------------------------------
    Write-Verbose "  [1/10] Checking BitLocker encryption status..."

    if ($rodcFinding.WinRMReachable) {
        $bitlocker = Get-RemoteBitLockerStatus -ComputerName $rodcHostName
        if ($bitlocker.Error -and $bitlocker.ProtectionStatus -eq 'Error') {
            $check1 = New-CheckResult -CheckName 'BitLocker Encryption' -Status 'Unknown' `
                -Details "Unable to query BitLocker status: $($bitlocker.Error)" `
                -Remediation 'Verify WMI access to Win32_EncryptableVolume namespace on the RODC. Ensure the BitLocker feature is installed.'
        }
        elseif ($bitlocker.IsEncrypted) {
            $check1 = New-CheckResult -CheckName 'BitLocker Encryption' -Status 'Pass' `
                -Details "C: drive is encrypted. Method: $($bitlocker.EncryptionMethod). Volume status: $($bitlocker.VolumeStatus). Protection: $($bitlocker.ProtectionStatus)."
        }
        else {
            $check1 = New-CheckResult -CheckName 'BitLocker Encryption' -Status 'Fail' `
                -Details "C: drive is NOT encrypted. Protection: $($bitlocker.ProtectionStatus). Volume status: $($bitlocker.VolumeStatus)." `
                -Remediation 'Enable BitLocker on the RODC system volume. Use manage-bde -on C: or Enable-BitLocker via GPO. RODCs in branch offices should always have disk encryption enabled to prevent offline attacks on the NTDS database.'
        }
    }
    else {
        $check1 = New-CheckResult -CheckName 'BitLocker Encryption' -Status 'Unknown' `
            -Details 'WinRM is not reachable. Cannot query BitLocker status remotely.' `
            -Remediation 'Enable WinRM on the RODC and ensure firewall rules allow TCP 5985/5986. Alternatively, check BitLocker status locally using manage-bde -status C:'
    }
    $null = $rodcFinding.Checks.Add($check1)
    Write-Verbose "    Result: $($check1.Status)"

    # ------------------------------------------------------------------
    # Check 2: Local Administrator Membership
    # ------------------------------------------------------------------
    Write-Verbose "  [2/10] Checking local Administrator group membership..."

    if ($rodcFinding.WinRMReachable) {
        $localAdmins = Get-RemoteLocalAdmins -ComputerName $rodcHostName
        if ($localAdmins.Error) {
            $check2 = New-CheckResult -CheckName 'Local Admin Membership' -Status 'Unknown' `
                -Details "Unable to enumerate local Administrators: $($localAdmins.Error)" `
                -Remediation 'Verify WinRM connectivity and that the querying account has permission to enumerate local group members on the RODC.'
        }
        elseif ($localAdmins.MemberCount -gt 2) {
            $memberNames = ($localAdmins.Members | ForEach-Object { $_.Name }) -join ', '
            $check2 = New-CheckResult -CheckName 'Local Admin Membership' -Status 'Warn' `
                -Details "Local Administrators group has $($localAdmins.MemberCount) members (expected <= 2). Members: $memberNames" `
                -Remediation "Reduce local Administrators group to only Domain Admins and a single break-glass local account. Remove unnecessary members. Current members: $memberNames"
        }
        else {
            $memberNames = ($localAdmins.Members | ForEach-Object { $_.Name }) -join ', '
            $check2 = New-CheckResult -CheckName 'Local Admin Membership' -Status 'Pass' `
                -Details "Local Administrators group has $($localAdmins.MemberCount) member(s). Members: $memberNames"
        }
    }
    else {
        $check2 = New-CheckResult -CheckName 'Local Admin Membership' -Status 'Unknown' `
            -Details 'WinRM is not reachable. Cannot enumerate local Administrators group.' `
            -Remediation 'Enable WinRM on the RODC. Alternatively, check local admin membership by running net localgroup Administrators on the RODC directly.'
    }
    $null = $rodcFinding.Checks.Add($check2)
    Write-Verbose "    Result: $($check2.Status)"

    # ------------------------------------------------------------------
    # Check 3: Delegated Admin Rights on RODC Computer Object
    # ------------------------------------------------------------------
    Write-Verbose "  [3/10] Checking delegated admin rights (managedBy)..."

    $delegation = Get-RODCDelegatedAdmin -RODCDistinguishedName $rodcDN
    if ($delegation.Error) {
        $check3 = New-CheckResult -CheckName 'Delegated Admin Rights' -Status 'Unknown' `
            -Details "Unable to query managedBy attribute: $($delegation.Error)" `
            -Remediation 'Verify AD query access to the RODC computer object.'
    }
    elseif ($delegation.IsDelegated) {
        $check3 = New-CheckResult -CheckName 'Delegated Admin Rights' -Status 'Pass' `
            -Details "RODC administration is delegated to: $($delegation.ManagedByName) ($($delegation.ManagedBy))."
    }
    else {
        $check3 = New-CheckResult -CheckName 'Delegated Admin Rights' -Status 'Warn' `
            -Details 'No delegated administrator configured (managedBy is empty). RODC has no designated local admin delegate.' `
            -Remediation 'Set the managedBy attribute on the RODC computer object to designate a branch office IT contact. Use ADUC or: Set-ADComputer <RODC> -ManagedBy <UserOrGroup>. This enables delegated RODC password replication management.'
    }
    $null = $rodcFinding.Checks.Add($check3)
    Write-Verbose "    Result: $($check3.Status)"

    # ------------------------------------------------------------------
    # Check 4: PRP Deny List Coverage
    # ------------------------------------------------------------------
    Write-Verbose "  [4/10] Checking PRP deny list coverage..."

    $prpDeny = Test-PRPDenyListCoverage -RODCHostName $rodcHostName -DomainDN $domainDN
    if ($prpDeny.Error) {
        $check4 = New-CheckResult -CheckName 'PRP Deny List' -Status 'Unknown' `
            -Details "Unable to query PRP deny list: $($prpDeny.Error)" `
            -Remediation 'Verify AD query access to the RODC msDS-NeverRevealGroup attribute.'
    }
    elseif ($prpDeny.IsCompliant) {
        $check4 = New-CheckResult -CheckName 'PRP Deny List' -Status 'Pass' `
            -Details "All $($prpDeny.RequiredGroups.Count) required high-privilege groups are in the PRP deny list. Total deny entries: $($prpDeny.TotalDenyEntries). Present: $($prpDeny.PresentGroups -join ', ')."
    }
    else {
        $check4 = New-CheckResult -CheckName 'PRP Deny List' -Status 'Fail' `
            -Details "PRP deny list is missing $($prpDeny.MissingGroups.Count) required group(s): $($prpDeny.MissingGroups -join ', '). Present: $($prpDeny.PresentGroups -join ', '). Total deny entries: $($prpDeny.TotalDenyEntries)." `
            -Remediation "Add the following groups to the RODC PRP deny list (msDS-NeverRevealGroup): $($prpDeny.MissingGroups -join ', '). Use Active Directory Users and Computers > RODC Properties > Password Replication Policy tab, or: Get-ADDomainController <RODC> | Set-ADObject -Add @{'msDS-NeverRevealGroup'=<GroupDN>}"
    }
    $null = $rodcFinding.Checks.Add($check4)
    Write-Verbose "    Result: $($check4.Status)"

    # ------------------------------------------------------------------
    # Check 5: Cached Credential Count
    # ------------------------------------------------------------------
    Write-Verbose "  [5/10] Checking cached credential count..."

    $cachedCreds = Get-CachedCredentialCount -RODCHostName $rodcHostName
    if ($cachedCreds.Error) {
        $check5 = New-CheckResult -CheckName 'Cached Credentials' -Status 'Unknown' `
            -Details "Unable to query cached credentials: $($cachedCreds.Error)" `
            -Remediation 'Verify AD query access to the RODC msDS-RevealedList attribute.'
    }
    elseif ($cachedCreds.CachedCount -gt $MaxCachedCredThreshold) {
        $check5 = New-CheckResult -CheckName 'Cached Credentials' -Status 'Warn' `
            -Details "Cached credential count ($($cachedCreds.CachedCount)) exceeds threshold ($MaxCachedCredThreshold). This increases exposure if the RODC is compromised." `
            -Remediation "Review the Password Replication Policy (PRP) allow list. Reduce the number of cached accounts to below $MaxCachedCredThreshold. Consider using fine-grained PRP policies and removing broad group memberships from the allow list. After updating PRP, existing cached credentials remain until passwords are changed."
    }
    else {
        $check5 = New-CheckResult -CheckName 'Cached Credentials' -Status 'Pass' `
            -Details "Cached credential count ($($cachedCreds.CachedCount)) is within threshold ($MaxCachedCredThreshold)."
    }
    $null = $rodcFinding.Checks.Add($check5)
    Write-Verbose "    Result: $($check5.Status)"

    # ------------------------------------------------------------------
    # Check 6: RODC Account Password Age
    # ------------------------------------------------------------------
    Write-Verbose "  [6/10] Checking RODC account password age..."

    $pwdAge = Get-RODCPasswordAge -RODCDistinguishedName $rodcDN
    if ($pwdAge.Error -and $pwdAge.AgeDays -lt 0) {
        $check6 = New-CheckResult -CheckName 'Account Password Age' -Status 'Unknown' `
            -Details "Unable to determine password age: $($pwdAge.Error)" `
            -Remediation 'Verify AD query access to the PasswordLastSet attribute on the RODC computer object.'
    }
    elseif ($pwdAge.AgeDays -gt $PasswordAgeThresholdDays) {
        $check6 = New-CheckResult -CheckName 'Account Password Age' -Status 'Warn' `
            -Details "RODC computer account password is $($pwdAge.AgeDays) days old (threshold: $PasswordAgeThresholdDays days). Last set: $($pwdAge.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss'))." `
            -Remediation "The RODC machine account password should be rotated. Verify the computer account can communicate with a writable DC for automatic password updates. Check that the RODC is not isolated from the network. If the password is stale, consider resetting it: netdom resetpwd /server:<WritableDC> /userd:<Admin> /passwordd:*"
    }
    else {
        $lastSetStr = if ($pwdAge.PasswordLastSet) { $pwdAge.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Unknown' }
        $check6 = New-CheckResult -CheckName 'Account Password Age' -Status 'Pass' `
            -Details "RODC computer account password is $($pwdAge.AgeDays) days old (threshold: $PasswordAgeThresholdDays days). Last set: $lastSetStr."
    }
    $null = $rodcFinding.Checks.Add($check6)
    Write-Verbose "    Result: $($check6.Status)"

    # ------------------------------------------------------------------
    # Check 7: NTDS Database Path Security
    # ------------------------------------------------------------------
    Write-Verbose "  [7/10] Checking NTDS database path..."

    if ($rodcFinding.WinRMReachable) {
        $ntdsPath = Get-RemoteNTDSPath -ComputerName $rodcHostName
        if ($ntdsPath.Error) {
            $check7 = New-CheckResult -CheckName 'NTDS Database Path' -Status 'Unknown' `
                -Details "Unable to query NTDS database path: $($ntdsPath.Error)" `
                -Remediation 'Verify WinRM connectivity and registry read access to HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters on the RODC.'
        }
        elseif ($ntdsPath.DatabasePath) {
            $pathDetails = "Database: $($ntdsPath.DatabasePath). Log: $($ntdsPath.LogPath). Volume: $($ntdsPath.Volume)."
            if ($ntdsPath.Volume -eq 'C:') {
                $check7 = New-CheckResult -CheckName 'NTDS Database Path' -Status 'Warn' `
                    -Details "NTDS database is on the system volume (C:). $pathDetails Best practice is to place the NTDS database on a separate volume." `
                    -Remediation 'Consider relocating the NTDS database to a dedicated volume (e.g., D:\NTDS). This provides better I/O performance and easier BitLocker management. Use ntdsutil to move the database: ntdsutil > activate instance ntds > files > move db to <path>.'
            }
            else {
                $check7 = New-CheckResult -CheckName 'NTDS Database Path' -Status 'Pass' `
                    -Details "NTDS database is on a dedicated volume ($($ntdsPath.Volume)). $pathDetails"
            }
        }
        else {
            $check7 = New-CheckResult -CheckName 'NTDS Database Path' -Status 'Unknown' `
                -Details 'NTDS database path could not be determined from registry.' `
                -Remediation 'Manually verify the NTDS database path on the RODC. Check HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters for the "DSA Database file" value.'
        }
    }
    else {
        $check7 = New-CheckResult -CheckName 'NTDS Database Path' -Status 'Unknown' `
            -Details 'WinRM is not reachable. Cannot query NTDS database path remotely.' `
            -Remediation 'Enable WinRM on the RODC. Alternatively, check the NTDS path locally via registry or ntdsutil.'
    }
    $null = $rodcFinding.Checks.Add($check7)
    Write-Verbose "    Result: $($check7.Status)"

    # ------------------------------------------------------------------
    # Check 8: Event Log Retention Configuration
    # ------------------------------------------------------------------
    Write-Verbose "  [8/10] Checking event log retention configuration..."

    if ($rodcFinding.WinRMReachable) {
        $eventLog = Get-RemoteEventLogConfig -ComputerName $rodcHostName
        if ($eventLog.Error) {
            $check8 = New-CheckResult -CheckName 'Event Log Retention' -Status 'Unknown' `
                -Details "Unable to query Security event log configuration: $($eventLog.Error)" `
                -Remediation 'Verify WinRM connectivity and permissions to read event log configuration on the RODC.'
        }
        else {
            $issues = @()
            if ($eventLog.MaxSizeMB -lt 128) {
                $issues += "Security log max size ($($eventLog.MaxSizeMB) MB) is below recommended minimum (128 MB)"
            }
            if ($eventLog.RetentionDays -lt 7 -and $eventLog.OverflowAction -ne 'OverwriteAsNeeded') {
                $issues += "Retention ($($eventLog.RetentionDays) days) is below recommended minimum (7 days)"
            }

            if ($issues.Count -gt 0) {
                $check8 = New-CheckResult -CheckName 'Event Log Retention' -Status 'Warn' `
                    -Details "Security event log configuration issues: $($issues -join '; '). Current: MaxSize=$($eventLog.MaxSizeMB) MB, Retention=$($eventLog.RetentionDays) days, Mode=$($eventLog.OverflowAction), Records=$($eventLog.RecordCount)." `
                    -Remediation 'Increase the Security event log maximum size to at least 128 MB via GPO: Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security > Maximum Log Size. Set to 131072 KB (128 MB) or higher. Configure retention to at least 7 days or implement a SIEM forwarding solution.'
            }
            else {
                $check8 = New-CheckResult -CheckName 'Event Log Retention' -Status 'Pass' `
                    -Details "Security event log configuration is adequate. MaxSize=$($eventLog.MaxSizeMB) MB, Retention=$($eventLog.RetentionDays) days, Mode=$($eventLog.OverflowAction), Records=$($eventLog.RecordCount)."
            }
        }
    }
    else {
        $check8 = New-CheckResult -CheckName 'Event Log Retention' -Status 'Unknown' `
            -Details 'WinRM is not reachable. Cannot query event log configuration remotely.' `
            -Remediation 'Enable WinRM on the RODC. Alternatively, check event log configuration locally using wevtutil gl Security.'
    }
    $null = $rodcFinding.Checks.Add($check8)
    Write-Verbose "    Result: $($check8.Status)"

    # ------------------------------------------------------------------
    # Check 9: Replication Encryption (LDAP Signing)
    # ------------------------------------------------------------------
    Write-Verbose "  [9/10] Checking LDAP signing configuration..."

    if ($rodcFinding.WinRMReachable) {
        $ldapSigning = Get-RemoteLDAPSigningConfig -ComputerName $rodcHostName
        if ($ldapSigning.Error) {
            $check9 = New-CheckResult -CheckName 'Replication Encryption' -Status 'Unknown' `
                -Details "Unable to query LDAP signing configuration: $($ldapSigning.Error)" `
                -Remediation 'Verify WinRM connectivity and registry read access on the RODC.'
        }
        else {
            $signingOK = ($ldapSigning.LDAPSigningValue -ge 1)
            $cbtDetails = "Channel Binding: $($ldapSigning.ChannelBindingLevel)"

            if ($signingOK) {
                $check9 = New-CheckResult -CheckName 'Replication Encryption' -Status 'Pass' `
                    -Details "LDAP signing is required ($($ldapSigning.LDAPSigningLevel)). $cbtDetails."
            }
            elseif ($ldapSigning.LDAPSigningValue -eq -1) {
                $check9 = New-CheckResult -CheckName 'Replication Encryption' -Status 'Warn' `
                    -Details "LDAP signing is not explicitly configured (using default). Level: $($ldapSigning.LDAPSigningLevel). $cbtDetails." `
                    -Remediation 'Configure LDAP signing requirement via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Domain controller: LDAP server signing requirements = Require signing. Or set registry value at HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters "ldap server signing requirements" = 2.'
            }
            else {
                $check9 = New-CheckResult -CheckName 'Replication Encryption' -Status 'Fail' `
                    -Details "LDAP signing is set to None ($($ldapSigning.LDAPSigningLevel)). $cbtDetails. Replication traffic is not protected." `
                    -Remediation 'Enable LDAP signing requirement immediately. Set via GPO: Domain controller: LDAP server signing requirements = Require signing. This protects against man-in-the-middle attacks on LDAP traffic between the RODC and hub DC.'
            }
        }
    }
    else {
        $check9 = New-CheckResult -CheckName 'Replication Encryption' -Status 'Unknown' `
            -Details 'WinRM is not reachable. Cannot query LDAP signing configuration remotely.' `
            -Remediation 'Enable WinRM on the RODC. Alternatively, check registry value HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters "ldap server signing requirements" on the RODC locally.'
    }
    $null = $rodcFinding.Checks.Add($check9)
    Write-Verbose "    Result: $($check9.Status)"

    # ------------------------------------------------------------------
    # Check 10: Physical Security Indicator (Site Documentation)
    # ------------------------------------------------------------------
    Write-Verbose "  [10/10] Checking AD site documentation..."

    $siteInfo = Get-ADSiteInfo -SiteName $rodcSite
    if ($siteInfo.Error) {
        $check10 = New-CheckResult -CheckName 'Physical Security' -Status 'Unknown' `
            -Details "Unable to query AD site information for '$rodcSite': $($siteInfo.Error)" `
            -Remediation 'Verify AD query access to the Sites container in the Configuration partition.'
    }
    elseif ($siteInfo.IsDocumented) {
        $descText = if ($siteInfo.Description) { "Description: $($siteInfo.Description)" } else { 'Description: (empty)' }
        $locText  = if ($siteInfo.Location) { "Location: $($siteInfo.Location)" } else { 'Location: (empty)' }
        $check10  = New-CheckResult -CheckName 'Physical Security' -Status 'Pass' `
            -Details "AD site '$rodcSite' is documented. $descText. $locText."
    }
    else {
        $check10 = New-CheckResult -CheckName 'Physical Security' -Status 'Warn' `
            -Details "AD site '$rodcSite' has no Description or Location configured. Physical security posture cannot be determined from AD site metadata." `
            -Remediation "Document the AD site in Active Directory Sites and Services. Set the Description and Location fields for site '$rodcSite' to indicate physical security controls (e.g., locked room, security cameras). Use: Set-ADReplicationSite -Identity '$rodcSite' -Description '<PhysicalSecurityDetails>' or ADSS snap-in."
    }
    $null = $rodcFinding.Checks.Add($check10)
    Write-Verbose "    Result: $($check10.Status)"

    # ------------------------------------------------------------------
    # Calculate per-RODC summary
    # ------------------------------------------------------------------
    $rodcFinding.PassCount    = ($rodcFinding.Checks | Where-Object { $_.Status -eq 'Pass' }).Count
    $rodcFinding.WarnCount    = ($rodcFinding.Checks | Where-Object { $_.Status -eq 'Warn' }).Count
    $rodcFinding.FailCount    = ($rodcFinding.Checks | Where-Object { $_.Status -eq 'Fail' }).Count
    $rodcFinding.UnknownCount = ($rodcFinding.Checks | Where-Object { $_.Status -eq 'Unknown' }).Count

    if ($rodcFinding.FailCount -gt 0) {
        $rodcFinding.OverallStatus = 'Fail'
    }
    elseif ($rodcFinding.WarnCount -gt 0) {
        $rodcFinding.OverallStatus = 'Warning'
    }
    elseif ($rodcFinding.UnknownCount -eq $rodcFinding.Checks.Count) {
        $rodcFinding.OverallStatus = 'Unknown'
    }
    else {
        $rodcFinding.OverallStatus = 'Pass'
    }

    $statusColor = switch ($rodcFinding.OverallStatus) {
        'Pass'    { 'Green' }
        'Warning' { 'Yellow' }
        'Fail'    { 'Red' }
        default   { 'Gray' }
    }
    Write-Host "    Overall: $($rodcFinding.OverallStatus) (Pass: $($rodcFinding.PassCount), Warn: $($rodcFinding.WarnCount), Fail: $($rodcFinding.FailCount), Unknown: $($rodcFinding.UnknownCount))" -ForegroundColor $statusColor

    $null = $allFindings.Add($rodcFinding)
}

Write-Host "`n[+] All RODC security checks complete.`n" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Region: Summary Calculations
# ---------------------------------------------------------------------------

$totalRODCs     = $allFindings.Count
$rodcsPassed    = ($allFindings | Where-Object { $_.OverallStatus -eq 'Pass' }).Count
$rodcsFailed    = ($allFindings | Where-Object { $_.OverallStatus -eq 'Fail' }).Count
$rodcsWarning   = ($allFindings | Where-Object { $_.OverallStatus -eq 'Warning' }).Count
$rodcsUnknown   = ($allFindings | Where-Object { $_.OverallStatus -eq 'Unknown' }).Count

$totalChecks    = ($allFindings | ForEach-Object { $_.Checks.Count } | Measure-Object -Sum).Sum
$totalPassed    = ($allFindings | ForEach-Object { $_.PassCount } | Measure-Object -Sum).Sum
$totalWarnings  = ($allFindings | ForEach-Object { $_.WarnCount } | Measure-Object -Sum).Sum
$totalFailed    = ($allFindings | ForEach-Object { $_.FailCount } | Measure-Object -Sum).Sum
$totalUnknown   = ($allFindings | ForEach-Object { $_.UnknownCount } | Measure-Object -Sum).Sum

# Calculate critical findings (Fail status on high-impact checks)
$criticalFindings = 0
foreach ($f in $allFindings) {
    foreach ($c in $f.Checks) {
        if ($c.Status -eq 'Fail' -and $c.CheckName -in @('BitLocker Encryption', 'PRP Deny List', 'Replication Encryption')) {
            $criticalFindings++
        }
    }
}

$healthPct = if ($totalChecks -gt 0) { [math]::Round(($totalPassed / $totalChecks) * 100) } else { 0 }

# ---------------------------------------------------------------------------
# Region: CSV Export
# ---------------------------------------------------------------------------

Write-Host "[*] Exporting CSV..." -ForegroundColor Yellow

$csvData = foreach ($f in $allFindings) {
    # Get each check result for this RODC
    $bitlockerCheck = $f.Checks | Where-Object { $_.CheckName -eq 'BitLocker Encryption' } | Select-Object -First 1
    $localAdminCheck = $f.Checks | Where-Object { $_.CheckName -eq 'Local Admin Membership' } | Select-Object -First 1
    $delegationCheck = $f.Checks | Where-Object { $_.CheckName -eq 'Delegated Admin Rights' } | Select-Object -First 1
    $prpDenyCheck = $f.Checks | Where-Object { $_.CheckName -eq 'PRP Deny List' } | Select-Object -First 1
    $cachedCredsCheck = $f.Checks | Where-Object { $_.CheckName -eq 'Cached Credentials' } | Select-Object -First 1
    $pwdAgeCheck = $f.Checks | Where-Object { $_.CheckName -eq 'Account Password Age' } | Select-Object -First 1
    $ntdsPathCheck = $f.Checks | Where-Object { $_.CheckName -eq 'NTDS Database Path' } | Select-Object -First 1
    $eventLogCheck = $f.Checks | Where-Object { $_.CheckName -eq 'Event Log Retention' } | Select-Object -First 1
    $ldapSignCheck = $f.Checks | Where-Object { $_.CheckName -eq 'Replication Encryption' } | Select-Object -First 1
    $physSecCheck = $f.Checks | Where-Object { $_.CheckName -eq 'Physical Security' } | Select-Object -First 1

    [PSCustomObject]@{
        RODCName              = $f.RODCName
        Site                  = $f.Site
        IPAddress             = $f.IPAddress
        WinRMReachable        = $f.WinRMReachable
        OverallStatus         = $f.OverallStatus
        PassCount             = $f.PassCount
        WarnCount             = $f.WarnCount
        FailCount             = $f.FailCount
        UnknownCount          = $f.UnknownCount
        BitLocker_Status      = if ($bitlockerCheck) { $bitlockerCheck.Status } else { 'N/A' }
        BitLocker_Details     = if ($bitlockerCheck) { $bitlockerCheck.Details } else { '' }
        LocalAdmin_Status     = if ($localAdminCheck) { $localAdminCheck.Status } else { 'N/A' }
        LocalAdmin_Details    = if ($localAdminCheck) { $localAdminCheck.Details } else { '' }
        Delegation_Status     = if ($delegationCheck) { $delegationCheck.Status } else { 'N/A' }
        Delegation_Details    = if ($delegationCheck) { $delegationCheck.Details } else { '' }
        PRPDenyList_Status    = if ($prpDenyCheck) { $prpDenyCheck.Status } else { 'N/A' }
        PRPDenyList_Details   = if ($prpDenyCheck) { $prpDenyCheck.Details } else { '' }
        CachedCreds_Status    = if ($cachedCredsCheck) { $cachedCredsCheck.Status } else { 'N/A' }
        CachedCreds_Details   = if ($cachedCredsCheck) { $cachedCredsCheck.Details } else { '' }
        PasswordAge_Status    = if ($pwdAgeCheck) { $pwdAgeCheck.Status } else { 'N/A' }
        PasswordAge_Details   = if ($pwdAgeCheck) { $pwdAgeCheck.Details } else { '' }
        NTDSPath_Status       = if ($ntdsPathCheck) { $ntdsPathCheck.Status } else { 'N/A' }
        NTDSPath_Details      = if ($ntdsPathCheck) { $ntdsPathCheck.Details } else { '' }
        EventLog_Status       = if ($eventLogCheck) { $eventLogCheck.Status } else { 'N/A' }
        EventLog_Details      = if ($eventLogCheck) { $eventLogCheck.Details } else { '' }
        LDAPSigning_Status    = if ($ldapSignCheck) { $ldapSignCheck.Status } else { 'N/A' }
        LDAPSigning_Details   = if ($ldapSignCheck) { $ldapSignCheck.Details } else { '' }
        PhysicalSec_Status    = if ($physSecCheck) { $physSecCheck.Status } else { 'N/A' }
        PhysicalSec_Details   = if ($physSecCheck) { $physSecCheck.Details } else { '' }
    }
}

$csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
Write-Host "[+] CSV exported: $csvFile" -ForegroundColor Green

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

# Build checklist table rows
$checklistRows = ""
foreach ($f in $allFindings) {
    $statusClass = switch ($f.OverallStatus) {
        'Pass'    { 'pass' }
        'Warning' { 'warn' }
        'Fail'    { 'fail' }
        default   { 'info' }
    }

    # Get individual check statuses for table columns
    $checkNames = @(
        'BitLocker Encryption',
        'Local Admin Membership',
        'PRP Deny List',
        'Cached Credentials',
        'Account Password Age',
        'Event Log Retention'
    )
    $cellsHtml = ""
    foreach ($cn in $checkNames) {
        $chk = $f.Checks | Where-Object { $_.CheckName -eq $cn } | Select-Object -First 1
        $chkStatus = if ($chk) { $chk.Status } else { 'N/A' }
        $chkClass = switch ($chkStatus) {
            'Pass'    { 'pass' }
            'Warn'    { 'warn' }
            'Fail'    { 'fail' }
            'Unknown' { 'info' }
            default   { 'info' }
        }
        $cellsHtml += "                            <td><span class=`"badge $chkClass`">$chkStatus</span></td>`n"
    }

    $checklistRows += @"
                        <tr data-status="$statusClass">
                            <td class="mono">$([System.Net.WebUtility]::HtmlEncode($f.RODCShortName))</td>
                            <td>$([System.Net.WebUtility]::HtmlEncode($f.Site))</td>
$cellsHtml                            <td><span class="badge $statusClass">$([System.Net.WebUtility]::HtmlEncode($f.OverallStatus))</span></td>
                        </tr>
"@
}

# Build detailed findings section with expandable per-RODC details
$detailedFindings = ""
foreach ($f in $allFindings) {
    $detailStatusClass = switch ($f.OverallStatus) {
        'Pass'    { 'pass' }
        'Warning' { 'warn' }
        'Fail'    { 'fail' }
        default   { 'info' }
    }

    $openAttr = if ($f.OverallStatus -eq 'Fail') { ' open' } else { '' }

    # Build check rows for this RODC
    $checkRows = ""
    foreach ($chk in $f.Checks) {
        $chkClass = switch ($chk.Status) {
            'Pass'    { 'pass' }
            'Warn'    { 'warn' }
            'Fail'    { 'fail' }
            'Unknown' { 'info' }
            default   { 'info' }
        }

        $remediationHtml = if ($chk.Status -ne 'Pass') {
            "<div class=`"detail-block full-width`"><h4>Remediation</h4><p>$([System.Net.WebUtility]::HtmlEncode($chk.Remediation))</p></div>"
        }
        else {
            ""
        }

        $checkRows += @"
                            <div class="check-item" style="margin-bottom:12px; padding:12px 16px; background:var(--bg-primary); border:1px solid var(--border-muted); border-radius:var(--radius-sm);">
                                <div style="display:flex; align-items:center; gap:10px; margin-bottom:6px;">
                                    <span class="status-dot $chkClass"></span>
                                    <strong>$([System.Net.WebUtility]::HtmlEncode($chk.CheckName))</strong>
                                    <span class="badge $chkClass" style="margin-left:auto;">$([System.Net.WebUtility]::HtmlEncode($chk.Status))</span>
                                </div>
                                <div style="font-size:0.85rem; color:var(--text-secondary); line-height:1.6;">$([System.Net.WebUtility]::HtmlEncode($chk.Details))</div>
                                $remediationHtml
                            </div>
"@
    }

    $detailedFindings += @"
                <details class="check-card" data-status="$detailStatusClass"$openAttr>
                    <summary class="check-summary">
                        <span class="status-dot $detailStatusClass"></span>
                        <span class="check-name">$([System.Net.WebUtility]::HtmlEncode($f.RODCName))</span>
                        <span class="check-target text-mono">Site: $([System.Net.WebUtility]::HtmlEncode($f.Site)) | IP: $([System.Net.WebUtility]::HtmlEncode($f.IPAddress))</span>
                        <span class="badge $detailStatusClass">$([System.Net.WebUtility]::HtmlEncode($f.OverallStatus))</span>
                    </summary>
                    <div class="check-detail">
                        <div class="detail-grid" style="margin-bottom:16px;">
                            <div class="detail-block">
                                <h4>Summary</h4>
                                <p>Passed: <span class="text-pass">$($f.PassCount)</span> | Warnings: <span class="text-warn">$($f.WarnCount)</span> | Failed: <span class="text-fail">$($f.FailCount)</span> | Unknown: <span class="text-info">$($f.UnknownCount)</span></p>
                            </div>
                            <div class="detail-block">
                                <h4>Connectivity</h4>
                                <p>WinRM: <span class="badge $(if ($f.WinRMReachable) { 'pass' } else { 'fail' })">$(if ($f.WinRMReachable) { 'Reachable' } else { 'Unreachable' })</span></p>
                            </div>
                        </div>
$checkRows
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
    <title>RODC Security Posture Assessment Report</title>
    <style>
/* ============================================================
   RODC Security Posture Report -- Embedded Stylesheet
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
.score-card.critical  .score-value { color: var(--fail); }

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
.legend-dot.info { background: var(--info); }

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

.section-icon.security { background: rgba(248,81,73,0.15); color: var(--fail); }
.section-icon.check    { background: rgba(46,160,67,0.15); color: var(--pass); }
.section-icon.detail   { background: rgba(210,153,34,0.15); color: var(--warn); }
.section-icon.summary  { background: rgba(88,166,255,0.15); color: var(--info); }

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
        <h1>RODC Security Posture Assessment Report</h1>
        <div class="subtitle">Read-Only Domain Controller security hardening validation &mdash; $([System.Net.WebUtility]::HtmlEncode($domainFQDN))</div>
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
                <span class="meta-label">Cached Cred Threshold</span>
                <span class="meta-value">$MaxCachedCredThreshold</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Password Age Threshold</span>
                <span class="meta-value">${PasswordAgeThresholdDays}d</span>
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
                <div class="ring-label">Pass Rate</div>
            </div>
        </div>
        <div class="score-legend">
            <div class="legend-item"><span class="legend-dot pass"></span><span class="legend-count">$totalPassed</span> Passed Checks</div>
            <div class="legend-item"><span class="legend-dot warn"></span><span class="legend-count">$totalWarnings</span> Warnings</div>
            <div class="legend-item"><span class="legend-dot fail"></span><span class="legend-count">$totalFailed</span> Failed</div>
            <div class="legend-item"><span class="legend-dot info"></span><span class="legend-count">$totalUnknown</span> Unknown</div>
        </div>
    </div>

    <div class="score-dashboard">
        <div class="score-card total"><div class="score-value">$totalRODCs</div><div class="score-label">Total RODCs</div></div>
        <div class="score-card pass"><div class="score-value">$rodcsPassed</div><div class="score-label">Passed</div></div>
        <div class="score-card warn"><div class="score-value">$rodcsWarning</div><div class="score-label">Warnings</div></div>
        <div class="score-card fail"><div class="score-value">$rodcsFailed</div><div class="score-label">Failed</div></div>
        <div class="score-card critical"><div class="score-value">$criticalFindings</div><div class="score-label">Critical Findings</div></div>
    </div>

    <div class="summary-card">
        <h3>Executive Summary</h3>
        <div class="summary-grid">
            <div class="summary-metric">
                <span class="metric-label">Total Security Checks</span>
                <span class="metric-value text-info">$totalChecks</span>
            </div>
            <div class="summary-metric">
                <span class="metric-label">Pass Rate</span>
                <span class="metric-value $(if ($healthPct -ge 90) { 'text-pass' } elseif ($healthPct -ge 70) { 'text-warn' } else { 'text-fail' })">$healthPct%</span>
            </div>
            <div class="summary-metric">
                <span class="metric-label">Critical Findings</span>
                <span class="metric-value $(if ($criticalFindings -gt 0) { 'text-fail' } else { 'text-pass' })">$criticalFindings</span>
            </div>
            <div class="summary-metric">
                <span class="metric-label">WinRM Reachable</span>
                <span class="metric-value text-info">$(($allFindings | Where-Object { $_.WinRMReachable }).Count) / $totalRODCs</span>
            </div>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Security Checklist Table                                     -->
    <!-- ============================================================ -->
    <div class="report-section">
        <div class="section-header">
            <div class="section-icon check">&#9745;</div>
            <span class="section-title">Security Checklist</span>
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
                        <th>BitLocker</th>
                        <th>Local Admins</th>
                        <th>PRP Deny List</th>
                        <th>Cached Creds</th>
                        <th>Password Age</th>
                        <th>Event Log</th>
                        <th>Overall</th>
                    </tr>
                </thead>
                <tbody>
$checklistRows
                </tbody>
            </table>
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Detailed Findings: Per-RODC                                  -->
    <!-- ============================================================ -->
    <div class="report-section">
        <div class="section-header">
            <div class="section-icon detail">&#128274;</div>
            <span class="section-title">Detailed Findings &amp; Remediation</span>
        </div>
        <div class="checks-container">
$detailedFindings
        </div>
    </div>

    <!-- ============================================================ -->
    <!-- Footer                                                       -->
    <!-- ============================================================ -->
    <div class="report-footer">
        <div>RODC Security Posture Assessment Report &mdash; Generated $reportTimestamp</div>
        <div class="disclaimer">Read-only assessment. No modifications were made to Active Directory objects, local configurations, or security settings. All queries used Get-* cmdlets and read-only WMI/WinRM operations. Remediation steps are advisory and must be reviewed and executed manually by an authorized administrator.</div>
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
Write-Host "  RODC Security Posture Assessment Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Total RODCs Assessed : $totalRODCs" -ForegroundColor White
Write-Host "  Passed               : $rodcsPassed" -ForegroundColor Green
Write-Host "  Warnings             : $rodcsWarning" -ForegroundColor Yellow
Write-Host "  Failed               : $rodcsFailed" -ForegroundColor Red
Write-Host "  Unknown              : $rodcsUnknown" -ForegroundColor Gray
Write-Host "------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  Total Checks Run     : $totalChecks" -ForegroundColor White
Write-Host "  Checks Passed        : $totalPassed" -ForegroundColor Green
Write-Host "  Checks Warned        : $totalWarnings" -ForegroundColor Yellow
Write-Host "  Checks Failed        : $totalFailed" -ForegroundColor Red
Write-Host "  Checks Unknown       : $totalUnknown" -ForegroundColor Gray
Write-Host "  Critical Findings    : $criticalFindings" -ForegroundColor $(if ($criticalFindings -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Pass Rate            : $healthPct%" -ForegroundColor $(if ($healthPct -ge 90) { 'Green' } elseif ($healthPct -ge 70) { 'Yellow' } else { 'Red' })
Write-Host "------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  HTML Report          : $htmlFile" -ForegroundColor White
Write-Host "  CSV Export           : $csvFile" -ForegroundColor White
Write-Host "  Execution Time       : ${executionTime}s" -ForegroundColor Gray
Write-Host "============================================================`n" -ForegroundColor Cyan
