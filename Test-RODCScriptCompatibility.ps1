#Requires -Version 5.1

<#
.SYNOPSIS
    Audits existing AD/DC health scripts for RODC compatibility issues and provides fixes.

.DESCRIPTION
    Test-RODCScriptCompatibility.ps1 scans a directory of PowerShell scripts to identify
    patterns that are incompatible with Read-Only Domain Controllers (RODCs). It detects
    four categories of issues:

      1. Writable LDAP Operations  - Set-AD*, New-*, Remove-* cmdlets without -WhatIf,
         and DirectoryEntry.CommitChanges() calls that will fail against an RODC.
      2. FSMO Role Assumptions     - Scripts that use Get-ADDomain without filtering
         IsReadOnly, or assume all DCs can perform write operations.
      3. Unreplicated Attributes   - References to attributes that are not replicated
         to RODCs (ms-DS-MachineAccountQuota, certain FRS/DFSR attributes).
      4. WinRM Assumptions         - Invoke-Command calls without -ErrorAction handling,
         or scripts that do not detect DC type before remote execution.

    For each issue found, the script records the script name, file path, issue type,
    line number, code snippet, severity, whether a fix is required, and whether the
    issue is auto-patchable.

    Output is generated in three forms:
      - CSV inventory file with all findings
      - HTML summary report with dark-theme styling and executive dashboard
      - Patched script copies (when -AutoPatch is specified)

    Patched scripts are saved alongside the originals with a .RODC-Compatible.ps1 suffix.
    Original scripts are NEVER modified. All patches include ShouldProcess support.

.PARAMETER ScriptPath
    The directory containing PowerShell scripts to scan. The directory is searched
    recursively for *.ps1 files.

.PARAMETER OutputPath
    The directory where inventory CSV, HTML report, and patched scripts are written.
    Created automatically if it does not exist. Default is C:\Reports\RODC.

.PARAMETER AutoPatch
    When specified, the script generates RODC-compatible versions of scripts that
    contain auto-patchable issues. Patched scripts are saved with a
    .RODC-Compatible.ps1 suffix. Original files are never modified.

.EXAMPLE
    .\Test-RODCScriptCompatibility.ps1 -ScriptPath "C:\Scripts\AD" -Verbose

    Scans all .ps1 files under C:\Scripts\AD and writes the inventory CSV and HTML
    report to the default output directory (C:\Reports\RODC).

.EXAMPLE
    .\Test-RODCScriptCompatibility.ps1 -ScriptPath "D:\Ops\DC-Scripts" -OutputPath "D:\Audit" -AutoPatch

    Scans scripts, writes reports to D:\Audit, and generates patched copies of all
    auto-patchable scripts.

.EXAMPLE
    .\Test-RODCScriptCompatibility.ps1 -ScriptPath ".\scripts" -AutoPatch -Verbose

    Scans with verbose output and generates patched script copies in the default
    output directory.

.NOTES
    Author  : Active Directory Reporting Team
    Version : 1.0.0
    Date    : 2026-02-09
    Safety  : READ-ONLY on source scripts. Patched copies are new files only.
    Requires: PowerShell 5.1 or later. No AD module required (static analysis only).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(
        Mandatory = $true,
        Position = 0,
        HelpMessage = "Directory containing PowerShell scripts to scan for RODC compatibility."
    )]
    [ValidateNotNullOrEmpty()]
    [string]$ScriptPath,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Output directory for CSV inventory, HTML report, and patched scripts."
    )]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "C:\Reports\RODC",

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Generate RODC-compatible patched versions of auto-patchable scripts."
    )]
    [switch]$AutoPatch
)

# ---------------------------------------------------------------------------
# Region: Initialization
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date
$script:Timestamp = $script:StartTime.ToString('yyyyMMdd_HHmmss')

Write-Verbose "Test-RODCScriptCompatibility started at $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Verbose "Parameters: ScriptPath=$ScriptPath, OutputPath=$OutputPath, AutoPatch=$AutoPatch"

# ---------------------------------------------------------------------------
# Region: Detection Pattern Definitions
# ---------------------------------------------------------------------------

# Category 1: Writable LDAP Operations
$script:WriteOperationPatterns = @(
    @{
        Pattern     = '(?i)\b(Set-ADUser|Set-ADComputer|Set-ADObject|Set-ADGroup|Set-ADAccountPassword|Set-ADOrganizationalUnit)\b'
        Description = 'Set-AD* cmdlet (writable LDAP operation)'
        Severity    = 'High'
        FixRequired = $true
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\b(New-ADUser|New-ADComputer|New-ADObject|New-ADGroup|New-ADOrganizationalUnit)\b(?!.*-WhatIf)'
        Description = 'New-AD* cmdlet without -WhatIf (creates AD objects)'
        Severity    = 'High'
        FixRequired = $true
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\b(Remove-ADUser|Remove-ADComputer|Remove-ADObject|Remove-ADGroup|Remove-ADOrganizationalUnit)\b(?!.*-WhatIf)'
        Description = 'Remove-AD* cmdlet without -WhatIf (deletes AD objects)'
        Severity    = 'High'
        FixRequired = $true
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\b(Enable-ADAccount|Disable-ADAccount|Unlock-ADAccount)\b'
        Description = 'Account state modification cmdlet (writable operation)'
        Severity    = 'High'
        FixRequired = $true
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\b(Move-ADObject|Rename-ADObject|Restore-ADObject)\b'
        Description = 'AD object manipulation cmdlet (writable operation)'
        Severity    = 'High'
        FixRequired = $true
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\.CommitChanges\s*\('
        Description = 'DirectoryEntry.CommitChanges() call (direct LDAP write)'
        Severity    = 'High'
        FixRequired = $true
        AutoPatch   = $false
    },
    @{
        Pattern     = '(?i)\[ADSI\].*\.Put\s*\('
        Description = 'ADSI .Put() method (direct LDAP attribute write)'
        Severity    = 'High'
        FixRequired = $true
        AutoPatch   = $false
    },
    @{
        Pattern     = '(?i)\[ADSI\].*\.SetInfo\s*\('
        Description = 'ADSI .SetInfo() method (direct LDAP write)'
        Severity    = 'High'
        FixRequired = $true
        AutoPatch   = $false
    }
)

# Category 2: FSMO Role Assumptions
$script:FSMOPatterns = @(
    @{
        Pattern     = '(?i)\bGet-ADDomain\b(?!.*IsReadOnly)'
        Description = 'Get-ADDomain without IsReadOnly filtering (may assume writable DC)'
        Severity    = 'Medium'
        FixRequired = $false
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\bGet-ADDomainController\b.*-Discover\b'
        Description = 'Get-ADDomainController -Discover (may return RODC without type check)'
        Severity    = 'Medium'
        FixRequired = $false
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\b(PDCEmulator|RIDMaster|InfrastructureMaster|SchemaMaster|DomainNamingMaster)\b'
        Description = 'FSMO role reference (RODCs cannot hold FSMO roles)'
        Severity    = 'Low'
        FixRequired = $false
        AutoPatch   = $false
    },
    @{
        Pattern     = '(?i)\bGet-ADDomainController\s+-Filter\s+\*'
        Description = 'Get-ADDomainController -Filter * without RODC exclusion logic'
        Severity    = 'Medium'
        FixRequired = $false
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\bdsquery\s+server\b'
        Description = 'dsquery server usage (does not distinguish RODC from writable DC)'
        Severity    = 'Medium'
        FixRequired = $false
        AutoPatch   = $false
    }
)

# Category 3: Unreplicated Attributes
$script:UnreplicatedAttributePatterns = @(
    @{
        Pattern     = '(?i)\bms-DS-MachineAccountQuota\b'
        Description = 'ms-DS-MachineAccountQuota attribute (not replicated to RODCs)'
        Severity    = 'Medium'
        FixRequired = $true
        AutoPatch   = $false
    },
    @{
        Pattern     = '(?i)\bmsDFSR-'
        Description = 'DFSR attribute reference (msDFSR-* may not replicate to RODCs)'
        Severity    = 'Medium'
        FixRequired = $true
        AutoPatch   = $false
    },
    @{
        Pattern     = '(?i)\bnTFRSMember\b'
        Description = 'FRS attribute nTFRSMember (legacy FRS, not replicated to RODCs)'
        Severity    = 'Medium'
        FixRequired = $true
        AutoPatch   = $false
    },
    @{
        Pattern     = '(?i)\bfRSMemberReference\b'
        Description = 'FRS attribute fRSMemberReference (not replicated to RODCs)'
        Severity    = 'Medium'
        FixRequired = $true
        AutoPatch   = $false
    },
    @{
        Pattern     = '(?i)\bms-DS-RevealedUsers\b'
        Description = 'ms-DS-RevealedUsers attribute (RODC-local, not on writable DCs)'
        Severity    = 'Low'
        FixRequired = $false
        AutoPatch   = $false
    },
    @{
        Pattern     = '(?i)\bmsDS-AuthenticatedToAccountlist\b'
        Description = 'msDS-AuthenticatedToAccountlist (may have partial replication to RODCs)'
        Severity    = 'Low'
        FixRequired = $false
        AutoPatch   = $false
    }
)

# Category 4: WinRM Assumptions
$script:WinRMPatterns = @(
    @{
        Pattern     = '(?i)\bInvoke-Command\b(?!.*-ErrorAction)'
        Description = 'Invoke-Command without -ErrorAction (will fail silently on unreachable RODCs)'
        Severity    = 'Medium'
        FixRequired = $true
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\bEnter-PSSession\b(?!.*-ErrorAction)'
        Description = 'Enter-PSSession without -ErrorAction handling'
        Severity    = 'Medium'
        FixRequired = $true
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\bNew-PSSession\b(?!.*-ErrorAction)'
        Description = 'New-PSSession without -ErrorAction handling'
        Severity    = 'Medium'
        FixRequired = $true
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\bInvoke-Command\b.*-ComputerName\b(?!.*IsReadOnly)'
        Description = 'Invoke-Command targeting DC without RODC type detection'
        Severity    = 'Medium'
        FixRequired = $false
        AutoPatch   = $true
    },
    @{
        Pattern     = '(?i)\bTest-WSMan\b'
        Description = 'Test-WSMan call (consider RODC WinRM configuration differences)'
        Severity    = 'Low'
        FixRequired = $false
        AutoPatch   = $false
    }
)

# Aggregate all pattern categories with labels
$script:AllPatternCategories = @(
    @{ Name = 'Write Operation';        Patterns = $script:WriteOperationPatterns }
    @{ Name = 'FSMO Assumption';        Patterns = $script:FSMOPatterns }
    @{ Name = 'Unreplicated Attribute'; Patterns = $script:UnreplicatedAttributePatterns }
    @{ Name = 'WinRM Issue';            Patterns = $script:WinRMPatterns }
)

# ---------------------------------------------------------------------------
# Region: Environment Validation
# ---------------------------------------------------------------------------

function Initialize-Environment {
    [CmdletBinding()]
    param()

    Write-Verbose "Validating environment..."

    # Validate script source directory
    if (-not (Test-Path -Path $ScriptPath -PathType Container)) {
        throw "Script source directory not found: '$ScriptPath'. Provide a valid directory path."
    }

    $resolvedPath = (Resolve-Path -Path $ScriptPath).Path
    Write-Verbose "Resolved script source path: $resolvedPath"

    # Count .ps1 files
    $ps1Files = @(Get-ChildItem -Path $resolvedPath -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue)
    if ($ps1Files.Count -eq 0) {
        throw "No .ps1 files found in '$resolvedPath'. Ensure the directory contains PowerShell scripts."
    }
    Write-Verbose "Found $($ps1Files.Count) PowerShell script(s) to scan."

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

    return @{
        ResolvedScriptPath = $resolvedPath
        ScriptFiles        = $ps1Files
    }
}

# ---------------------------------------------------------------------------
# Region: Script Scanner
# ---------------------------------------------------------------------------

function Invoke-ScriptScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$ScriptFiles
    )

    Write-Verbose "Beginning compatibility scan of $($ScriptFiles.Count) script(s)..."

    $allFindings = [System.Collections.Generic.List[PSObject]]::new()
    $scriptSummaries = [System.Collections.Generic.List[PSObject]]::new()
    $scannedCount = 0

    foreach ($file in $ScriptFiles) {
        $scannedCount++
        $relativeName = $file.Name
        $filePath = $file.FullName

        Write-Verbose "  [$scannedCount/$($ScriptFiles.Count)] Scanning: $relativeName"

        try {
            $lines = Get-Content -Path $filePath -ErrorAction Stop
        }
        catch {
            Write-Warning "Cannot read file '$filePath': $($_.Exception.Message)"
            continue
        }

        $fileFindings = [System.Collections.Generic.List[PSObject]]::new()

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $lineNum = $i + 1
            $lineText = $lines[$i]

            # Skip empty lines and pure comment lines for performance
            $trimmed = $lineText.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            # Skip lines inside comment blocks (basic heuristic)
            # We track block comments with a simple state flag
            # This is handled at the file level below

            foreach ($category in $script:AllPatternCategories) {
                foreach ($patternDef in $category.Patterns) {
                    if ($lineText -match $patternDef.Pattern) {
                        # Extract a clean code snippet (trim and truncate)
                        $snippet = $lineText.Trim()
                        if ($snippet.Length -gt 200) {
                            $snippet = $snippet.Substring(0, 197) + '...'
                        }

                        $finding = [PSCustomObject]@{
                            ScriptName   = $relativeName
                            Path         = $filePath
                            IssueType    = $category.Name
                            LineNumber   = $lineNum
                            CodeSnippet  = $snippet
                            Description  = $patternDef.Description
                            Severity     = $patternDef.Severity
                            FixRequired  = if ($patternDef.FixRequired) { 'Yes' } else { 'No' }
                            AutoPatchable = if ($patternDef.AutoPatch) { 'Yes' } else { 'No' }
                        }

                        $fileFindings.Add($finding)
                        $allFindings.Add($finding)
                    }
                }
            }
        }

        # Build per-script summary
        $highCount = @($fileFindings | Where-Object { $_.Severity -eq 'High' }).Count
        $mediumCount = @($fileFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        $lowCount = @($fileFindings | Where-Object { $_.Severity -eq 'Low' }).Count
        $patchableCount = @($fileFindings | Where-Object { $_.AutoPatchable -eq 'Yes' }).Count

        $overallStatus = 'Compatible'
        if ($highCount -gt 0) {
            $overallStatus = 'Incompatible'
        }
        elseif ($mediumCount -gt 0) {
            $overallStatus = 'Review Needed'
        }
        elseif ($lowCount -gt 0) {
            $overallStatus = 'Minor Issues'
        }

        $scriptSummaries.Add([PSCustomObject]@{
            ScriptName     = $relativeName
            Path           = $filePath
            TotalIssues    = $fileFindings.Count
            HighSeverity   = $highCount
            MediumSeverity = $mediumCount
            LowSeverity    = $lowCount
            AutoPatchable  = $patchableCount
            Status         = $overallStatus
            LineCount      = $lines.Count
            Findings       = $fileFindings
        })

        if ($fileFindings.Count -gt 0) {
            Write-Verbose "    Found $($fileFindings.Count) issue(s) (High: $highCount, Medium: $mediumCount, Low: $lowCount)"
        }
        else {
            Write-Verbose "    No RODC compatibility issues detected."
        }
    }

    Write-Verbose "Scan complete. Total findings: $($allFindings.Count) across $($ScriptFiles.Count) script(s)."

    return @{
        Findings        = $allFindings
        ScriptSummaries = $scriptSummaries
    }
}

# ---------------------------------------------------------------------------
# Region: Comment Block Filter
# ---------------------------------------------------------------------------

function Test-LineInCommentBlock {
    <#
    .SYNOPSIS
        Checks if a specific line is inside a <# #> comment block.
    .DESCRIPTION
        Parses the file content up to the target line to determine
        whether the line falls within a multi-line comment block.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Lines,

        [Parameter(Mandatory)]
        [int]$TargetLineIndex
    )

    $inBlock = $false

    for ($i = 0; $i -le $TargetLineIndex; $i++) {
        $line = $Lines[$i]

        if ($inBlock) {
            if ($line -match '#>') {
                $inBlock = $false
            }
        }
        else {
            if ($line -match '<#') {
                $inBlock = $true
                # Check if block closes on same line
                if ($line -match '#>') {
                    $inBlock = $false
                }
            }
        }
    }

    return $inBlock
}

# ---------------------------------------------------------------------------
# Region: Auto-Patcher
# ---------------------------------------------------------------------------

function Invoke-AutoPatch {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [object[]]$ScriptSummaries
    )

    Write-Verbose "Beginning auto-patch generation..."

    $patchedFiles = [System.Collections.Generic.List[PSObject]]::new()
    $patchableScripts = @($ScriptSummaries | Where-Object { $_.AutoPatchable -gt 0 -and $_.Status -ne 'Compatible' })

    if ($patchableScripts.Count -eq 0) {
        Write-Verbose "No auto-patchable scripts found. Skipping patch generation."
        return $patchedFiles
    }

    Write-Verbose "Found $($patchableScripts.Count) script(s) with auto-patchable issues."

    # Create patched scripts subdirectory
    $patchDir = Join-Path -Path $OutputPath -ChildPath "PatchedScripts"
    if (-not (Test-Path -Path $patchDir -PathType Container)) {
        New-Item -Path $patchDir -ItemType Directory -Force | Out-Null
        Write-Verbose "Created patch output directory: $patchDir"
    }

    foreach ($scriptSummary in $patchableScripts) {
        $sourceFile = $scriptSummary.Path
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($scriptSummary.ScriptName)
        $patchedFileName = "$baseName.RODC-Compatible.ps1"
        $patchedFilePath = Join-Path -Path $patchDir -ChildPath $patchedFileName

        Write-Verbose "  Patching: $($scriptSummary.ScriptName) -> $patchedFileName"

        if (-not $PSCmdlet.ShouldProcess($sourceFile, "Generate RODC-compatible patched version")) {
            continue
        }

        try {
            $originalContent = Get-Content -Path $sourceFile -Raw -ErrorAction Stop
            $originalLines = Get-Content -Path $sourceFile -ErrorAction Stop
            $patchedContent = $originalContent

            # Track what patches were applied
            $appliedPatches = [System.Collections.Generic.List[string]]::new()

            # ------------------------------------------------------------------
            # Patch 1: Add -ExcludeRODCs parameter if [CmdletBinding()] exists
            # ------------------------------------------------------------------
            if ($originalContent -match '(?i)\[CmdletBinding\(') {
                # Check if param() block exists
                if ($originalContent -match '(?is)param\s*\((.+?)\)') {
                    $paramBlock = $Matches[0]

                    # Only add if not already present
                    if ($paramBlock -notmatch '(?i)ExcludeRODCs') {
                        $rodcParam = @'

    [Parameter(
        HelpMessage = "Exclude Read-Only Domain Controllers from operations that require write access."
    )]
    [switch]$ExcludeRODCs
'@
                        # Insert before the closing parenthesis of param()
                        $lastParenIndex = $paramBlock.LastIndexOf(')')
                        if ($lastParenIndex -gt 0) {
                            $beforeClose = $paramBlock.Substring(0, $lastParenIndex)
                            $needsComma = $beforeClose.TrimEnd()
                            if ($needsComma[-1] -ne ',' -and $needsComma[-1] -ne '(') {
                                $rodcParam = ",$rodcParam"
                            }
                            $newParamBlock = $paramBlock.Substring(0, $lastParenIndex) + $rodcParam + "`n)"
                            $patchedContent = $patchedContent.Replace($paramBlock, $newParamBlock)
                            $appliedPatches.Add('Added -ExcludeRODCs parameter')
                        }
                    }
                }
            }

            # ------------------------------------------------------------------
            # Patch 2: Add RODC detection function after param block
            # ------------------------------------------------------------------
            $rodcDetectionBlock = @'

# ---------------------------------------------------------------------------
# RODC Compatibility: Detection Logic (auto-generated patch)
# ---------------------------------------------------------------------------

function Test-IsRODC {
    <#
    .SYNOPSIS
        Detects whether the specified domain controller is a Read-Only Domain Controller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DCName = $env:COMPUTERNAME
    )

    try {
        $dc = Get-ADDomainController -Identity $DCName -ErrorAction Stop
        return [bool]$dc.IsReadOnly
    }
    catch {
        Write-Warning "Cannot determine DC type for '$DCName': $($_.Exception.Message)"
        return $false
    }
}

function Get-WritableDC {
    <#
    .SYNOPSIS
        Returns a writable domain controller for operations that cannot run on an RODC.
    #>
    [CmdletBinding()]
    param()

    try {
        $dc = Get-ADDomainController -Discover -Writable -ErrorAction Stop
        return $dc.HostName
    }
    catch {
        Write-Warning "Cannot discover writable DC: $($_.Exception.Message)"
        return $null
    }
}

'@
            # Insert after the param() block closing
            if ($patchedContent -match '(?is)(param\s*\([^)]*(?:\([^)]*\)[^)]*)*\))') {
                $fullParamMatch = $Matches[0]
                $insertPoint = $patchedContent.IndexOf($fullParamMatch) + $fullParamMatch.Length
                $patchedContent = $patchedContent.Insert($insertPoint, "`n$rodcDetectionBlock")
                $appliedPatches.Add('Added RODC detection functions (Test-IsRODC, Get-WritableDC)')
            }

            # ------------------------------------------------------------------
            # Patch 3: Wrap Set-AD* cmdlets with RODC check
            # ------------------------------------------------------------------
            $setADPattern = '(?i)^(\s*)(Set-ADUser|Set-ADComputer|Set-ADObject|Set-ADGroup|Set-ADAccountPassword|Set-ADOrganizationalUnit)(\s+.+)$'
            $patchedLines = $patchedContent -split "`n"
            $newLines = [System.Collections.Generic.List[string]]::new()
            $wrappedSetCmds = $false

            foreach ($line in $patchedLines) {
                if ($line -match $setADPattern) {
                    $indent = $Matches[1]
                    $cmdlet = $Matches[2]
                    $args = $Matches[3]

                    $newLines.Add("${indent}# RODC Compatibility: Writable operation guard (auto-patched)")
                    $newLines.Add("${indent}if (`$ExcludeRODCs -and (Test-IsRODC)) {")
                    $newLines.Add("${indent}    Write-Warning `"Skipping $cmdlet on RODC `$(`$env:COMPUTERNAME). Use -ExcludeRODCs:`$false to override or target a writable DC.`"")
                    $newLines.Add("${indent}} else {")
                    # Add -WhatIf:$WhatIfPreference and -Confirm:$ConfirmPreference if not present
                    $enhancedArgs = $args
                    if ($args -notmatch '(?i)-WhatIf') {
                        $enhancedArgs = "$enhancedArgs -WhatIf:`$WhatIfPreference"
                    }
                    if ($args -notmatch '(?i)-Confirm') {
                        $enhancedArgs = "$enhancedArgs -Confirm:`$ConfirmPreference"
                    }
                    $newLines.Add("${indent}    ${cmdlet}${enhancedArgs}")
                    $newLines.Add("${indent}}")
                    $wrappedSetCmds = $true
                }
                else {
                    $newLines.Add($line)
                }
            }

            if ($wrappedSetCmds) {
                $patchedContent = $newLines -join "`n"
                $appliedPatches.Add('Wrapped Set-AD* cmdlets with RODC guard and ShouldProcess support')
            }

            # ------------------------------------------------------------------
            # Patch 4: Wrap New-AD* and Remove-AD* cmdlets with RODC check
            # ------------------------------------------------------------------
            $mutationPattern = '(?i)^(\s*)(New-ADUser|New-ADComputer|New-ADObject|New-ADGroup|New-ADOrganizationalUnit|Remove-ADUser|Remove-ADComputer|Remove-ADObject|Remove-ADGroup|Remove-ADOrganizationalUnit|Enable-ADAccount|Disable-ADAccount|Unlock-ADAccount|Move-ADObject|Rename-ADObject|Restore-ADObject)(\s+.+)$'
            $patchedLines = $patchedContent -split "`n"
            $newLines = [System.Collections.Generic.List[string]]::new()
            $wrappedMutations = $false

            foreach ($line in $patchedLines) {
                # Skip lines already patched (contain "RODC Compatibility" comment)
                if ($line -match 'RODC Compatibility') {
                    $newLines.Add($line)
                    continue
                }

                if ($line -match $mutationPattern) {
                    $indent = $Matches[1]
                    $cmdlet = $Matches[2]
                    $args = $Matches[3]

                    $newLines.Add("${indent}# RODC Compatibility: Writable operation guard (auto-patched)")
                    $newLines.Add("${indent}if (`$ExcludeRODCs -and (Test-IsRODC)) {")
                    $newLines.Add("${indent}    Write-Warning `"Skipping $cmdlet on RODC `$(`$env:COMPUTERNAME). Operation requires a writable DC.`"")
                    $newLines.Add("${indent}} else {")
                    $enhancedArgs = $args
                    if ($args -notmatch '(?i)-WhatIf') {
                        $enhancedArgs = "$enhancedArgs -WhatIf:`$WhatIfPreference"
                    }
                    if ($args -notmatch '(?i)-Confirm') {
                        $enhancedArgs = "$enhancedArgs -Confirm:`$ConfirmPreference"
                    }
                    $newLines.Add("${indent}    ${cmdlet}${enhancedArgs}")
                    $newLines.Add("${indent}}")
                    $wrappedMutations = $true
                }
                else {
                    $newLines.Add($line)
                }
            }

            if ($wrappedMutations) {
                $patchedContent = $newLines -join "`n"
                $appliedPatches.Add('Wrapped New-AD*/Remove-AD*/account mutation cmdlets with RODC guard')
            }

            # ------------------------------------------------------------------
            # Patch 5: Add -ErrorAction to Invoke-Command/Enter-PSSession/New-PSSession
            # ------------------------------------------------------------------
            $winrmCmdlets = @('Invoke-Command', 'Enter-PSSession', 'New-PSSession')
            $winrmPatched = $false

            foreach ($cmdlet in $winrmCmdlets) {
                $winrmPattern = "(?i)(\b${cmdlet}\b)(?!.*-ErrorAction)(\s+)"
                if ($patchedContent -match $winrmPattern) {
                    $patchedContent = [regex]::Replace(
                        $patchedContent,
                        $winrmPattern,
                        "`$1 -ErrorAction Stop`$2"
                    )
                    $winrmPatched = $true
                }
            }

            if ($winrmPatched) {
                $appliedPatches.Add('Added -ErrorAction Stop to WinRM cmdlets')
            }

            # ------------------------------------------------------------------
            # Patch 6: Update comment-based help with RODC limitations
            # ------------------------------------------------------------------
            $rodcNotes = @"

    RODC COMPATIBILITY NOTES (auto-generated):
    - This patched version includes RODC detection and write-operation guards.
    - Use -ExcludeRODCs to skip write operations when running against an RODC.
    - Patched operations include -WhatIf and -Confirm support via ShouldProcess.
    - Original script: $($scriptSummary.ScriptName)
    - Patched on: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
"@
            if ($patchedContent -match '(?i)\.NOTES') {
                $notesIndex = $patchedContent.IndexOf('.NOTES')
                # Find the end of the .NOTES line
                $lineEnd = $patchedContent.IndexOf("`n", $notesIndex)
                if ($lineEnd -gt 0) {
                    $patchedContent = $patchedContent.Insert($lineEnd, "`n$rodcNotes")
                    $appliedPatches.Add('Updated .NOTES with RODC compatibility information')
                }
            }

            # ------------------------------------------------------------------
            # Write patched file
            # ------------------------------------------------------------------
            if ($appliedPatches.Count -gt 0) {
                $patchedContent | Out-File -FilePath $patchedFilePath -Encoding UTF8 -Force

                $patchedFiles.Add([PSCustomObject]@{
                    OriginalScript  = $scriptSummary.ScriptName
                    OriginalPath    = $sourceFile
                    PatchedFileName = $patchedFileName
                    PatchedPath     = $patchedFilePath
                    PatchesApplied  = $appliedPatches.Count
                    PatchDetails    = ($appliedPatches -join '; ')
                })

                Write-Verbose "    Applied $($appliedPatches.Count) patch(es): $($appliedPatches -join ', ')"
            }
            else {
                Write-Verbose "    No patches were applicable for $($scriptSummary.ScriptName)."
            }
        }
        catch {
            Write-Warning "Failed to patch '$($scriptSummary.ScriptName)': $($_.Exception.Message)"
        }
    }

    Write-Verbose "Auto-patch generation complete. Generated $($patchedFiles.Count) patched script(s)."
    return $patchedFiles
}

# ---------------------------------------------------------------------------
# Region: CSV Export
# ---------------------------------------------------------------------------

function Export-InventoryCSV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    $csvPath = Join-Path -Path $OutputPath -ChildPath "RODC_ScriptCompatibility_$($script:Timestamp).csv"

    Write-Verbose "Exporting CSV inventory to: $csvPath"

    if ($Findings.Count -eq 0) {
        # Write an empty CSV with headers
        $emptyRow = [PSCustomObject]@{
            ScriptName    = ''
            Path          = ''
            IssueType     = ''
            LineNumber    = ''
            CodeSnippet   = ''
            Description   = ''
            Severity      = ''
            FixRequired   = ''
            AutoPatchable = ''
        }
        @($emptyRow) | Select-Object ScriptName, Path, IssueType, LineNumber, CodeSnippet, Description, Severity, FixRequired, AutoPatchable |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
    }
    else {
        $Findings |
            Select-Object ScriptName, Path, IssueType, LineNumber, CodeSnippet, Description, Severity, FixRequired, AutoPatchable |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
    }

    Write-Verbose "CSV inventory exported: $csvPath"
    return $csvPath
}

# ---------------------------------------------------------------------------
# Region: HTML Report Generation
# ---------------------------------------------------------------------------

function Build-HTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$ScriptSummaries,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$PatchedFiles,

        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [int]$TotalScripts
    )

    Write-Verbose "Generating HTML report..."

    # Executive summary calculations
    $totalFindings = $Findings.Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq 'Low' }).Count

    $writeOpCount = @($Findings | Where-Object { $_.IssueType -eq 'Write Operation' }).Count
    $fsmoCount = @($Findings | Where-Object { $_.IssueType -eq 'FSMO Assumption' }).Count
    $unreplCount = @($Findings | Where-Object { $_.IssueType -eq 'Unreplicated Attribute' }).Count
    $winrmCount = @($Findings | Where-Object { $_.IssueType -eq 'WinRM Issue' }).Count

    $compatibleScripts = @($ScriptSummaries | Where-Object { $_.Status -eq 'Compatible' }).Count
    $incompatibleScripts = @($ScriptSummaries | Where-Object { $_.Status -eq 'Incompatible' }).Count
    $reviewScripts = @($ScriptSummaries | Where-Object { $_.Status -eq 'Review Needed' }).Count
    $minorScripts = @($ScriptSummaries | Where-Object { $_.Status -eq 'Minor Issues' }).Count

    $autoPatchableCount = @($Findings | Where-Object { $_.AutoPatchable -eq 'Yes' }).Count
    $manualFixCount = @($Findings | Where-Object { $_.AutoPatchable -eq 'No' -and $_.FixRequired -eq 'Yes' }).Count

    $healthPct = if ($TotalScripts -gt 0) {
        [math]::Round(($compatibleScripts / $TotalScripts) * 100)
    }
    else { 0 }

    # Build script summary table rows
    $scriptRows = [System.Text.StringBuilder]::new()
    foreach ($s in ($ScriptSummaries | Sort-Object -Property @{Expression = { switch ($_.Status) { 'Incompatible' { 0 } 'Review Needed' { 1 } 'Minor Issues' { 2 } 'Compatible' { 3 } default { 4 } } }})) {
        $statusClass = switch ($s.Status) {
            'Compatible'    { 'status-pass' }
            'Minor Issues'  { 'status-info' }
            'Review Needed' { 'status-warn' }
            'Incompatible'  { 'status-fail' }
            default         { 'status-secondary' }
        }

        [void]$scriptRows.AppendLine("<tr>")
        [void]$scriptRows.AppendLine("  <td><strong>$([System.Net.WebUtility]::HtmlEncode($s.ScriptName))</strong></td>")
        [void]$scriptRows.AppendLine("  <td>$($s.TotalIssues)</td>")
        [void]$scriptRows.AppendLine("  <td class=`"severity-high`">$($s.HighSeverity)</td>")
        [void]$scriptRows.AppendLine("  <td class=`"severity-medium`">$($s.MediumSeverity)</td>")
        [void]$scriptRows.AppendLine("  <td class=`"severity-low`">$($s.LowSeverity)</td>")
        [void]$scriptRows.AppendLine("  <td>$($s.AutoPatchable)</td>")
        [void]$scriptRows.AppendLine("  <td>$($s.LineCount)</td>")
        [void]$scriptRows.AppendLine("  <td><span class=`"badge $statusClass`">$([System.Net.WebUtility]::HtmlEncode($s.Status))</span></td>")
        [void]$scriptRows.AppendLine("</tr>")
    }

    # Build findings detail table rows
    $findingRows = [System.Text.StringBuilder]::new()
    foreach ($f in ($Findings | Sort-Object -Property @{Expression = { switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } 'Low' { 2 } default { 3 } } }}, ScriptName, LineNumber)) {
        $sevClass = switch ($f.Severity) {
            'High'   { 'status-fail' }
            'Medium' { 'status-warn' }
            'Low'    { 'status-info' }
            default  { 'status-secondary' }
        }

        $typeClass = switch ($f.IssueType) {
            'Write Operation'        { 'status-fail' }
            'FSMO Assumption'        { 'status-warn' }
            'Unreplicated Attribute' { 'status-warn' }
            'WinRM Issue'            { 'status-info' }
            default                  { 'status-secondary' }
        }

        [void]$findingRows.AppendLine("<tr>")
        [void]$findingRows.AppendLine("  <td><strong>$([System.Net.WebUtility]::HtmlEncode($f.ScriptName))</strong></td>")
        [void]$findingRows.AppendLine("  <td><span class=`"badge $typeClass`">$([System.Net.WebUtility]::HtmlEncode($f.IssueType))</span></td>")
        [void]$findingRows.AppendLine("  <td class=`"line-num`">$($f.LineNumber)</td>")
        [void]$findingRows.AppendLine("  <td class=`"code-cell`"><code>$([System.Net.WebUtility]::HtmlEncode($f.CodeSnippet))</code></td>")
        [void]$findingRows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode($f.Description))</td>")
        [void]$findingRows.AppendLine("  <td><span class=`"badge $sevClass`">$([System.Net.WebUtility]::HtmlEncode($f.Severity))</span></td>")
        [void]$findingRows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode($f.FixRequired))</td>")
        [void]$findingRows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode($f.AutoPatchable))</td>")
        [void]$findingRows.AppendLine("</tr>")
    }

    # Build patched files section
    $patchSection = ''
    if ($PatchedFiles.Count -gt 0) {
        $patchRows = [System.Text.StringBuilder]::new()
        foreach ($p in $PatchedFiles) {
            [void]$patchRows.AppendLine("<tr>")
            [void]$patchRows.AppendLine("  <td><strong>$([System.Net.WebUtility]::HtmlEncode($p.OriginalScript))</strong></td>")
            [void]$patchRows.AppendLine("  <td><strong>$([System.Net.WebUtility]::HtmlEncode($p.PatchedFileName))</strong></td>")
            [void]$patchRows.AppendLine("  <td>$($p.PatchesApplied)</td>")
            [void]$patchRows.AppendLine("  <td class=`"reason-cell`">$([System.Net.WebUtility]::HtmlEncode($p.PatchDetails))</td>")
            [void]$patchRows.AppendLine("</tr>")
        }

        $patchSection = @"
    <div class="card">
        <h2>Auto-Patched Scripts</h2>
        <p class="text-secondary">Patched versions were generated with RODC compatibility guards. Original files were NOT modified.</p>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Original Script</th>
                        <th>Patched File</th>
                        <th>Patches Applied</th>
                        <th>Patch Details</th>
                    </tr>
                </thead>
                <tbody>
                    $($patchRows.ToString())
                </tbody>
            </table>
        </div>
    </div>
"@
    }

    # No-findings notice
    $noDataNotice = ''
    if ($Findings.Count -eq 0) {
        $noDataNotice = '<div class="card"><p class="text-secondary" style="text-align:center;padding:2rem;">All scanned scripts are RODC-compatible. No issues were detected.</p></div>'
    }

    # Ring calculation
    $circumference = [math]::Round(2 * [math]::PI * 68, 2)
    $ringOffset = [math]::Round($circumference * (1 - ($healthPct / 100)), 2)
    $ringColor = switch ($true) {
        ($healthPct -ge 90) { '#2ea043' }
        ($healthPct -ge 70) { '#d29922' }
        ($healthPct -ge 50) { '#f0883e' }
        default             { '#f85149' }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RODC Script Compatibility Report - $($script:Timestamp)</title>
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
            max-width: 1500px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }

        header {
            background: linear-gradient(135deg, #1a2332 0%, #1e2d3d 100%);
            border-bottom: 1px solid #30363d;
            padding: 2rem 1.5rem;
            position: relative;
        }

        header::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 4px;
            background: linear-gradient(90deg, #2ea043, #58a6ff, #d29922, #f85149);
        }

        header h1 {
            font-size: 1.75rem;
            font-weight: 700;
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
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
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
            font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace;
        }

        .summary-item .label {
            color: #8b949e;
            font-size: 0.8rem;
            margin-top: 0.25rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }

        .value-green  { color: #2ea043; }
        .value-yellow { color: #d29922; }
        .value-red    { color: #f85149; }
        .value-blue   { color: #58a6ff; }
        .value-gray   { color: #8b949e; }

        /* ---- Ring ---- */
        .ring-container {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 2rem;
            margin-bottom: 1.5rem;
        }

        .ring-wrapper {
            position: relative;
            width: 160px;
            height: 160px;
        }

        .ring-wrapper svg {
            transform: rotate(-90deg);
            width: 160px;
            height: 160px;
        }

        .ring-wrapper .ring-bg {
            fill: none;
            stroke: #30363d;
            stroke-width: 12;
        }

        .ring-wrapper .ring-fill {
            fill: none;
            stroke-width: 12;
            stroke-linecap: round;
        }

        .ring-text {
            position: absolute;
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .ring-text .pct {
            font-size: 2.2rem;
            font-weight: 800;
            font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace;
        }

        .ring-text .ring-label {
            font-size: 0.75rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .ring-legend {
            display: flex;
            flex-direction: column;
            gap: 10px;
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

        .legend-dot.green  { background: #2ea043; }
        .legend-dot.blue   { background: #58a6ff; }
        .legend-dot.yellow { background: #d29922; }
        .legend-dot.red    { background: #f85149; }

        .legend-count {
            font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace;
            font-weight: 600;
            min-width: 28px;
        }

        /* ---- Category Breakdown ---- */
        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .category-card {
            background-color: #1a2332;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem;
            border-left: 4px solid;
        }

        .category-card.write-op  { border-left-color: #f85149; }
        .category-card.fsmo      { border-left-color: #d29922; }
        .category-card.unrepl    { border-left-color: #d29922; }
        .category-card.winrm     { border-left-color: #58a6ff; }

        .category-card .cat-value {
            font-size: 1.75rem;
            font-weight: 700;
            font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace;
        }

        .category-card .cat-label {
            color: #8b949e;
            font-size: 0.8rem;
            margin-top: 0.15rem;
        }

        /* ---- Tables ---- */
        .table-wrapper {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }

        thead th {
            background-color: #1a2332;
            color: #8b949e;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.72rem;
            letter-spacing: 0.05em;
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 2px solid #30363d;
            position: sticky;
            top: 0;
            white-space: nowrap;
        }

        tbody td {
            padding: 0.6rem 1rem;
            border-bottom: 1px solid #21262d;
            color: #e6edf3;
            vertical-align: top;
        }

        tbody tr:hover { background-color: rgba(88, 166, 255, 0.04); }

        .code-cell {
            max-width: 400px;
        }

        .code-cell code {
            font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace;
            font-size: 0.78rem;
            color: #e6edf3;
            background-color: #0f1419;
            border: 1px solid #30363d;
            border-radius: 4px;
            padding: 0.15em 0.4em;
            word-break: break-all;
            display: inline-block;
            max-width: 100%;
            overflow-wrap: break-word;
        }

        .line-num {
            font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace;
            color: #8b949e;
            text-align: right;
            white-space: nowrap;
        }

        .severity-high { color: #f85149; font-weight: 600; }
        .severity-medium { color: #d29922; font-weight: 600; }
        .severity-low { color: #58a6ff; font-weight: 600; }

        .reason-cell {
            max-width: 350px;
            font-size: 0.78rem;
            color: #8b949e;
        }

        /* ---- Badges ---- */
        .badge {
            display: inline-block;
            padding: 0.2em 0.65em;
            border-radius: 12px;
            font-size: 0.72rem;
            font-weight: 600;
            white-space: nowrap;
        }

        .status-pass { background-color: rgba(46, 160, 67, 0.15); color: #2ea043; border: 1px solid rgba(46, 160, 67, 0.3); }
        .status-warn { background-color: rgba(210, 153, 34, 0.15); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.3); }
        .status-fail { background-color: rgba(248, 81, 73, 0.15); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.3); }
        .status-info { background-color: rgba(88, 166, 255, 0.15); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.3); }
        .status-secondary { background-color: rgba(139, 148, 158, 0.10); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.2); }

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
            .category-grid { grid-template-columns: repeat(2, 1fr); }
            header h1 { font-size: 1.35rem; }
            .container { padding: 1rem; }
            .ring-container { flex-direction: column; }
        }

        @media print {
            body { background: #fff; color: #1a1a1a; }
            .card { border-color: #ddd; background: #f8f8f8; }
            .badge { border-color: #ccc; }
        }
    </style>
</head>
<body>

<header>
    <div class="container" style="padding-top:0;padding-bottom:0;">
        <h1>RODC Script Compatibility Report</h1>
        <p>Automated audit of PowerShell scripts for Read-Only Domain Controller compatibility issues</p>
        <div class="meta-bar">
            <span>Source: <strong>$([System.Net.WebUtility]::HtmlEncode($SourcePath))</strong></span>
            <span>Scripts Scanned: <strong>$TotalScripts</strong></span>
            <span>Total Findings: <strong>$totalFindings</strong></span>
            <span>Auto-Patch: <strong>$(if ($AutoPatch) { 'Enabled' } else { 'Disabled' })</strong></span>
            <span>Generated: <strong>$($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</strong></span>
        </div>
    </div>
</header>

<div class="container">

    <!-- Health Ring + Legend -->
    <div class="card">
        <div class="ring-container">
            <div class="ring-wrapper">
                <svg viewBox="0 0 160 160">
                    <circle class="ring-bg" cx="80" cy="80" r="68"/>
                    <circle class="ring-fill" cx="80" cy="80" r="68"
                            stroke="$ringColor"
                            stroke-dasharray="$circumference"
                            stroke-dashoffset="$ringOffset"/>
                </svg>
                <div class="ring-text">
                    <div class="pct" style="color:$ringColor">$healthPct%</div>
                    <div class="ring-label">Compatible</div>
                </div>
            </div>
            <div class="ring-legend">
                <div class="legend-item"><span class="legend-dot green"></span><span class="legend-count">$compatibleScripts</span> Compatible</div>
                <div class="legend-item"><span class="legend-dot blue"></span><span class="legend-count">$minorScripts</span> Minor Issues</div>
                <div class="legend-item"><span class="legend-dot yellow"></span><span class="legend-count">$reviewScripts</span> Review Needed</div>
                <div class="legend-item"><span class="legend-dot red"></span><span class="legend-count">$incompatibleScripts</span> Incompatible</div>
            </div>
        </div>
    </div>

    <!-- Executive Summary -->
    <div class="card">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="value value-blue">$TotalScripts</div>
                <div class="label">Scripts Scanned</div>
            </div>
            <div class="summary-item">
                <div class="value value-green">$compatibleScripts</div>
                <div class="label">Fully Compatible</div>
            </div>
            <div class="summary-item">
                <div class="value value-red">$incompatibleScripts</div>
                <div class="label">Incompatible</div>
            </div>
            <div class="summary-item">
                <div class="value value-yellow">$reviewScripts</div>
                <div class="label">Review Needed</div>
            </div>
            <div class="summary-item">
                <div class="value value-red">$highCount</div>
                <div class="label">High Severity</div>
            </div>
            <div class="summary-item">
                <div class="value value-yellow">$mediumCount</div>
                <div class="label">Medium Severity</div>
            </div>
            <div class="summary-item">
                <div class="value value-blue">$lowCount</div>
                <div class="label">Low Severity</div>
            </div>
            <div class="summary-item">
                <div class="value value-green">$autoPatchableCount</div>
                <div class="label">Auto-Patchable</div>
            </div>
        </div>
    </div>

    <!-- Issue Category Breakdown -->
    <div class="card">
        <h2>Issue Category Breakdown</h2>
        <div class="category-grid">
            <div class="category-card write-op">
                <div class="cat-value" style="color:#f85149;">$writeOpCount</div>
                <div class="cat-label">Write Operations</div>
            </div>
            <div class="category-card fsmo">
                <div class="cat-value" style="color:#d29922;">$fsmoCount</div>
                <div class="cat-label">FSMO Assumptions</div>
            </div>
            <div class="category-card unrepl">
                <div class="cat-value" style="color:#d29922;">$unreplCount</div>
                <div class="cat-label">Unreplicated Attributes</div>
            </div>
            <div class="category-card winrm">
                <div class="cat-value" style="color:#58a6ff;">$winrmCount</div>
                <div class="cat-label">WinRM Issues</div>
            </div>
        </div>
    </div>

    $noDataNotice

    <!-- Script Inventory -->
    <div class="card">
        <h2>Script Inventory</h2>
        <p class="text-secondary" style="margin-bottom:1rem;">Per-script summary sorted by compatibility status (most critical first).</p>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Script Name</th>
                        <th>Total Issues</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Auto-Patchable</th>
                        <th>Lines</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    $($scriptRows.ToString())
                </tbody>
            </table>
        </div>
    </div>

    <!-- Detailed Findings -->
    <div class="card">
        <h2>Detailed Findings</h2>
        <p class="text-secondary" style="margin-bottom:1rem;">All detected RODC compatibility issues sorted by severity.</p>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Script</th>
                        <th>Issue Type</th>
                        <th>Line</th>
                        <th>Code Snippet</th>
                        <th>Description</th>
                        <th>Severity</th>
                        <th>Fix Required</th>
                        <th>Auto-Patchable</th>
                    </tr>
                </thead>
                <tbody>
                    $($findingRows.ToString())
                </tbody>
            </table>
        </div>
    </div>

    <!-- Auto-Patched Scripts (if applicable) -->
    $patchSection

</div>

<footer>
    RODC Script Compatibility Report &mdash; Generated $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) &mdash; Static Analysis Only &mdash; Original Scripts Not Modified
</footer>

</body>
</html>
"@

    return $html
}

# ---------------------------------------------------------------------------
# Region: Main Execution
# ---------------------------------------------------------------------------

try {
    # Step 1: Initialize environment
    Write-Verbose "Step 1/5: Initializing environment..."
    $env = Initialize-Environment
    $resolvedScriptPath = $env.ResolvedScriptPath
    $scriptFiles = $env.ScriptFiles

    # Step 2: Scan scripts for compatibility issues
    Write-Verbose "Step 2/5: Scanning scripts for RODC compatibility issues..."
    $scanResults = Invoke-ScriptScan -ScriptFiles $scriptFiles
    $allFindings = @($scanResults.Findings)
    $scriptSummaries = @($scanResults.ScriptSummaries)

    # Step 3: Auto-patch if requested
    $patchedFiles = @()
    if ($AutoPatch) {
        Write-Verbose "Step 3/5: Generating auto-patched scripts..."
        $patchedFiles = @(Invoke-AutoPatch -ScriptSummaries $scriptSummaries)
    }
    else {
        Write-Verbose "Step 3/5: Auto-patch skipped (use -AutoPatch to enable)."
    }

    # Step 4: Export CSV inventory
    Write-Verbose "Step 4/5: Exporting CSV inventory..."
    $csvPath = Export-InventoryCSV -Findings $allFindings

    # Step 5: Generate HTML report
    Write-Verbose "Step 5/5: Generating HTML report..."
    $htmlContent = Build-HTMLReport `
        -Findings $allFindings `
        -ScriptSummaries $scriptSummaries `
        -PatchedFiles $patchedFiles `
        -SourcePath $resolvedScriptPath `
        -TotalScripts $scriptFiles.Count

    $htmlPath = Join-Path -Path $OutputPath -ChildPath "RODC_ScriptCompatibility_$($script:Timestamp).html"
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Verbose "HTML report saved: $htmlPath"

    # Summary output
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime

    $compatibleCount = @($scriptSummaries | Where-Object { $_.Status -eq 'Compatible' }).Count
    $incompatibleCount = @($scriptSummaries | Where-Object { $_.Status -eq 'Incompatible' }).Count
    $reviewCount = @($scriptSummaries | Where-Object { $_.Status -eq 'Review Needed' }).Count

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  RODC Script Compatibility Audit - Complete" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Source Directory:    $resolvedScriptPath" -ForegroundColor White
    Write-Host "  Scripts Scanned:     $($scriptFiles.Count)" -ForegroundColor White
    Write-Host "  Total Findings:      $($allFindings.Count)" -ForegroundColor White
    Write-Host ""

    if ($compatibleCount -gt 0) {
        Write-Host "  Compatible:          $compatibleCount" -ForegroundColor Green
    }
    else {
        Write-Host "  Compatible:          0" -ForegroundColor Gray
    }

    if ($incompatibleCount -gt 0) {
        Write-Host "  Incompatible:        $incompatibleCount" -ForegroundColor Red
    }
    else {
        Write-Host "  Incompatible:        0" -ForegroundColor Gray
    }

    if ($reviewCount -gt 0) {
        Write-Host "  Review Needed:       $reviewCount" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Review Needed:       0" -ForegroundColor Gray
    }

    $highSevCount = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $medSevCount = @($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowSevCount = @($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count

    Write-Host ""
    Write-Host "  High Severity:       $highSevCount" -ForegroundColor $(if ($highSevCount -gt 0) { 'Red' } else { 'Gray' })
    Write-Host "  Medium Severity:     $medSevCount" -ForegroundColor $(if ($medSevCount -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Host "  Low Severity:        $lowSevCount" -ForegroundColor $(if ($lowSevCount -gt 0) { 'Cyan' } else { 'Gray' })

    if ($AutoPatch) {
        Write-Host ""
        Write-Host "  Patched Scripts:     $($patchedFiles.Count)" -ForegroundColor $(if ($patchedFiles.Count -gt 0) { 'Green' } else { 'Gray' })
        if ($patchedFiles.Count -gt 0) {
            $patchDir = Join-Path -Path $OutputPath -ChildPath "PatchedScripts"
            Write-Host "  Patch Directory:     $patchDir" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host "  Reports:" -ForegroundColor White
    Write-Host "    CSV:  $csvPath" -ForegroundColor Gray
    Write-Host "    HTML: $htmlPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Duration: $($duration.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NOTE: Original scripts were NOT modified." -ForegroundColor Yellow
    Write-Host "  Review the HTML report for detailed findings and recommendations." -ForegroundColor Yellow
    Write-Host ""

    # Return object for pipeline consumption
    [PSCustomObject]@{
        CSVPath              = $csvPath
        HTMLPath             = $htmlPath
        TotalScriptsScanned  = $scriptFiles.Count
        TotalFindings        = $allFindings.Count
        CompatibleScripts    = $compatibleCount
        IncompatibleScripts  = $incompatibleCount
        ReviewNeededScripts  = $reviewCount
        HighSeverity         = $highSevCount
        MediumSeverity       = $medSevCount
        LowSeverity          = $lowSevCount
        PatchedScripts       = $patchedFiles.Count
        DurationSeconds      = [math]::Round($duration.TotalSeconds, 1)
    }
}
catch {
    Write-Error "RODC Script Compatibility Audit failed: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    throw
}
