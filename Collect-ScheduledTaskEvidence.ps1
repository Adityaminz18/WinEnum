<#
.SYNOPSIS
    Forensic Evidence Collector — Suspicious Scheduled Tasks (SnSensor)

.DESCRIPTION
    Collects forensic evidence for scheduled tasks matching the pattern
    "SnSensor{*}" that invoke mshta.exe to load a remote HTA payload
    from https://snconor.vg.

    Evidence collected:
      - Full task XML definitions
      - Task metadata (author, creation date, triggers, actions)
      - Execution history and last-run info
      - Associated registry keys
      - mshta.exe process artifacts (if running)
      - Network connection artifacts
      - File-system artifacts (task files from C:\Windows\System32\Tasks)
      - SHA256 hashes of all collected files

.NOTES
    Case       : CaseSolved — Day 3
    Target     : Aman's Laptop
    Author     : Forensic Investigator
    Date       : $(Get-Date -Format 'yyyy-MM-dd')
    Run As     : Administrator (elevated prompt required)
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$OutputDir = "$PSScriptRoot\Evidence_SnSensor_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

function Write-Banner {
    $banner = @"

  ╔══════════════════════════════════════════════════════════════╗
  ║   FORENSIC EVIDENCE COLLECTOR — Scheduled Task Artifacts    ║
  ║   Target Pattern : SnSensor{*}                              ║
  ║   IOC            : mshta.exe → https://snconor.vg           ║
  ╚══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Write-Section ([string]$Title) {
    Write-Host "`n[$((Get-Date).ToString('HH:mm:ss'))] ▶ $Title" -ForegroundColor Yellow
}

function Write-Success ([string]$Msg) {
    Write-Host "    [+] $Msg" -ForegroundColor Green
}

function Write-Info ([string]$Msg) {
    Write-Host "    [i] $Msg" -ForegroundColor Gray
}

function Write-Warn ([string]$Msg) {
    Write-Host "    [!] $Msg" -ForegroundColor Red
}

# ─── Initialisation ──────────────────────────────────────────────────────────

Write-Banner

# Create evidence output directory tree
$dirs = @(
    $OutputDir,
    "$OutputDir\TaskXML",
    "$OutputDir\TaskFiles",
    "$OutputDir\Registry",
    "$OutputDir\Process",
    "$OutputDir\Network",
    "$OutputDir\Hashes"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
Write-Success "Evidence directory created: $OutputDir"

# Start transcript for full audit trail
$transcriptPath = "$OutputDir\collection_transcript.log"
Start-Transcript -Path $transcriptPath -Force | Out-Null
Write-Success "Transcript logging started"

# ─── 1. Enumerate matching scheduled tasks ───────────────────────────────────

Write-Section "Enumerating Scheduled Tasks matching 'SnSensor{*}'"

$matchingTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like 'SnSensor{*}' }

if (-not $matchingTasks) {
    Write-Warn "No tasks matching 'SnSensor{*}' found. Broadening search to '*SnSensor*'..."
    $matchingTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like '*SnSensor*' }
}

if (-not $matchingTasks) {
    Write-Warn "No matching tasks found on this system."
    Write-Host "    Attempting to collect residual artifacts from the task filesystem..." -ForegroundColor Gray

    # Even if tasks are deleted, XML files may remain on disk
    $taskDir = "$env:SystemRoot\System32\Tasks"
    $residualFiles = Get-ChildItem -Path $taskDir -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*SnSensor*' }

    if ($residualFiles) {
        Write-Success "Found $($residualFiles.Count) residual task file(s) on disk"
        foreach ($rf in $residualFiles) {
            Copy-Item -Path $rf.FullName -Destination "$OutputDir\TaskFiles\$($rf.Name)" -Force
            Write-Info "Copied: $($rf.FullName)"
        }
    }
} else {
    Write-Success "Found $($matchingTasks.Count) matching task(s)"
}

# ─── 2. Collect detailed task information ─────────────────────────────────────

$taskReport = @()

foreach ($task in $matchingTasks) {
    $taskName = $task.TaskName
    Write-Section "Processing Task: $taskName"

    # --- 2a. Export full XML definition ---
    try {
        $xmlContent = Export-ScheduledTask -TaskName $taskName -TaskPath $task.TaskPath
        $xmlFile = "$OutputDir\TaskXML\$($taskName).xml"
        $xmlContent | Out-File -FilePath $xmlFile -Encoding UTF8
        Write-Success "Exported XML → $xmlFile"
    } catch {
        Write-Warn "Failed to export XML for $taskName : $_"
    }

    # --- 2b. Collect task metadata ---
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

    $record = [PSCustomObject]@{
        TaskName          = $taskName
        TaskPath          = $task.TaskPath
        State             = $task.State
        Author            = $task.Author
        Description       = $task.Description
        Date              = $task.Date
        URI               = $task.URI
        # Trigger details
        TriggerCount      = ($task.Triggers | Measure-Object).Count
        TriggerTypes      = ($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join '; '
        TriggerDetails    = ($task.Triggers | ForEach-Object {
            $props = $_ | Select-Object * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties, PSComputerName
            ($props.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
        }) -join ' | '
        # Action details
        ActionCount       = ($task.Actions | Measure-Object).Count
        ActionExecute     = ($task.Actions | ForEach-Object { $_.Execute }) -join '; '
        ActionArguments   = ($task.Actions | ForEach-Object { $_.Arguments }) -join '; '
        # Principal / Security context
        Principal_UserID  = $task.Principal.UserId
        Principal_LogonType = $task.Principal.LogonType
        Principal_RunLevel  = $task.Principal.RunLevel
        # Run history
        LastRunTime       = if ($taskInfo) { $taskInfo.LastRunTime } else { 'N/A' }
        LastTaskResult    = if ($taskInfo) { $taskInfo.LastTaskResult } else { 'N/A' }
        NextRunTime       = if ($taskInfo) { $taskInfo.NextRunTime } else { 'N/A' }
        NumberOfMissedRuns = if ($taskInfo) { $taskInfo.NumberOfMissedRuns } else { 'N/A' }
    }

    $taskReport += $record
    Write-Success "Metadata collected"

    # --- 2c. Check actions for mshta.exe / snconor.vg IOCs ---
    foreach ($action in $task.Actions) {
        $exe  = $action.Execute
        $args = $action.Arguments

        if ($exe -match 'mshta' -or $args -match 'snconor\.vg') {
            Write-Warn "IOC MATCH — Action invokes mshta.exe with suspicious URL"
            Write-Info "  Execute   : $exe"
            Write-Info "  Arguments : $args"
        }
    }

    # --- 2d. Copy raw task file from System32\Tasks ---
    $taskFilePath = "$env:SystemRoot\System32\Tasks$($task.TaskPath)$taskName"
    if (Test-Path $taskFilePath) {
        $destFile = "$OutputDir\TaskFiles\$($taskName)_raw"
        Copy-Item -Path $taskFilePath -Destination $destFile -Force
        Write-Success "Raw task file copied → $destFile"

        # Hash the file
        $hash = Get-FileHash -Path $destFile -Algorithm SHA256
        "$($hash.Algorithm): $($hash.Hash)  $taskFilePath" |
            Out-File -FilePath "$OutputDir\Hashes\task_file_hashes.txt" -Append -Encoding UTF8
        Write-Info "SHA256: $($hash.Hash)"
    } else {
        Write-Info "Raw task file not found at expected path: $taskFilePath"
    }
}

# Export task metadata report
if ($taskReport.Count -gt 0) {
    $csvPath = "$OutputDir\task_metadata_report.csv"
    $taskReport | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Success "Task metadata report → $csvPath"

    $jsonPath = "$OutputDir\task_metadata_report.json"
    $taskReport | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Success "Task metadata report → $jsonPath"
}

# ─── 3. Registry evidence ────────────────────────────────────────────────────

Write-Section "Collecting Registry Evidence"

$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
)

foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        try {
            $subKeys = Get-ChildItem -Path $regPath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'SnSensor' }

            foreach ($key in $subKeys) {
                $keyName = ($key.Name -replace '[\\/:*?"<>|]', '_')
                $exportFile = "$OutputDir\Registry\$keyName.txt"

                $key | Get-ItemProperty -ErrorAction SilentlyContinue |
                    Format-List * |
                    Out-File -FilePath $exportFile -Encoding UTF8

                Write-Success "Registry key exported → $exportFile"
            }
        } catch {
            Write-Warn "Error reading registry path $regPath : $_"
        }
    }
}

# Also dump the full TaskCache\Tree for context
try {
    $treeExport = "$OutputDir\Registry\TaskCache_Tree_Full.txt"
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree" $treeExport /y 2>$null
    if (Test-Path $treeExport) {
        Write-Success "Full TaskCache Tree exported → $treeExport"
    }
} catch {
    Write-Info "Could not export full TaskCache Tree"
}

# ─── 4. Process artifacts (if mshta.exe is currently running) ─────────────────

Write-Section "Checking for Active mshta.exe Processes"

$mshtaProcs = Get-Process -Name 'mshta' -ErrorAction SilentlyContinue

if ($mshtaProcs) {
    Write-Warn "mshta.exe is currently RUNNING — $($mshtaProcs.Count) instance(s)"

    foreach ($proc in $mshtaProcs) {
        $procFile = "$OutputDir\Process\mshta_PID_$($proc.Id).txt"

        [PSCustomObject]@{
            PID            = $proc.Id
            ProcessName    = $proc.ProcessName
            StartTime      = $proc.StartTime
            CPU            = $proc.CPU
            WorkingSet_MB  = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            Path           = $proc.Path
            CommandLine    = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
            ParentPID      = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).ParentProcessId
        } | Format-List * | Out-File -FilePath $procFile -Encoding UTF8

        Write-Success "Process details saved → $procFile"
    }
} else {
    Write-Info "mshta.exe is not currently running"
}

# Check for any scheduled-task-related svchost or taskeng processes
$taskProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'SnSensor|snconor\.vg|mshta' }

if ($taskProcs) {
    $taskProcs | Select-Object ProcessId, Name, CommandLine, CreationDate, ParentProcessId |
        Export-Csv -Path "$OutputDir\Process\ioc_related_processes.csv" -NoTypeInformation -Encoding UTF8
    Write-Success "IOC-related processes exported"
}

# ─── 5. Network artifacts ────────────────────────────────────────────────────

Write-Section "Collecting Network Artifacts (snconor.vg)"

# DNS cache entries
try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
        Where-Object { $_.Entry -like '*snconor*' }

    if ($dnsCache) {
        $dnsCache | Export-Csv -Path "$OutputDir\Network\dns_cache_snconor.csv" -NoTypeInformation -Encoding UTF8
        Write-Success "DNS cache entries for snconor.vg captured"
    } else {
        Write-Info "No DNS cache entries found for snconor.vg"
    }
} catch {
    Write-Info "Could not query DNS client cache"
}

# Active connections to snconor.vg
try {
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }

    $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
        @{N='ProcessName'; E={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }} |
        Export-Csv -Path "$OutputDir\Network\active_connections.csv" -NoTypeInformation -Encoding UTF8
    Write-Success "Active TCP connections snapshot saved"
} catch {
    Write-Info "Could not capture network connections"
}

# Resolve snconor.vg for IOC enrichment
try {
    $resolve = Resolve-DnsName -Name 'snconor.vg' -ErrorAction SilentlyContinue
    if ($resolve) {
        $resolve | Format-List * | Out-File -FilePath "$OutputDir\Network\snconor_vg_dns_resolution.txt" -Encoding UTF8
        Write-Success "DNS resolution for snconor.vg saved"
    }
} catch {
    Write-Info "Could not resolve snconor.vg (may be offline or sinkholed)"
}

# ─── 6. Event log evidence ───────────────────────────────────────────────────

Write-Section "Collecting Relevant Event Logs"

# Task Scheduler operational log
try {
    $taskEvents = Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'SnSensor' }

    if ($taskEvents) {
        $taskEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message |
            Export-Csv -Path "$OutputDir\task_scheduler_events.csv" -NoTypeInformation -Encoding UTF8
        Write-Success "Task Scheduler events ($($taskEvents.Count) entries) exported"
    } else {
        Write-Info "No Task Scheduler events referencing SnSensor found"
    }
} catch {
    Write-Info "Could not read Task Scheduler event log"
}

# Security log — task creation events (Event ID 4698)
try {
    $secEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4698   # A scheduled task was created
    } -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'SnSensor' }

    if ($secEvents) {
        $secEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message |
            Export-Csv -Path "$OutputDir\security_task_creation_events.csv" -NoTypeInformation -Encoding UTF8
        Write-Success "Security event log — task creation events exported"
    } else {
        Write-Info "No Security event 4698 (task creation) referencing SnSensor"
    }
} catch {
    Write-Info "Could not read Security event log (requires elevated privileges)"
}

# ─── 7. All scheduled tasks snapshot (for context) ───────────────────────────

Write-Section "Exporting Full Scheduled Tasks List (baseline)"

Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author, Date |
    Export-Csv -Path "$OutputDir\all_scheduled_tasks.csv" -NoTypeInformation -Encoding UTF8
Write-Success "Full scheduled task list exported"

# ─── 8. System context ───────────────────────────────────────────────────────

Write-Section "Collecting System Context"

$systemInfo = [PSCustomObject]@{
    ComputerName   = $env:COMPUTERNAME
    UserName       = $env:USERNAME
    Domain         = $env:USERDOMAIN
    OSVersion      = (Get-CimInstance Win32_OperatingSystem).Caption
    OSBuild        = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    Architecture   = $env:PROCESSOR_ARCHITECTURE
    CollectionTime = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC+00:00')
    TimeZone       = (Get-TimeZone).DisplayName
    IPAddresses    = ((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress -join ', ')
}

$systemInfo | Format-List * | Out-File -FilePath "$OutputDir\system_context.txt" -Encoding UTF8
Write-Success "System context saved"

# ─── 9. Generate summary report ──────────────────────────────────────────────

Write-Section "Generating Evidence Summary Report"

$reportPath = "$OutputDir\EVIDENCE_SUMMARY.txt"

@"
╔══════════════════════════════════════════════════════════════════╗
║              FORENSIC EVIDENCE COLLECTION REPORT                ║
║              Case: CaseSolved — Day 3                           ║
╚══════════════════════════════════════════════════════════════════╝

Collection Date  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer Name    : $($env:COMPUTERNAME)
Investigator     : $($env:USERNAME)
Target Artifact  : Scheduled Tasks matching "SnSensor{*}"
IOC              : mshta.exe loading https://snconor.vg

─── FINDINGS ──────────────────────────────────────────────────────

Tasks Found      : $($matchingTasks.Count)

Task Details:
$( ($taskReport | ForEach-Object {
@"
  ┌─ Task: $($_.TaskName)
  │  State       : $($_.State)
  │  Author      : $($_.Author)
  │  Created     : $($_.Date)
  │  Action(s)   : $($_.ActionExecute) $($_.ActionArguments)
  │  Trigger(s)  : $($_.TriggerTypes)
  │  Last Run    : $($_.LastRunTime)
  │  Run Level   : $($_.Principal_RunLevel)
  └────────────────────────────────────────────────────────────
"@
}) -join "`n" )

─── IOC INDICATORS ────────────────────────────────────────────────

  • mshta.exe is a Living-off-the-Land Binary (LOLBin) used to
    execute remote HTA (HTML Application) payloads.
  • The URL https://snconor.vg likely serves a malicious HTA
    file that downloads and executes secondary payloads.
  • Two identically-patterned tasks (SnSensor{GUID}) suggest
    persistence via redundant scheduled task registration.

─── EVIDENCE ARTIFACTS ────────────────────────────────────────────

  Directory : $OutputDir

  Files collected:
$( (Get-ChildItem -Path $OutputDir -Recurse -File | ForEach-Object {
    "    • $($_.FullName.Replace($OutputDir, '.'))"
}) -join "`n" )

─── CHAIN OF CUSTODY ──────────────────────────────────────────────

  Collection Start : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Method           : Automated PowerShell collection script
  Integrity        : SHA256 hashes recorded for all binary artifacts

══════════════════════════════════════════════════════════════════
"@ | Out-File -FilePath $reportPath -Encoding UTF8

Write-Success "Evidence summary → $reportPath"

# ─── 10. Hash the entire evidence directory ───────────────────────────────────

Write-Section "Computing Integrity Hashes for All Evidence Files"

$allFiles = Get-ChildItem -Path $OutputDir -Recurse -File
$hashReport = foreach ($f in $allFiles) {
    $h = Get-FileHash -Path $f.FullName -Algorithm SHA256
    [PSCustomObject]@{
        File   = $f.FullName.Replace($OutputDir, '.')
        SHA256 = $h.Hash
    }
}

$hashReport | Export-Csv -Path "$OutputDir\Hashes\all_evidence_hashes.csv" -NoTypeInformation -Encoding UTF8
Write-Success "All evidence hashed ($($allFiles.Count) files)"

# ─── Cleanup ──────────────────────────────────────────────────────────────────

Stop-Transcript | Out-Null

Write-Host "`n" -NoNewline
Write-Host "  ✅ Evidence collection complete." -ForegroundColor Green
Write-Host "  📁 Output: $OutputDir" -ForegroundColor Cyan
Write-Host "  📄 Report: $reportPath" -ForegroundColor Cyan
Write-Host ""
