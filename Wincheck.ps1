#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Forensic Evidence Collection Script for ROHAN-IPV
.DESCRIPTION
    Collects key forensic artifacts from the target laptop into C:\ForensicOutput
    Run as Administrator on the target machine.
.NOTES
    Case: Rohan Goyal Company Laptop Investigation
    Date: May 2026
#>

$OutputDir = "C:\ForensicOutput_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Write-Host "[*] Output directory: $OutputDir" -ForegroundColor Cyan

# --- 1. SYSTEM INFO ---
Write-Host "[+] Collecting system info..." -ForegroundColor Green
systeminfo > "$OutputDir\systeminfo.txt"

# --- 2. EVENT LOGS ---
Write-Host "[+] Exporting event logs..." -ForegroundColor Green
$logDir = "$OutputDir\EventLogs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
wevtutil epl Security "$logDir\Security.evtx" 2>$null
wevtutil epl System "$logDir\System.evtx" 2>$null
wevtutil epl Application "$logDir\Application.evtx" 2>$null
wevtutil epl "Microsoft-Windows-PowerShell/Operational" "$logDir\PowerShell.evtx" 2>$null
wevtutil epl "Microsoft-Windows-Windows Defender/Operational" "$logDir\Defender.evtx" 2>$null
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "$logDir\Sysmon.evtx" 2>$null

# --- 3. RECENT LOGINS ---
Write-Host "[+] Collecting login events..." -ForegroundColor Green
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}} |
  Export-Csv "$OutputDir\recent_logins.csv" -NoTypeInformation

# --- 4. INSTALLED SOFTWARE ---
Write-Host "[+] Collecting installed software..." -ForegroundColor Green
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
  Sort-Object InstallDate -Descending |
  Export-Csv "$OutputDir\installed_software.csv" -NoTypeInformation

Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
  Export-Csv "$OutputDir\installed_software_x86.csv" -NoTypeInformation

# --- 5. PERSISTENCE: STARTUP & SCHEDULED TASKS ---
Write-Host "[+] Collecting persistence mechanisms..." -ForegroundColor Green
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Out-File "$OutputDir\persistence_run_hklm.txt"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Out-File "$OutputDir\persistence_run_hkcu.txt"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Out-File "$OutputDir\persistence_runonce.txt"

Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} |
  ForEach-Object { $t = $_; $t.Actions | Select-Object @{N='TaskName';E={$t.TaskName}}, @{N='Path';E={$t.TaskPath}}, @{N='State';E={$t.State}}, Execute, Arguments } |
  Export-Csv "$OutputDir\scheduled_tasks.csv" -NoTypeInformation

# --- 6. NETWORK ---
Write-Host "[+] Collecting network data..." -ForegroundColor Green
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
  Export-Csv "$OutputDir\active_connections.csv" -NoTypeInformation

Get-DnsClientCache | Select-Object Entry, Data, TimeToLive | Export-Csv "$OutputDir\dns_cache.csv" -NoTypeInformation
ipconfig /all > "$OutputDir\ipconfig.txt"

# --- 7. RUNNING PROCESSES ---
Write-Host "[+] Collecting process list..." -ForegroundColor Green
Get-Process | Select-Object Id, ProcessName, Path, StartTime, Company |
  Sort-Object StartTime -Descending |
  Export-Csv "$OutputDir\running_processes.csv" -NoTypeInformation

# --- 8. BROWSER HISTORY LOCATIONS ---
Write-Host "[+] Locating browser databases..." -ForegroundColor Green
$browserPaths = @(
    "C:\Users\RohanGoyal\AppData\Local\Google\Chrome\User Data\Default\History",
    "C:\Users\RohanGoyal\AppData\Local\Microsoft\Edge\User Data\Default\History",
    "C:\Users\RohanGoyal\AppData\Roaming\Mozilla\Firefox\Profiles"
)
$browserDir = "$OutputDir\BrowserData"
New-Item -ItemType Directory -Path $browserDir -Force | Out-Null
foreach ($p in $browserPaths) {
    if (Test-Path $p) {
        Copy-Item $p "$browserDir\$(Split-Path $p -Leaf)_$(Split-Path (Split-Path $p) -Leaf)" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "    Found: $p" -ForegroundColor Yellow
    }
}

# --- 9. USB DEVICE HISTORY ---
Write-Host "[+] Collecting USB history..." -ForegroundColor Green
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue |
  Select-Object FriendlyName, Mfg, Service, PSChildName |
  Export-Csv "$OutputDir\usb_history.csv" -NoTypeInformation

# --- 10. RECENT FILES ---
Write-Host "[+] Finding recently modified files..." -ForegroundColor Green
Get-ChildItem -Path "C:\Users\RohanGoyal" -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) -and !$_.PSIsContainer } |
  Sort-Object LastWriteTime -Descending |
  Select-Object FullName, LastWriteTime, Length -First 500 |
  Export-Csv "$OutputDir\recent_files_14days.csv" -NoTypeInformation

# --- 11. EXECUTABLES IN USER DIRS ---
Write-Host "[+] Scanning for executables in user directories..." -ForegroundColor Green
Get-ChildItem -Path "C:\Users\RohanGoyal" -Recurse -Include "*.exe","*.bat","*.ps1","*.vbs","*.cmd","*.scr","*.dll" -ErrorAction SilentlyContinue |
  Select-Object FullName, CreationTime, LastWriteTime, Length |
  Export-Csv "$OutputDir\user_executables.csv" -NoTypeInformation

# --- 12. WINDOWS DEFENDER DETECTIONS ---
Write-Host "[+] Checking Defender detections..." -ForegroundColor Green
Get-MpThreatDetection -ErrorAction SilentlyContinue |
  Select-Object DetectionTime, Resources, ThreatName, ActionSuccess |
  Export-Csv "$OutputDir\defender_detections.csv" -NoTypeInformation

Get-MpComputerStatus -ErrorAction SilentlyContinue | Out-File "$OutputDir\defender_status.txt"

# --- 13. DOWNLOADS FOLDER ---
Write-Host "[+] Listing Downloads folder..." -ForegroundColor Green
Get-ChildItem "C:\Users\RohanGoyal\Downloads" -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, CreationTime, LastWriteTime, Length |
  Sort-Object LastWriteTime -Descending |
  Export-Csv "$OutputDir\downloads_folder.csv" -NoTypeInformation

# --- 14. RECYCLE BIN ---
Write-Host "[+] Checking Recycle Bin..." -ForegroundColor Green
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue |
  Select-Object FullName, CreationTime, Length |
  Export-Csv "$OutputDir\recycle_bin.csv" -NoTypeInformation

# --- DONE ---
Write-Host "`n[✓] Collection complete! Output saved to: $OutputDir" -ForegroundColor Cyan
Write-Host "[!] Compress and transfer this folder for analysis." -ForegroundColor Yellow
Compress-Archive -Path $OutputDir -DestinationPath "$OutputDir.zip" -Force
Write-Host "[✓] ZIP created: $OutputDir.zip" -ForegroundColor Green
