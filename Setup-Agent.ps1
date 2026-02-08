#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AssetsMan Login Agent - All-in-One Setup

.DESCRIPTION
    Single-file installer with embedded agent code.
    - Install: Deploys agent + scheduled task
    - Uninstall: Removes everything
    - Status: Check current installation

.NOTES
    Run as Administrator: .\Setup-Agent.ps1
#>

$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\AssetsMan-Agent"
$TaskName = "AssetsMan Login Agent"
$ScriptPath = "$InstallDir\LoginAgent.ps1"
$ConfigPath = "$InstallDir\agent-config.json"

#region Embedded LoginAgent Script
$LoginAgentScript = @'
#Requires -RunAsAdministrator
param([string]$ConfigPath = "$PSScriptRoot\agent-config.json")

if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config file not found: $ConfigPath"
    exit 1
}

$config = Get-Content $ConfigPath | ConvertFrom-Json
$API_URL = $config.api_url
$API_KEY = if ($config.token) { $config.token } elseif ($config.api_key) { $config.api_key } else { $null }
$CHECK_INTERVAL = if ($config.check_interval_seconds) { $config.check_interval_seconds } else { 5 }
$IGNORE_SSL = $config.ignore_ssl

if ([string]::IsNullOrEmpty($API_KEY) -or $API_KEY -eq "YOUR_TOKEN_HERE") {
    Write-Error "Please configure your token in agent-config.json"
    exit 1
}

if ($IGNORE_SSL) {
    try {
        Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
        }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    } catch {}
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

function Get-LogonTypeName {
    param([int]$LogonType)
    switch ($LogonType) {
        2  { "interactive" }
        3  { "network" }
        4  { "batch" }
        5  { "service" }
        7  { "unlock" }
        8  { "network_cleartext" }
        9  { "new_credentials" }
        10 { "rdp" }
        11 { "cached_interactive" }
        default { "unknown" }
    }
}

function Send-ToAPI {
    param([string]$Endpoint, [hashtable]$Body)
    try {
        $headers = @{ "Content-Type" = "application/json"; "X-API-Key" = $API_KEY }
        $response = Invoke-RestMethod -Uri "$API_URL/$Endpoint" -Method POST -Headers $headers -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 30
        return $response
    } catch {
        Write-Warning "API Error: $($_.Exception.Message)"
        return $null
    }
}

function Send-Heartbeat {
    $body = @{
        hostname = $env:COMPUTERNAME
        ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress
    }
    $result = Send-ToAPI -Endpoint "register" -Body $body
    if ($result) { Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Heartbeat OK" }
}

function Send-LoginEvent {
    param([string]$EventType, [string]$Username, [string]$Domain, [string]$LoginType, [string]$SourceIP, [datetime]$EventTime)
    $body = @{
        event_type = $EventType; username = $Username; domain = $Domain
        login_type = $LoginType; source_ip = $SourceIP
        event_time = $EventTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $result = Send-ToAPI -Endpoint "login-event" -Body $body
    if ($result) { Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Event: $EventType - $Username ($LoginType)" }
}

function Process-SecurityEvent {
    param($Event)
    $eventId = $Event.Id
    $eventTime = $Event.TimeCreated
    $xml = [xml]$Event.ToXml()
    $eventData = $xml.Event.EventData.Data
    
    $username = ($eventData | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    $domain = ($eventData | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
    $logonTypeRaw = ($eventData | Where-Object { $_.Name -eq "LogonType" }).'#text'
    $sourceIP = ($eventData | Where-Object { $_.Name -eq "IpAddress" }).'#text'
    
    if ($eventId -eq 4648) { $logonTypeRaw = "10" }
    
    # Debug: Show what we're processing
    Write-Host "  -> ID:$eventId User:$username Type:$logonTypeRaw" -ForegroundColor Gray
    
    $skip = @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "Window Manager", "Font Driver Host")
    if ($skip -contains $username) { return }
    if ($username -match '\$$') { return }
    if ($username -match '^(DWM|UMFD)-\d+$') { return }
    if ([string]::IsNullOrEmpty($username) -or $username -eq "-") { return }
    
    $logonType = Get-LogonTypeName -LogonType ([int]$logonTypeRaw)
    if ($logonType -in @("network", "service", "batch", "network_cleartext", "new_credentials")) { return }
    
    $eventType = if ($eventId -eq 4624 -or $eventId -eq 4648) { "login" } else { "logout" }
    Send-LoginEvent -EventType $eventType -Username $username -Domain $domain -LoginType $logonType -SourceIP $sourceIP -EventTime $eventTime
}

Write-Host "========================================="
Write-Host "  AssetsMan Login Agent v1.2"
Write-Host "========================================="
Write-Host "API: $API_URL | Interval: ${CHECK_INTERVAL}s"
Write-Host "-----------------------------------------"

Send-Heartbeat
$lastEventTime = (Get-Date).AddMinutes(-1)
$script:processedIds = @()
$lastHeartbeat = Get-Date

Write-Host "Monitoring login/logout events..."

try {
    while ($true) {
        try {
            Write-Host "." -NoNewline -ForegroundColor DarkGray
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4624, 4634, 4648
                StartTime = $lastEventTime
            } -MaxEvents 200 -ErrorAction SilentlyContinue
            
            if ($events -and $events.Count -gt 0) {
                Write-Host "" # newline
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Found $($events.Count) events since $($lastEventTime.ToString('HH:mm:ss'))" -ForegroundColor DarkYellow
                $newCount = 0
                foreach ($evt in ($events | Sort-Object TimeCreated)) {
                    if ($script:processedIds -contains $evt.RecordId) { continue }
                    $newCount++
                    Process-SecurityEvent -Event $evt
                    $script:processedIds += $evt.RecordId
                    if ($script:processedIds.Count -gt 100) { $script:processedIds = $script:processedIds[-100..-1] }
                }
                if ($newCount -gt 0) {
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Processed $newCount NEW events" -ForegroundColor Cyan
                }
                $lastEventTime = ($events | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
            }
        } catch {
            Write-Host "[WARN] $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        if ((Get-Date) - $lastHeartbeat -gt [TimeSpan]::FromMinutes(1)) {
            Send-Heartbeat
            $lastHeartbeat = Get-Date
        }
        
        Start-Sleep -Seconds $CHECK_INTERVAL
    }
} catch {
    Write-Host "[FATAL] $($_.Exception.Message)" -ForegroundColor Red
    Read-Host "Press Enter to exit"
}
'@
#endregion

#region Functions
function Show-Menu {
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "  AssetsMan Login Agent Setup" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Install Agent"
    Write-Host "  [2] Uninstall Agent"
    Write-Host "  [3] Check Status"
    Write-Host "  [Q] Quit"
    Write-Host ""
}

function Check-Existing {
    $hasTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $hasDir = Test-Path $InstallDir
    return @{ HasTask = $null -ne $hasTask; HasDir = $hasDir; TaskState = if ($hasTask) { $hasTask.State } else { "N/A" } }
}

function Show-Status {
    Write-Host "`n=== Agent Status ===" -ForegroundColor Yellow
    $s = Check-Existing
    Write-Host "Task: $(if ($s.HasTask) { "Installed ($($s.TaskState))" } else { 'Not found' })"
    Write-Host "Directory: $(if ($s.HasDir) { 'Exists' } else { 'Not found' })"
    if ($s.HasDir -and (Test-Path $ConfigPath)) {
        $c = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        Write-Host "API URL: $($c.api_url)"
    }
    Read-Host "`nPress Enter to continue"
}

function Uninstall-Silent {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Start-Sleep 2 }
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    Get-WmiObject Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like "*LoginAgent.ps1*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
}

function Install-Agent {
    Write-Host "`n=== Install Agent ===" -ForegroundColor Green
    $status = Check-Existing
    
    if ($status.HasTask -or $status.HasDir) {
        Write-Host "`nExisting installation detected!" -ForegroundColor Yellow
        Write-Host "  [1] Reinstall (keep config)"
        Write-Host "  [2] Clean install"
        Write-Host "  [3] Cancel"
        $choice = Read-Host "Select"
        switch ($choice) {
            "1" { if ($status.HasDir -and (Test-Path $ConfigPath)) { $script:savedConfig = Get-Content $ConfigPath -Raw }; Uninstall-Silent }
            "2" { Uninstall-Silent; $script:savedConfig = $null }
            default { Write-Host "Cancelled."; return }
        }
    }
    
    # Get config
    if (-not $script:savedConfig) {
        Write-Host "`nConfigure agent:" -ForegroundColor Yellow
        $apiUrl = Read-Host "API URL (e.g., http://server:port/api/agent)"
        $token = Read-Host "Token"
        $ignoreSSL = Read-Host "Ignore SSL? (y/N)"
        $interval = Read-Host "Check interval seconds (default: 5)"
        
        $cfg = @{
            api_url = $apiUrl
            token = $token
            check_interval_seconds = if ($interval -match '^\d+$') { [int]$interval } else { 5 }
            ignore_ssl = ($ignoreSSL -eq "y" -or $ignoreSSL -eq "Y")
        }
        $script:savedConfig = $cfg | ConvertTo-Json
    }
    
    # Validate
    $cfg = $script:savedConfig | ConvertFrom-Json
    $tokenVal = if ($cfg.token) { $cfg.token } elseif ($cfg.api_key) { $cfg.api_key } else { $null }
    if ([string]::IsNullOrEmpty($tokenVal)) { Write-Host "ERROR: Token required!" -ForegroundColor Red; return }
    if ([string]::IsNullOrEmpty($cfg.api_url)) { Write-Host "ERROR: API URL required!" -ForegroundColor Red; return }
    
    # Install
    Write-Host "`n[1/5] Creating directory..."
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    
    Write-Host "[2/5] Writing agent files..."
    $LoginAgentScript | Set-Content $ScriptPath -Encoding UTF8
    $script:savedConfig | Set-Content $ConfigPath -Encoding UTF8
    (Get-Item $InstallDir -Force).Attributes = 'Hidden'
    Write-Host "      Folder hidden." -ForegroundColor Yellow
    
    Write-Host "[3/5] Creating scheduled task..."
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "AssetsMan Login Agent" | Out-Null
    
    Write-Host "[4/5] Testing connection..."
    if ($cfg.ignore_ssl) {
        try {
            Add-Type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
            }
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        } catch {}
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
    
    $body = @{ hostname = $env:COMPUTERNAME; ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress } | ConvertTo-Json
    $headers = @{ "Content-Type" = "application/json"; "X-API-Key" = $tokenVal }
    try {
        $resp = Invoke-RestMethod -Uri "$($cfg.api_url)/register" -Method POST -Headers $headers -Body $body -TimeoutSec 30
        Write-Host "      Connected! Server ID: $($resp.server_id)" -ForegroundColor Green
    } catch {
        Write-Host "      Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "[5/5] Starting agent..."
    Start-ScheduledTask -TaskName $TaskName
    
    Write-Host "`n=========================================" -ForegroundColor Green
    Write-Host "  Installation Complete!" -ForegroundColor Green
    Write-Host "========================================="
    Write-Host "Agent is running and will auto-start on boot."
    Read-Host "`nPress Enter to continue"
}

function Uninstall-Agent {
    Write-Host "`n=== Uninstall Agent ===" -ForegroundColor Red
    $s = Check-Existing
    if (-not $s.HasTask -and -not $s.HasDir) { Write-Host "No installation found."; Read-Host "Press Enter"; return }
    
    $confirm = Read-Host "Remove agent completely? (y/N)"
    if ($confirm -ne "y" -and $confirm -ne "Y") { Write-Host "Cancelled."; return }
    
    Write-Host "[1/3] Stopping agent..."
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq "Running") { Stop-ScheduledTask -TaskName $TaskName; Start-Sleep 2 }
    
    Write-Host "[2/3] Removing task..."
    if ($task) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
    Get-WmiObject Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like "*LoginAgent.ps1*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    
    Write-Host "[3/3] Removing files..."
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    
    Write-Host "`n=========================================" -ForegroundColor Green
    Write-Host "  Uninstallation Complete!" -ForegroundColor Green
    Write-Host "========================================="
    Read-Host "Press Enter to continue"
}
#endregion

# Main
do {
    Show-Menu
    $sel = Read-Host "Select option"
    switch ($sel.ToUpper()) {
        "1" { Install-Agent }
        "2" { Uninstall-Agent }
        "3" { Show-Status }
        "Q" { break }
        default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep 1 }
    }
} while ($sel.ToUpper() -ne "Q")

Write-Host "Goodbye!" -ForegroundColor Cyan
