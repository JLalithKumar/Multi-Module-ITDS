# ==============================================================================
# CyberShield XDR -- Controlled Threat Simulation & Verification Tool
# ==============================================================================
# Safely simulates specific benign events to test detection by:
# 1. Network Activity Agent (Ports, Domains, Encoded Processes)
# 2. System Logs Collector Agent (Event 4625, Event 7045, EDR Indicator Events)
# ==============================================================================

param (
    [string]$Action = "menu"
)

function Show-Header {
    Clear-Host
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "   CyberShield XDR -- Controlled Threat Simulation Toolkit       " -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host " Safely trigger controlled events to verify System & Network Agents" -ForegroundColor DarkGray
    Write-Host " All actions are benign and designed specifically for SOC testing.`n" -ForegroundColor DarkGray
}

function Test-NetworkRoguePort {
    Write-Host "`n[*] [TEST 1] Testing Network Agent: Rogue C2 Port 1337 Connection..." -ForegroundColor Cyan
    Write-Host "    Attempting a short socket connection to 127.0.0.1:1337" -ForegroundColor Gray
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect("127.0.0.1", 1337, $null, $null)
        $null = $iar.AsyncWaitHandle.WaitOne(800, $false)
        $tcp.Close()
    } catch {}
    Write-Host "[+] Connection probe to port 1337 completed." -ForegroundColor Green
    Write-Host "[>] Check your Network Agent window & SOC Console (/agent)." -ForegroundColor Yellow
}

function Test-NetworkSuspiciousDomain {
    Write-Host "`n[*] [TEST 2] Testing Network Agent: Suspicious Domain Access (testmyids.com)..." -ForegroundColor Cyan
    Write-Host "    Resolving standard benign IDS test domain: testmyids.com" -ForegroundColor Gray
    try {
        Resolve-DnsName -Name "testmyids.com" -ErrorAction SilentlyContinue | Out-Null
        curl.exe http://testmyids.com --max-time 2 -ErrorAction SilentlyContinue | Out-Null
    } catch {}
    Write-Host "[+] Query to testmyids.com sent." -ForegroundColor Green
    Write-Host "[>] Check your Network Agent window & SOC Console (/agent)." -ForegroundColor Yellow
}

function Test-NetworkEncodedProcess {
    Write-Host "`n[*] [TEST 3] Testing Network Agent: Obfuscated Encoded PowerShell Execution..." -ForegroundColor Cyan
    Write-Host "    Executing a benign Base64-encoded echo command..." -ForegroundColor Gray
    # Benign payload: Write-Host "CyberShield Probe Active"
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Write-Host "CyberShield Probe Active"'))
    Start-Process powershell.exe -ArgumentList "-NoProfile", "-EncodedCommand", $encoded -WindowStyle Hidden
    Start-Sleep -Seconds 1
    Write-Host "[+] Encoded execution launched." -ForegroundColor Green
    Write-Host "[>] Check your Network Agent window & SOC Console (/agent)." -ForegroundColor Yellow
}

function Test-SystemFailedLogon {
    Write-Host "`n[*] [TEST 4] Testing System Agent: Failed Logon Attempt (Windows Event 4625)..." -ForegroundColor Cyan
    Write-Host "    Simulating an invalid authentication attempt against local IPC..." -ForegroundColor Gray
    try {
        net use \\127.0.0.1\IPC$ /u:CyberShieldSimulatedHacker "WrongPass999!" 2>$null | Out-Null
    } catch {}
    Write-Host "[+] Invalid logon probe completed (Windows Security Event 4625 generated)." -ForegroundColor Green
    Write-Host "[>] Check your System Agent window & SOC Console (/agent)." -ForegroundColor Yellow
}

function Test-SystemServiceCreation {
    Write-Host "`n[*] [TEST 5] Testing System Agent: Service Installation Persistence (Event 7045)..." -ForegroundColor Cyan
    Write-Host "    Creating and immediately deleting a harmless test service..." -ForegroundColor Gray
    $serviceName = "CyberShieldAuditTest"
    try {
        sc.exe create $serviceName binPath= "C:\Windows\System32\cmd.exe" start= demand 2>$null | Out-Null
        Start-Sleep -Milliseconds 500
        sc.exe delete $serviceName 2>$null | Out-Null
        Write-Host "[+] Service created and safely removed (Windows System Event 7045 generated)." -ForegroundColor Green
    } catch {
        Write-Host "[-] Note: Service creation requires running as Administrator." -ForegroundColor DarkYellow
    }
    Write-Host "[>] Check your System Agent window & SOC Console (/agent)." -ForegroundColor Yellow
}

function Test-SystemMaliciousIndicatorLog {
    Write-Host "`n[*] [TEST 6] Testing System Agent: Malicious Indicator Event (Ransomware / Mimikatz)..." -ForegroundColor Cyan
    Write-Host "    Logging a benign test event into Windows Application Log with threat signatures..." -ForegroundColor Gray
    try {
        # Ensure event source exists in Application log
        if (-not [System.Diagnostics.EventLog]::SourceExists("CyberShieldSensor")) {
            New-EventLog -LogName Application -Source "CyberShieldSensor" -ErrorAction SilentlyContinue | Out-Null
        }
        Write-EventLog -LogName Application -Source "CyberShieldSensor" -EventId 9991 -EntryType Error -Message "CyberShield Simulated Intrusion: Hostile process invoked 'vssadmin delete shadows' and 'mimikatz' indicators."
        Write-Host "[+] High-risk security event written to Application log." -ForegroundColor Green
    } catch {
        # Fallback to direct eventcreate
        eventcreate /T ERROR /ID 991 /L APPLICATION /SO CyberShieldSensor /D "CyberShield Simulated Intrusion: Hostile process invoked vssadmin delete shadows." 2>$null | Out-Null
        Write-Host "[+] Security event written via eventcreate." -ForegroundColor Green
    }
    Write-Host "[>] Check your System Agent window & SOC Console (/agent)." -ForegroundColor Yellow
}

function Run-AllTests {
    Test-NetworkRoguePort
    Start-Sleep -Seconds 2
    Test-NetworkSuspiciousDomain
    Start-Sleep -Seconds 2
    Test-NetworkEncodedProcess
    Start-Sleep -Seconds 2
    Test-SystemFailedLogon
    Start-Sleep -Seconds 2
    Test-SystemServiceCreation
    Start-Sleep -Seconds 2
    Test-SystemMaliciousIndicatorLog
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "   All 6 Controlled Threat Scenarios Dispatched!                 " -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "Review your open agent terminals and the SOC dashboard: http://localhost:5173" -ForegroundColor Yellow
}

# Interactive Menu
if ($Action -eq "all") {
    Run-AllTests
    exit
}

Show-Header

while ($true) {
    Write-Host "Select a controlled test to execute:" -ForegroundColor White
    Write-Host "  [1] Network Agent : Rogue C2 Port 1337 Connection     (Severity: CRITICAL)" -ForegroundColor Red
    Write-Host "  [2] Network Agent : Suspicious Domain (testmyids.com) (Severity: CRITICAL)" -ForegroundColor Red
    Write-Host "  [3] Network Agent : Obfuscated Encoded PowerShell    (Severity: CRITICAL)" -ForegroundColor Red
    Write-Host "  [4] System Agent  : Failed Authentication Event 4625  (Severity: HIGH)" -ForegroundColor Yellow
    Write-Host "  [5] System Agent  : Service Creation Event 7045       (Severity: MEDIUM/HIGH)" -ForegroundColor Yellow
    Write-Host "  [6] System Agent  : Ransomware/Mimikatz Log Indicator (Severity: CRITICAL)" -ForegroundColor Red
    Write-Host "  [7] RUN ALL TESTS SEQUENTIALLY                        (Full Simulation)" -ForegroundColor Green
    Write-Host "  [Q] Quit`n" -ForegroundColor Gray

    $choice = Read-Host "Enter your choice [1-7 or Q]"
    switch ($choice) {
        "1" { Test-NetworkRoguePort }
        "2" { Test-NetworkSuspiciousDomain }
        "3" { Test-NetworkEncodedProcess }
        "4" { Test-SystemFailedLogon }
        "5" { Test-SystemServiceCreation }
        "6" { Test-SystemMaliciousIndicatorLog }
        "7" { Run-AllTests }
        "Q" { exit }
        "q" { exit }
        default { Write-Host "Invalid choice, please select 1-7." -ForegroundColor DarkYellow }
    }
    Write-Host "`n-----------------------------------------------------------------`n" -ForegroundColor DarkGray
}
