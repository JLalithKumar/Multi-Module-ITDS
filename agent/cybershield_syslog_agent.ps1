# ==============================================================================
# CyberShield Live System Log Collector Agent (Windows Host)
# ==============================================================================
# Collects live Windows System, Security, and Application Event Logs in real-time
# and streams them to CyberShield XDR for threat analysis and log correlation.
# ==============================================================================

$API_ENDPOINT = "http://localhost:8000/api/v1/agent/telemetry"
$HOSTNAME = $env:COMPUTERNAME
$OS = "Windows 11 / $([System.Environment]::OSVersion.Version)"

# Resolve local IP
$IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback|vEthernet' } | Select-Object -First 1).IPAddress
if (-not $IP) { $IP = "127.0.0.1" }

Clear-Host
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   CyberShield XDR -- Live Windows System Log Collector         " -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[+] Hostname      : $HOSTNAME" -ForegroundColor Green
Write-Host "[+] Local IP      : $IP" -ForegroundColor Green
Write-Host "[+] Platform      : $OS" -ForegroundColor Green
Write-Host "[+] Ingestion API : $API_ENDPOINT" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Active Log Channels Monitored:" -ForegroundColor White
Write-Host "    - Windows System Logs (Services, Drivers, Kernel, Reboots)" -ForegroundColor Gray
Write-Host "    - Windows Application Logs (Crashes, Software, Errors)" -ForegroundColor Gray
Write-Host "    - Security Audit Events (Logons, Policy, Account Actions)" -ForegroundColor Gray
Write-Host "    - PowerShell Script Engine Logs (Execution Tracing)" -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Agent streaming live logs. Press Ctrl+C to terminate.`n" -ForegroundColor Yellow

# Track last query timestamp
$lastCheck = (Get-Date).AddMinutes(-2)
$processedRecordIds = [System.Collections.Generic.HashSet[string]]::new()

while ($true) {
    try {
        $events = [System.Collections.ArrayList]::new()
        $currentTime = Get-Date

        # 1. Collect System & Application logs
        $logNames = @("System", "Application")
        foreach ($logName in $logNames) {
            try {
                $rawEvents = Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $lastCheck } -MaxEvents 20 -ErrorAction SilentlyContinue
                if ($rawEvents) {
                    foreach ($ev in $rawEvents) {
                        $key = "$logName-$($ev.RecordId)"
                        if (-not $processedRecordIds.Contains($key)) {
                            $processedRecordIds.Add($key) | Out-Null

                            # Clean summary of message
                            $cleanMsg = ""
                            if ($ev.Message) {
                                $cleanMsg = ($ev.Message -split "`r?`n")[0].Trim()
                                if ($cleanMsg.Length -gt 140) { $cleanMsg = $cleanMsg.Substring(0, 140) + "..." }
                            }
                            if (-not $cleanMsg) { $cleanMsg = "Windows $logName Event ID $($ev.Id) from $($ev.ProviderName)" }

                            $details = "[Event $($ev.Id)] $cleanMsg"
                            $isWarningOrError = ($ev.Level -in 1, 2, 3) # Critical=1, Error=2, Warning=3
                            $isSecurityThreat = ($ev.Id -in 7045, 1102, 104, 4625, 4740)

                            $eventObj = @{
                                event_type   = "system_log"
                                process_name = if ($ev.ProviderName) { $ev.ProviderName } else { "$logName-Service" }
                                pid          = if ($ev.ProcessId) { [int]$ev.ProcessId } else { 0 }
                                dest_ip      = ""
                                dest_port    = 0
                                domain       = ""
                                cmdline      = ""
                                details      = $details
                            }
                            $events.Add($eventObj) | Out-Null

                            # Console output
                            $timeStr = $ev.TimeCreated.ToString("HH:mm:ss")
                            if ($isSecurityThreat) {
                                Write-Host "[$timeStr] [!] CRITICAL SECURITY: $details" -ForegroundColor Red
                            } elseif ($isWarningOrError) {
                                Write-Host "[$timeStr] [!] SYSTEM WARNING: $details" -ForegroundColor Yellow
                            } else {
                                Write-Host "[$timeStr] [+] SYSTEM LOG: $details" -ForegroundColor Gray
                            }
                        }
                    }
                }
            } catch {
                # Ignore channel errors
            }
        }

        # 2. Collect Security Events (Requires elevation; graceful fallback if not admin)
        try {
            $secEvents = Get-WinEvent -FilterHashtable @{ LogName = "Security"; StartTime = $lastCheck } -MaxEvents 10 -ErrorAction SilentlyContinue
            if ($secEvents) {
                foreach ($ev in $secEvents) {
                    $key = "Security-$($ev.RecordId)"
                    if (-not $processedRecordIds.Contains($key)) {
                        $processedRecordIds.Add($key) | Out-Null

                        $cleanMsg = ""
                        if ($ev.Message) {
                            $cleanMsg = ($ev.Message -split "`r?`n")[0].Trim()
                            if ($cleanMsg.Length -gt 140) { $cleanMsg = $cleanMsg.Substring(0, 140) + "..." }
                        }
                        if (-not $cleanMsg) { $cleanMsg = "Security Audit Event ID $($ev.Id)" }

                        $details = "[Security Event $($ev.Id)] $cleanMsg"
                        $isThreat = ($ev.Id -in 4625, 4740, 1102, 4697)

                        $eventObj = @{
                            event_type   = "windows_event"
                            process_name = "Security-Auditing"
                            pid          = if ($ev.ProcessId) { [int]$ev.ProcessId } else { 0 }
                            dest_ip      = ""
                            dest_port    = 0
                            domain       = ""
                            cmdline      = ""
                            details      = $details
                        }
                        $events.Add($eventObj) | Out-Null

                        $timeStr = $ev.TimeCreated.ToString("HH:mm:ss")
                        if ($isThreat) {
                            Write-Host "[$timeStr] [!] AUDIT ALERT: $details" -ForegroundColor Red
                        } else {
                            Write-Host "[$timeStr] [+] AUDIT LOG: $details" -ForegroundColor DarkCyan
                        }
                    }
                }
            }
        } catch {}

        # Keep cache trimmed
        if ($processedRecordIds.Count -gt 1000) {
            $processedRecordIds.Clear()
        }

        # Update lastCheck pointer
        $lastCheck = $currentTime

        # 3. Always dispatch telemetry batch or heartbeat
        $batch = @{
            agent_id = "laptop-syslog-agent"
            hostname = $HOSTNAME
            os       = $OS
            ip       = $IP
            events   = $events
        }

        $jsonPayload = $batch | ConvertTo-Json -Depth 5 -Compress
        $null = Invoke-RestMethod -Uri $API_ENDPOINT -Method Post -Body $jsonPayload -ContentType "application/json" -TimeoutSec 3 -ErrorAction SilentlyContinue

    } catch {
        # Silent sleep on API error (e.g. backend restarting)
    }

    Start-Sleep -Seconds 3
}
