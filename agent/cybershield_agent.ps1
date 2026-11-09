# ==============================================================================
# CyberShield Live Endpoint Agent (Active Laptop Monitor)
# ==============================================================================
# Monitors real-time network connections, web navigation, and process execution
# on this machine and transmits live telemetry to CyberShield XDR.
# ==============================================================================

$API_ENDPOINT = "http://localhost:8000/api/v1/agent/telemetry"
$HOSTNAME = $env:COMPUTERNAME
$OS = "Windows 11 / $([System.Environment]::OSVersion.Version)"

# Get local IP
$IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback|vEthernet' } | Select-Object -First 1).IPAddress
if (-not $IP) { $IP = "127.0.0.1" }

Clear-Host
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   CyberShield XDR -- Live Endpoint Monitoring Agent            " -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[+] Hostname      : $HOSTNAME" -ForegroundColor Green
Write-Host "[+] Local IP      : $IP" -ForegroundColor Green
Write-Host "[+] OS Platform   : $OS" -ForegroundColor Green
Write-Host "[+] Ingestion API : $API_ENDPOINT" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Active Sensors:" -ForegroundColor White
Write-Host "    - Outbound Socket & Web Traffic Monitor" -ForegroundColor Gray
Write-Host "    - Suspicious Domain & Host Analyzer" -ForegroundColor Gray
Write-Host "    - Real-time EDR Process Inspector" -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Agent running. Try browsing or testing any site to see live capture!" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to terminate agent monitoring.`n" -ForegroundColor DarkGray

# Keep track of previously reported connections to prevent duplicate spam
$seenConnections = [System.Collections.Generic.HashSet[string]]::new()

while ($true) {
    try {
        $events = [System.Collections.ArrayList]::new()

        # 1. Inspect live active TCP connections (browsers, curl, powershell, background tools)
        $connections = Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue |
            Where-Object { 
                (($_.RemoteAddress -ne "127.0.0.1" -and 
                  $_.RemoteAddress -ne "::1" -and 
                  $_.RemoteAddress -notmatch "^192\.168\." -and 
                  $_.RemoteAddress -notmatch "^10\." -and
                  $_.RemoteAddress -ne "0.0.0.0") -or
                 ($_.RemotePort -in 1337, 4444, 6667, 8888, 31337, 9999))
            }

        foreach ($conn in $connections) {
            $connKey = "$($conn.OwningProcess):$($conn.RemoteAddress):$($conn.RemotePort)"
            if (-not $seenConnections.Contains($connKey)) {
                $seenConnections.Add($connKey) | Out-Null
                
                # Resolve process name
                $procName = "Unknown"
                try {
                    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc) { $procName = $proc.ProcessName + ".exe" }
                } catch {}

                $eventObj = @{
                    event_type   = "network_connection"
                    process_name = $procName
                    pid          = [int]$conn.OwningProcess
                    dest_ip      = [string]$conn.RemoteAddress
                    dest_port    = [int]$conn.RemotePort
                    domain       = ""
                    cmdline      = ""
                    details      = "Active connection state: $($conn.State)"
                }
                $events.Add($eventObj) | Out-Null

                # Visual terminal logging
                $isSuspicious = ($conn.RemoteAddress -like "*203.0.113.*") -or ($conn.RemoteAddress -like "*.13") -or ($conn.RemotePort -in 4444, 1337, 6667, 8888, 31337, 9999)
                if ($isSuspicious) {
                    Write-Host "[!] ALERT - SUSPICIOUS TRAFFIC: $procName -> $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Red
                } else {
                    Write-Host "[+] Net Activity: $procName -> $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor DarkGray
                }
            }
        }

        # 2. Inspect active DNS client cache for suspicious / tested domains
        try {
            $dnsEntries = Get-DnsClientCache -ErrorAction SilentlyContinue |
                Where-Object { $_.Entry -match '(?i)(testmyids|evil|malware|c2-server|phish|ransom|exploit|darknet)' }
            foreach ($dns in $dnsEntries) {
                $dnsKey = "dns:$($dns.Entry)"
                if (-not $seenConnections.Contains($dnsKey)) {
                    $seenConnections.Add($dnsKey) | Out-Null
                    $events.Add(@{
                        event_type   = "dns_lookup"
                        process_name = "DNS-Resolver"
                        pid          = 0
                        dest_ip      = if ($dns.Data) { [string]$dns.Data } else { "0.0.0.0" }
                        dest_port    = 53
                        domain       = [string]$dns.Entry
                        cmdline      = ""
                        details      = "Suspicious DNS query: $($dns.Entry) (Type: $($dns.Type))"
                    }) | Out-Null
                    Write-Host "[!] ALERT - SUSPICIOUS DOMAIN RESOLVED: $($dns.Entry)" -ForegroundColor Red
                }
            }
        } catch {}

        # 3. Inspect recent processes for suspicious command line execution
        try {
            $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.CommandLine -match '(?i)(-enc\s+|-encodedcommand\s+|vssadmin\s+delete|mimikatz|invoke-expression|downloadstring)'
                }
            foreach ($p in $procs) {
                $procKey = "proc:$($p.ProcessId):$($p.CreationDate)"
                if (-not $seenConnections.Contains($procKey)) {
                    $seenConnections.Add($procKey) | Out-Null
                    $events.Add(@{
                        event_type   = "process_launch"
                        process_name = [string]$p.Name
                        pid          = [int]$p.ProcessId
                        dest_ip      = ""
                        dest_port    = 0
                        domain       = ""
                        cmdline      = [string]$p.CommandLine
                        details      = "Suspicious commandline execution: $($p.Name)"
                    }) | Out-Null
                    Write-Host "[!] ALERT - SUSPICIOUS EXECUTION: $($p.Name) -> $($p.CommandLine)" -ForegroundColor Red
                }
            }
        } catch {}

        # Keep HashSet manageable
        if ($seenConnections.Count -gt 500) {
            $seenConnections.Clear()
        }

        # 2. Always send at least a heartbeat or batch if events exist
        $batch = @{
            agent_id = "laptop-agent-win"
            hostname = $HOSTNAME
            os       = $OS
            ip       = $IP
            events   = $events
        }

        $jsonPayload = $batch | ConvertTo-Json -Depth 5 -Compress
        $response = Invoke-RestMethod -Uri $API_ENDPOINT -Method Post -Body $jsonPayload -ContentType "application/json" -TimeoutSec 3 -ErrorAction Stop

        if ($response.data.threats_count -gt 0) {
            Write-Host "[***] CYBERSHIELD SERVER FLAGGED $($response.data.threats_count) THREAT(S) IN RECENT ACTION! [***]" -ForegroundColor Magenta
        }

    } catch {
        Write-Host "[-] Waiting for CyberShield server at $API_ENDPOINT..." -ForegroundColor DarkYellow
    }

    Start-Sleep -Seconds 2
}
