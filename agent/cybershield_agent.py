#!/usr/bin/env python3
"""
CyberShield XDR -- Live Cross-Platform Endpoint Monitoring Agent
Monitors real-time active outbound sockets, processes, and web connections
and pushes telemetry to CyberShield XDR.
"""

import json
import os
import platform
import socket
import sys
import time
import urllib.request

API_ENDPOINT = os.getenv("CYBERSHIELD_API", "http://localhost:8000/api/v1/agent/telemetry")
HOSTNAME = socket.gethostname()
OS_PLATFORM = f"{platform.system()} {platform.release()}"


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()

print("\033[96m=================================================================\033[0m")
print("\033[93m   CyberShield XDR -- Live Endpoint Monitoring Agent            \033[0m")
print("\033[96m=================================================================\033[0m")
print(f"\033[92m[+] Hostname      : {HOSTNAME}\033[0m")
print(f"\033[92m[+] Local IP      : {LOCAL_IP}\033[0m")
print(f"\033[92m[+] OS Platform   : {OS_PLATFORM}\033[0m")
print(f"\033[92m[+] Ingestion API : {API_ENDPOINT}\033[0m")
print("\033[96m=================================================================\033[0m")
print("\033[97m[*] Monitoring active outbound connections and process activity...\033[0m")
print("\033[90mAgent running. Press Ctrl+C to terminate.\033[0m\n")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("\033[93m[!] 'psutil' not installed. Running in heartbeat / light probe mode.\033[0m")

seen_conns = set()

while True:
    events = []

    if HAS_PSUTIL:
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status in ("ESTABLISHED", "SYN_SENT") and conn.raddr:
                    rip = conn.raddr.ip
                    rport = conn.raddr.port

                    # Skip loopback and private subnets
                    if rip.startswith("127.") or rip.startswith("192.168.") or rip.startswith("10.") or rip == "::1":
                        continue

                    conn_key = f"{conn.pid}:{rip}:{rport}"
                    if conn_key not in seen_conns:
                        seen_conns.add(conn_key)
                        proc_name = "unknown"
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except Exception:
                                pass

                        is_suspicious = "203.0.113." in rip or rip.endswith(".13") or rport in (4444, 1337, 6667, 8888)
                        if is_suspicious:
                            print(f"\033[91m[!] ALERT - SUSPICIOUS TRAFFIC: {proc_name} -> {rip}:{rport}\033[0m")
                        else:
                            print(f"\033[90m[+] Captured Outbound: {proc_name} -> {rip}:{rport}\033[0m")

                        events.append({
                            "event_type": "network_connection",
                            "process_name": proc_name,
                            "pid": conn.pid or 0,
                            "dest_ip": rip,
                            "dest_port": rport,
                            "domain": "",
                            "cmdline": "",
                            "details": f"Status: {conn.status}",
                        })
        except Exception as e:
            pass

        if len(seen_conns) > 500:
            seen_conns.clear()

    payload = {
        "agent_id": "laptop-agent-py",
        "hostname": HOSTNAME,
        "os": OS_PLATFORM,
        "ip": LOCAL_IP,
        "events": events,
    }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(API_ENDPOINT, data=data_bytes, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            threats = resp_data.get("data", {}).get("threats_count", 0)
            if threats > 0:
                print(f"\033[95m[***] CYBERSHIELD SERVER DETECTED {threats} THREATS! [***]\033[0m")
    except Exception:
        print(f"\033[93m[-] Waiting for CyberShield server at {API_ENDPOINT}...\033[0m")

    time.sleep(2)
