from datetime import datetime, timezone
import re
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.models import (
    Alert,
    Incident,
    NetworkEvent,
    Notification,
    SecurityLog,
    User,
)
from app.db.session import get_db
from app.services.alert_dispatcher import (
    dispatch_critical_threat_alert,
    get_alert_config,
    update_alert_config,
    DISPATCH_HISTORY,
)

router = APIRouter()

# In-memory agent state for ultra-fast telemetry streaming
AGENT_STATE = {
    "agent_id": "laptop-sensor-01",
    "hostname": "Unknown",
    "os": "Windows",
    "ip": "127.0.0.1",
    "status": "waiting",
    "last_seen": None,
    "events_captured": 0,
    "threats_detected": 0,
    "recent_events": [],
}

SUSPICIOUS_IPS = {"203.0.113.", "198.51.100.", "192.0.2.", ".13"}
SUSPICIOUS_PORTS = {4444, 1337, 6667, 8888, 31337, 9999}
SUSPICIOUS_DOMAINS = {
    "testmyids.com",
    "evil.com",
    "malware-traffic-analysis.net",
    "c2-server",
    "phish",
    "ransom",
    "exploit",
    "darknet",
}


class AgentEvent(BaseModel):
    event_type: str  # "network_connection", "process_launch", "dns_lookup", "suspicious_login"
    process_name: str = "unknown"
    pid: int = 0
    dest_ip: str = ""
    dest_port: int = 0
    domain: str = ""
    cmdline: str = ""
    details: str = ""


class TelemetryBatch(BaseModel):
    agent_id: str = "laptop-sensor-01"
    hostname: str = "LAPTOP"
    os: str = "Windows"
    ip: str = "127.0.0.1"
    events: list[AgentEvent] = []


@router.get("/status")
def get_agent_status() -> dict:
    is_online = False
    if AGENT_STATE["last_seen"]:
        diff = (datetime.now(timezone.utc) - AGENT_STATE["last_seen"]).total_seconds()
        is_online = diff < 20

    return {
        "success": True,
        "data": {
            **AGENT_STATE,
            "is_online": is_online,
            "last_seen_iso": AGENT_STATE["last_seen"].isoformat() if AGENT_STATE["last_seen"] else None,
            "recent_events": AGENT_STATE["recent_events"][-25:],
        },
    }


@router.post("/telemetry")
def receive_telemetry(payload: TelemetryBatch, db: Session = Depends(get_db)) -> dict:
    now = datetime.now(timezone.utc)
    AGENT_STATE["hostname"] = payload.hostname
    AGENT_STATE["os"] = payload.os
    AGENT_STATE["ip"] = payload.ip
    AGENT_STATE["last_seen"] = now
    AGENT_STATE["status"] = "online"

    # Find admin or first user for org scoping
    admin_user = db.query(User).filter(User.role.has(name="Admin")).first() or db.query(User).first()
    org_id = admin_user.organization_id if admin_user else 1

    alerts_created = []

    for ev in payload.events:
        AGENT_STATE["events_captured"] += 1
        is_threat = False
        threat_title = ""
        threat_severity = "high"
        threat_tactic = "Defense Evasion"
        threat_technique = "T1071 Application Layer Protocol"

        # Check 1: Suspicious destination IP
        if ev.dest_ip:
            if any(ev.dest_ip.startswith(prefix) or ev.dest_ip.endswith(prefix) for prefix in SUSPICIOUS_IPS):
                is_threat = True
                threat_title = f"Rogue External IP Access: {ev.dest_ip}:{ev.dest_port}"
                threat_severity = "critical" if ev.dest_ip.endswith(".13") else "high"
                threat_tactic = "Command and Control"
                threat_technique = "T1071.001 Web Protocols"

        # Check 2: Suspicious ports (Common C2 / Reverse Shells)
        if ev.dest_port in SUSPICIOUS_PORTS:
            is_threat = True
            threat_title = f"Rogue Communication Port {ev.dest_port} Detected"
            threat_severity = "critical"
            threat_tactic = "Command and Control"
            threat_technique = "T1571 Non-Standard Port"

        # Check 3: Suspicious Domain / Web Access
        if ev.domain:
            low_domain = ev.domain.lower()
            if any(bad in low_domain for bad in SUSPICIOUS_DOMAINS):
                is_threat = True
                threat_title = f"Suspicious Website Access: {ev.domain}"
                threat_severity = "critical"
                threat_tactic = "Initial Access"
                threat_technique = "T1189 Drive-by Compromise"

        # Check 4: Suspicious Process / Encoded Commands
        if ev.cmdline:
            low_cmd = ev.cmdline.lower()
            if any(kw in low_cmd for kw in ["-enc", "-encodedcommand", "downloadstring", "vssadmin", "mimikatz", "invoke-expression"]):
                is_threat = True
                threat_title = f"Suspicious Execution: {ev.process_name}"
                threat_severity = "critical"
                threat_tactic = "Execution"
                threat_technique = "T1059 Command and Scripting Interpreter"

        # Check 5: Windows Security / System Event Logs
        low_details = f"{ev.details} {ev.cmdline}".lower()
        if ev.event_type in ("windows_event", "system_log", "security_audit", "syslog") or "event" in low_details:
            if "4625" in low_details or "logon failure" in low_details or "failed to log on" in low_details:
                is_threat = True
                threat_title = "Failed Authentication / Password Guessing (Event 4625)"
                threat_severity = "high"
                threat_tactic = "Credential Access"
                threat_technique = "T1110.001 Password Guessing"
            elif "4740" in low_details or "account locked" in low_details or "lockout" in low_details:
                is_threat = True
                threat_title = "User Account Lockout Detected (Event 4740)"
                threat_severity = "high"
                threat_tactic = "Credential Access"
                threat_technique = "T1110 Brute Force"
            elif "7045" in low_details or "service was installed" in low_details or "service installed" in low_details:
                is_threat = True
                threat_title = "New Service Installed (Event 7045 - Potential Persistence)"
                threat_severity = "medium"
                threat_tactic = "Persistence"
                threat_technique = "T1543.003 Windows Service"
            elif "1102" in low_details or "audit log was cleared" in low_details or "log cleared" in low_details:
                is_threat = True
                threat_title = "Security Audit Log Cleared (Event 1102 - Defense Evasion)"
                threat_severity = "critical"
                threat_tactic = "Defense Evasion"
                threat_technique = "T1070.001 Clear Windows Event Logs"
            elif "4697" in low_details or "service installation was attempted" in low_details:
                is_threat = True
                threat_title = "Service Installation Attempt (Event 4697)"
                threat_severity = "high"
                threat_tactic = "Persistence"
                threat_technique = "T1543.003 Windows Service"
            elif any(kw in low_details for kw in ["mimikatz", "sekurlsa", "invoke-expression", "downloadstring", "ransom", "vssadmin"]):
                is_threat = True
                threat_title = f"Malicious Activity in System Log: {ev.process_name}"
                threat_severity = "critical"
                threat_tactic = "Execution"
                threat_technique = "T1059 Command and Scripting Interpreter"

        # Determine readable destination/summary
        destination_label = ""
        if ev.dest_ip and ev.dest_port:
            destination_label = f"{ev.dest_ip}:{ev.dest_port}"
        elif ev.domain:
            destination_label = ev.domain
        elif ev.details:
            destination_label = ev.details
        elif ev.cmdline:
            destination_label = ev.cmdline
        else:
            destination_label = "Local System Activity"

        # Record into recent in-memory ring buffer
        stream_item = {
            "time": now.strftime("%H:%M:%S"),
            "process": ev.process_name,
            "pid": ev.pid,
            "destination": destination_label,
            "event_type": ev.event_type,
            "is_threat": is_threat,
            "threat_title": threat_title,
            "severity": threat_severity if is_threat else "info",
        }
        AGENT_STATE["recent_events"].append(stream_item)
        if len(AGENT_STATE["recent_events"]) > 100:
            AGENT_STATE["recent_events"].pop(0)

        # Store system logs and Windows events into SecurityLog table
        if ev.event_type in ("windows_event", "system_log", "security_audit", "syslog"):
            db.add(
                SecurityLog(
                    source=f"WinAgent-{payload.hostname}",
                    log_type=ev.event_type,
                    message=f"[{ev.event_type.upper()}] {ev.process_name} (PID {ev.pid}): {ev.details or destination_label}",
                    severity=threat_severity if is_threat else "info",
                    tags=["live-agent", "host-telemetry", ev.event_type],
                    organization_id=org_id,
                )
            )

        # Always log network activity as a NetworkEvent if dest_ip exists
        if ev.dest_ip and ev.dest_port:
            db.add(
                NetworkEvent(
                    src_ip=payload.ip,
                    dst_ip=ev.dest_ip,
                    src_port=50000,
                    port=ev.dest_port,
                    protocol="TCP",
                    event_type=f"Outbound: {ev.process_name}",
                    severity=threat_severity if is_threat else "info",
                    status="blocked" if is_threat else "established",
                    bytes_in=1420,
                    bytes_out=890,
                    geo={"host": payload.hostname},
                    organization_id=org_id,
                )
            )

        # If flagged as a threat, generate Security Alert, Incident, and WebSocket Notification
        if is_threat:
            AGENT_STATE["threats_detected"] += 1

            # 1. Security Log
            db.add(
                SecurityLog(
                    source=f"agent-{payload.hostname}",
                    log_type="live-sensor",
                    message=f"[AGENT ALERT] Process {ev.process_name} (PID {ev.pid}) triggered threat: {threat_title}. Details: {ev.details or ev.cmdline or ev.dest_ip}",
                    severity=threat_severity,
                    tags=["live-agent", "laptop-detection", ev.event_type],
                    organization_id=org_id,
                )
            )

            # 2. Alert
            alert_rec = Alert(
                title=threat_title,
                severity=threat_severity,
                status="open",
                source=f"Endpoint: {payload.hostname} ({ev.process_name})",
                tactic=threat_tactic,
                technique=threat_technique,
                confidence=0.96,
                description=f"Live sensor on {payload.hostname} detected live hostile action: {ev.process_name} connected to {ev.dest_ip or ev.domain}:{ev.dest_port}. Cmdline: {ev.cmdline or 'Standard Web Request'}",
                organization_id=org_id,
                user_email=admin_user.email if admin_user else "admin@cybershield.dev",
            )
            db.add(alert_rec)
            db.flush()

            # 3. Notification for WebSocket Live Feed
            if admin_user:
                db.add(
                    Notification(
                        channel="browser",
                        title=f"🚨 {threat_title}",
                        message=alert_rec.description,
                        severity=threat_severity,
                        organization_id=org_id,
                        recipient_user_id=admin_user.id,
                        required_permission="alerts:read",
                        related_entity="alert",
                        related_id=alert_rec.id,
                    )
                )

            # 4. Critical Incident
            if threat_severity == "critical":
                db.add(
                    Incident(
                        title=f"Endpoint Compromise: {threat_title} on {payload.hostname}",
                        severity="critical",
                        status="triage",
                        assignee=admin_user.full_name if admin_user else "Lead Analyst",
                        evidence={"source_host": payload.hostname, "process": ev.process_name, "destination": ev.dest_ip or ev.domain},
                        timeline=[
                            {"event": f"Sensor detected live hostile activity by {ev.process_name}", "actor": "Endpoint Agent"},
                            {"event": "Incident dispatched to SOC Lead", "actor": "CyberShield XDR"},
                        ],
                        organization_id=org_id,
                    )
                )

            # 5. Immediate Emergency SMS & Email Alert Dispatch
            if threat_severity in ("critical", "high"):
                try:
                    dispatch_critical_threat_alert(
                        title=threat_title,
                        details=alert_rec.description,
                        hostname=payload.hostname,
                        process_name=ev.process_name,
                        severity=threat_severity,
                        ip=payload.ip,
                        destination=destination_label,
                    )
                except Exception as exc:
                    pass

            alerts_created.append({"title": threat_title, "severity": threat_severity})

    db.commit()

    return {
        "success": True,
        "data": {
            "status": "processed",
            "events_count": len(payload.events),
            "threats_count": len(alerts_created),
            "threats": alerts_created,
        },
    }


class AlertConfigUpdate(BaseModel):
    registered_email: str | None = None
    registered_phone: str | None = None
    email_enabled: bool | None = None
    sms_enabled: bool | None = None
    sms_provider: str | None = None
    sms_webhook_url: str | None = None
    sms_api_key: str | None = None
    twilio_account_sid: str | None = None
    twilio_from_phone: str | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_pass: str | None = None


@router.get("/alerts-config")
def get_alert_notification_config() -> dict:
    return {
        "success": True,
        "config": get_alert_config(),
        "recent_dispatches": DISPATCH_HISTORY[-20:],
    }


@router.post("/alerts-config")
def set_alert_notification_config(payload: AlertConfigUpdate) -> dict:
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    new_cfg = update_alert_config(updates)
    return {"success": True, "config": new_cfg}


@router.post("/test-alert-dispatch")
def trigger_test_alert_dispatch() -> dict:
    result = dispatch_critical_threat_alert(
        title="TEST CRITICAL THREAT: Rogue Reverse Shell Probe",
        details="Autonomous emergency test alert triggered from CyberShield SOC console to verify real-time SMS & Email channels.",
        hostname="DEMO-LAPTOP",
        process_name="powershell_probe.exe",
        severity="critical",
        ip="192.168.1.50",
        destination="rogue-c2.darknet:1337",
    )
    return {"success": True, "dispatch": result}
