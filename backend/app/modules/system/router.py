import psutil
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import require_permissions
from app.db.models import (
    Alert,
    AuditLog,
    Incident,
    NetworkEvent,
    Notification,
    SecurityLog,
    User,
)
from app.db.session import get_db

router = APIRouter()


class SimulatePayload(BaseModel):
    threat_type: str  # sql-injection, brute-force, ransomware, powershell, port-scan, dns-tunnel
    target_user_email: str | None = None
    source: str = "demo-sensor"


@router.get("/resources")
def get_system_resources() -> dict:
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net_io = psutil.net_io_counters()

    # Get top processes by CPU/Memory
    top_processes = []
    try:
        for proc in sorted(psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]), key=lambda p: (p.info.get("cpu_percent") or 0), reverse=True)[:6]:
            top_processes.append(
                {
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "cpu_percent": round(proc.info["cpu_percent"] or 0, 1),
                    "memory_percent": round(proc.info["memory_percent"] or 0, 1),
                    "status": proc.info["status"],
                }
            )
    except Exception:
        pass

    # Resource Optimization Insights
    recommendations = []
    if cpu_percent > 75:
        recommendations.append({"type": "warning", "message": f"High CPU utilization ({cpu_percent}%). Check intensive processes."})
    else:
        recommendations.append({"type": "optimal", "message": "CPU load is optimal (<70%)."})

    if memory.percent > 80:
        recommendations.append({"type": "warning", "message": f"Memory pressure detected ({memory.percent}%). Consider clearing temp caches."})
    else:
        recommendations.append({"type": "optimal", "message": "Memory utilization is healthy."})

    if disk.percent > 85:
        recommendations.append({"type": "critical", "message": f"Storage capacity critical ({disk.percent}% used). Enable log retention cleanup."})
    else:
        recommendations.append({"type": "optimal", "message": f"Disk space is sufficient ({round(disk.free / (1024**3), 1)} GB free)."})

    return {
        "success": True,
        "data": {
            "cpu_percent": cpu_percent,
            "cpu_count": psutil.cpu_count(logical=True),
            "memory": {
                "total_gb": round(memory.total / (1024**3), 2),
                "used_gb": round(memory.used / (1024**3), 2),
                "percent": memory.percent,
            },
            "disk": {
                "total_gb": round(disk.total / (1024**3), 2),
                "used_gb": round(disk.used / (1024**3), 2),
                "percent": disk.percent,
            },
            "network_io": {
                "bytes_sent_mb": round(net_io.bytes_sent / (1024**2), 2),
                "bytes_recv_mb": round(net_io.bytes_recv / (1024**2), 2),
            },
            "top_processes": top_processes,
            "recommendations": recommendations,
        },
    }


@router.post("/simulate-threat")
def simulate_threat(
    payload: SimulatePayload,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("alerts:create")),
) -> dict:
    threat_map = {
        "sql-injection": {
            "title": "SQL Injection Exploit Probe",
            "message": "GET /api/users?id=1 UNION SELECT username, password_hash FROM auth_users --",
            "source": payload.source or "waf-proxy",
            "severity": "critical",
            "tactic": "Initial Access",
            "technique": "T1190 Exploit Public-Facing Application",
        },
        "ransomware": {
            "title": "Ransomware Shadow Copy Deletion",
            "message": "cmd.exe /c vssadmin delete shadows /all /quiet && bcdedit /set {default} recoveryenabled No",
            "source": payload.source or "edr-agent",
            "severity": "critical",
            "tactic": "Impact",
            "technique": "T1490 Inhibit System Recovery",
        },
        "powershell": {
            "title": "Obfuscated PowerShell Execution",
            "message": "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=",
            "source": payload.source or "endpoint-sensor",
            "severity": "high",
            "tactic": "Execution",
            "technique": "T1059.001 PowerShell",
        },
        "port-scan": {
            "title": "TCP Port Reconnaissance Burst",
            "message": "SYN scan detected: 20 ports probed in 1.4 seconds from scanning host 198.51.100.42",
            "source": payload.source or "network-ids",
            "severity": "medium",
            "tactic": "Discovery",
            "technique": "T1046 Network Service Discovery",
        },
        "dns-tunnel": {
            "title": "Suspected DNS Exfiltration Tunnel",
            "message": "Observed high-entropy query: dXNlcl9jcmVkZW50aWFsc19leGZpbHRyYXRpb24=.data.c2-domain.test",
            "source": payload.source or "dns-sensor",
            "severity": "medium",
            "tactic": "Command and Control",
            "technique": "T1071.004 DNS",
        },
    }

    t_info = threat_map.get(payload.threat_type)
    if not t_info and payload.threat_type != "brute-force":
        raise HTTPException(status_code=400, detail=f"Unknown threat type: {payload.threat_type}")

    target_email = payload.target_user_email or user.email

    # Handle Brute Force specifically
    if payload.threat_type == "brute-force":
        target_user = db.query(User).filter(User.email == target_email).first()
        if target_user:
            target_user.failed_login_count += 3

        log_record = SecurityLog(
            source=payload.source or "auth-gateway",
            log_type="authentication",
            message=f"Consecutive failed login burst (5 failures in 30s) for user {target_email} from IP 203.0.113.88",
            severity="high",
            tags=["brute-force", "credential-stuffing", "auth-failure"],
            organization_id=user.organization_id,
        )
        db.add(log_record)
        db.flush()

        alert_record = Alert(
            title="Credential Stuffing / Brute Force Burst",
            severity="high",
            status="open",
            source=payload.source or "auth-gateway",
            tactic="Credential Access",
            technique="T1110 Brute Force",
            confidence=0.92,
            description=f"Multiple rapid failed authentications against {target_email}. Possible credential compromise in progress.",
            organization_id=user.organization_id,
            user_email=target_email,
        )
        db.add(alert_record)
        db.flush()

        db.add(
            Notification(
                channel="browser",
                title=alert_record.title,
                message=alert_record.description,
                severity=alert_record.severity,
                organization_id=user.organization_id,
                recipient_user_id=user.id,
                required_permission="alerts:read",
                related_entity="alert",
                related_id=alert_record.id,
            )
        )
        db.commit()
        return {"success": True, "data": {"alert_id": alert_record.id, "title": alert_record.title, "severity": alert_record.severity}}

    # Standard threat simulation
    log_record = SecurityLog(
        source=t_info["source"],
        log_type="detection-simulation",
        message=t_info["message"],
        severity=t_info["severity"],
        tags=[payload.threat_type, "live-simulation"],
        organization_id=user.organization_id,
    )
    db.add(log_record)
    db.flush()

    # Create Alert
    alert_record = Alert(
        title=t_info["title"],
        severity=t_info["severity"],
        status="open",
        source=t_info["source"],
        tactic=t_info["tactic"],
        technique=t_info["technique"],
        confidence=0.95,
        description=f"Automated threat detector caught {t_info['title']}: {t_info['message'][:120]}...",
        organization_id=user.organization_id,
        user_email=target_email,
    )
    db.add(alert_record)
    db.flush()

    # Create network event if port scan or dns
    if payload.threat_type in {"port-scan", "dns-tunnel"}:
        db.add(
            NetworkEvent(
                src_ip="198.51.100.42",
                dst_ip="10.0.0.15",
                src_port=54122,
                port=80 if payload.threat_type == "port-scan" else 53,
                protocol="TCP" if payload.threat_type == "port-scan" else "UDP",
                event_type=t_info["title"],
                severity=t_info["severity"],
                status="blocked",
                bytes_in=18500,
                bytes_out=1200,
                geo={"country": "External Scanner"},
                organization_id=user.organization_id,
            )
        )

    # If critical, optionally correlate into an Incident
    if t_info["severity"] == "critical":
        incident = Incident(
            title=f"Incident: {t_info['title']}",
            severity="critical",
            status="triage",
            assignee=user.full_name or "SOC Lead",
            evidence={"alert_id": alert_record.id, "payload": t_info["message"]},
            timeline=[
                {"event": "Attack indicator detected by CyberShield", "actor": "sensor"},
                {"event": "Critical incident opened automatically", "actor": "system"},
            ],
            organization_id=user.organization_id,
        )
        db.add(incident)

    # WebSocket Notification
    db.add(
        Notification(
            channel="browser",
            title=alert_record.title,
            message=alert_record.description,
            severity=alert_record.severity,
            organization_id=user.organization_id,
            recipient_user_id=user.id,
            required_permission="alerts:read",
            related_entity="alert",
            related_id=alert_record.id,
        )
    )

    db.add(
        AuditLog(
            actor=user.email,
            action=f"simulate:{payload.threat_type}",
            entity="threat_simulation",
            metadata_json={"alert_id": alert_record.id, "type": payload.threat_type},
            ip_address=request.client.host if request.client else "",
        )
    )
    db.commit()

    return {
        "success": True,
        "data": {
            "alert_id": alert_record.id,
            "title": alert_record.title,
            "severity": alert_record.severity,
            "tactic": alert_record.tactic,
            "technique": alert_record.technique,
        },
    }


@router.post("/purge-data")
def purge_demo_data(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_permissions("settings:update")),
) -> dict:
    org_id = user.organization_id
    deleted_alerts = db.query(Alert).filter(Alert.organization_id == org_id).delete(synchronize_session=False)
    deleted_logs = db.query(SecurityLog).filter(SecurityLog.organization_id == org_id).delete(synchronize_session=False)
    deleted_incidents = db.query(Incident).filter(Incident.organization_id == org_id).delete(synchronize_session=False)
    deleted_network = db.query(NetworkEvent).filter(NetworkEvent.organization_id == org_id).delete(synchronize_session=False)
    deleted_notifs = db.query(Notification).filter(Notification.organization_id == org_id).delete(synchronize_session=False)

    db.add(
        AuditLog(
            actor=user.email,
            action="system:purge_demo_data",
            entity="database",
            metadata_json={
                "deleted_alerts": deleted_alerts,
                "deleted_logs": deleted_logs,
                "deleted_incidents": deleted_incidents,
                "deleted_network": deleted_network,
            },
            ip_address=request.client.host if request.client else "",
        )
    )
    db.commit()

    return {
        "success": True,
        "data": {
            "cleared_alerts": deleted_alerts,
            "cleared_logs": deleted_logs,
            "cleared_incidents": deleted_incidents,
            "cleared_network": deleted_network,
            "cleared_notifications": deleted_notifs,
        },
    }
