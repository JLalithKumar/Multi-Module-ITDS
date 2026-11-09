from fastapi import APIRouter
from sqlalchemy import text

from app.db.session import SessionLocal

from app.modules.agent.router import router as agent_router
from app.modules.anomaly.router import router as anomaly_router
from app.modules.audit.router import router as audit_router
from app.modules.auth.router import router as auth_router
from app.modules.dashboard.router import router as dashboard_router
from app.modules.detection.router import router as detection_router
from app.modules.incidents.router import router as incidents_router
from app.modules.logs.router import router as logs_router
from app.modules.malware.router import router as malware_router
from app.modules.network.router import router as network_router
from app.modules.notifications.router import router as notifications_router
from app.modules.reports.router import router as reports_router
from app.modules.settings.router import router as settings_router
from app.modules.system.router import router as system_router
from app.modules.threat_intel.router import router as threat_intel_router
from app.modules.users.router import router as users_router
from app.modules.vulnerability.router import router as vulnerability_router
from app.modules.websocket.router import router as websocket_router

api_router = APIRouter()
api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(logs_router, prefix="/logs", tags=["Log Management"])
api_router.include_router(detection_router, prefix="/detection", tags=["Threat Detection"])
api_router.include_router(anomaly_router, prefix="/anomaly", tags=["Anomaly Detection"])
api_router.include_router(network_router, prefix="/network", tags=["Network Monitoring"])
api_router.include_router(malware_router, prefix="/malware", tags=["Malware Analysis"])
api_router.include_router(vulnerability_router, prefix="/vulnerabilities", tags=["Vulnerability Scanner"])
api_router.include_router(threat_intel_router, prefix="/threat-intel", tags=["Threat Intelligence"])
api_router.include_router(incidents_router, prefix="/incidents", tags=["Incident Management"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reports"])
api_router.include_router(notifications_router, prefix="/notifications", tags=["Notifications"])
api_router.include_router(audit_router, prefix="/audit", tags=["Audit Logs"])
api_router.include_router(settings_router, prefix="/settings", tags=["System Settings"])
api_router.include_router(users_router, prefix="/users", tags=["User & Employee Management"])
api_router.include_router(system_router, prefix="/system", tags=["System Telemetry & Simulation"])
api_router.include_router(agent_router, prefix="/agent", tags=["Live Endpoint Agent"])
api_router.include_router(websocket_router, prefix="/ws", tags=["Real Time"])


@api_router.get("/health")
def health() -> dict:
    return {"success": True, "data": {"status": "healthy", "service": "cybershield-xdr"}}


@api_router.get("/ready")
def ready() -> dict:
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    finally:
        db.close()
    return {"success": True, "data": {"status": "ready"}}
