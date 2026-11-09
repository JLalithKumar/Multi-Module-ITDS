import csv
import io
import json
from pathlib import PurePath

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import require_permissions
from app.db.models import AuditLog, SecurityLog, User
from app.db.session import get_db
from app.schemas.modules import LogCreate, LogRead
from app.services.security_detection import analyze_text

router = APIRouter()


@router.get("", response_model=list[LogRead])
def list_logs(
    search: str = "",
    severity: str = "",
    skip: int = 0,
    limit: int = Query(50, le=200),
    user: User = Depends(require_permissions("logs:read")),
    db: Session = Depends(get_db),
) -> list[SecurityLog]:
    query = db.query(SecurityLog).filter(SecurityLog.organization_id == user.organization_id)
    if search:
        query = query.filter(SecurityLog.message.ilike(f"%{search}%"))
    if severity:
        query = query.filter(SecurityLog.severity == severity)
    return query.order_by(SecurityLog.created_at.desc()).offset(skip).limit(limit).all()


@router.post("", response_model=LogRead)
def create_log(payload: LogCreate, user: User = Depends(require_permissions("logs:read")), db: Session = Depends(get_db)) -> SecurityLog:
    log = SecurityLog(**payload.model_dump(), organization_id=user.organization_id)
    db.add(log)
    db.add(AuditLog(actor=user.email, action="logs:create", entity="logs", metadata_json={"source": payload.source}))
    for alert in analyze_text(payload.message, payload.source)["alerts"]:
        from app.db.models import Alert
        from app.services.alert_dispatcher import dispatch_critical_threat_alert

        db.add(Alert(**alert, status="open", tactic="Detection", technique=alert["title"], organization_id=user.organization_id))
        if alert.get("severity") in ("critical", "high"):
            try:
                dispatch_critical_threat_alert(
                    title=alert.get("title", "Critical Log Threat"),
                    details=alert.get("description", payload.message),
                    hostname=payload.source,
                    process_name="LogIngestionSensor",
                    severity=alert.get("severity", "critical"),
                    destination=payload.source,
                )
            except Exception:
                pass
    db.commit()
    db.refresh(log)
    return log


@router.post("/upload")
def upload_logs(request: Request, file: UploadFile = File(...), user: User = Depends(require_permissions("logs:read")), db: Session = Depends(get_db)) -> dict:
    safe_name = PurePath(file.filename or "upload.log").name.replace("\\", "_").replace("/", "_")
    content_bytes = file.file.read(settings.MAX_UPLOAD_BYTES + 1)
    if len(content_bytes) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file is too large")
    content = content_bytes.decode("utf-8", errors="ignore")
    created = 0
    if safe_name.endswith(".json"):
        payload = json.loads(content)
        rows = payload if isinstance(payload, list) else [payload]
        for row in rows:
            db.add(SecurityLog(source=row.get("source", safe_name), log_type=row.get("log_type", "json"), message=str(row.get("message", row)), severity=row.get("severity", "info"), raw=row, organization_id=user.organization_id))
            created += 1
    elif safe_name.endswith(".csv"):
        for row in csv.DictReader(io.StringIO(content)):
            db.add(SecurityLog(source=row.get("source", safe_name), log_type=row.get("log_type", "csv"), message=row.get("message", str(row)), severity=row.get("severity", "info"), raw=row, organization_id=user.organization_id))
            created += 1
    else:
        for line in content.splitlines():
            if line.strip():
                db.add(SecurityLog(source=safe_name, log_type="text", message=line[:4000], severity="info", raw={"line": line[:4000]}, organization_id=user.organization_id))
                created += 1
    db.add(AuditLog(actor=user.email, action="logs:upload", entity="logs", metadata_json={"file": safe_name, "count": created, "size": len(content_bytes)}, ip_address=request.client.host if request.client else ""))
    db.commit()
    return {"success": True, "data": {"created": created, "filename": safe_name}}
