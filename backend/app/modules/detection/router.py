import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import require_permissions
from app.db.models import Alert, Detection, DetectionSuppression, Notification, User
from app.db.session import get_db
from app.schemas.modules import DetectionRequest, DetectionResult, RuleCreate, SuppressionCreate
from app.services.alert_dispatcher import dispatch_critical_threat_alert
from app.services.security_detection import SIGNATURES, analyze_text

router = APIRouter(dependencies=[Depends(require_permissions("alerts:read"))])


@router.get("/rules")
def rules() -> dict:
    return {"success": True, "data": SIGNATURES}


@router.get("/custom-rules")
def custom_rules(db: Session = Depends(get_db)) -> dict:
    rows = db.query(Detection).order_by(Detection.id.desc()).all()
    return {"success": True, "data": [{"id": row.id, "name": row.name, "category": row.category, "severity": row.severity, "pattern": row.pattern, "enabled": row.enabled} for row in rows]}


@router.post("/custom-rules")
def create_rule(payload: RuleCreate, db: Session = Depends(get_db)) -> dict:
    row = Detection(**payload.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"success": True, "data": {"id": row.id, "name": row.name, "enabled": row.enabled}}


@router.post("/analyze", response_model=DetectionResult)
def analyze(payload: DetectionRequest, db: Session = Depends(get_db), user: User = Depends(require_permissions("alerts:read"))) -> DetectionResult:
    result = analyze_text(payload.text, payload.source)
    suppressed = {
        row.signature_name
        for row in db.query(DetectionSuppression).filter(DetectionSuppression.source == payload.source, DetectionSuppression.enabled.is_(True)).all()
    }
    custom_rules = db.query(Detection).filter(Detection.enabled.is_(True)).all()
    for rule in custom_rules:
        if re.search(rule.pattern, payload.text):
            result["alerts"].append({"title": rule.name, "severity": rule.severity, "source": payload.source, "confidence": 0.72, "description": f"Custom rule matched: {rule.category}"})
    result["alerts"] = [alert for alert in result["alerts"] if alert["title"] not in suppressed]
    result["matched"] = bool(result["alerts"])
    for alert in result["alerts"]:
        record = Alert(**alert, status="open", tactic="Detection", technique=alert["title"], organization_id=user.organization_id)
        db.add(record)
        db.flush()
        db.add(Notification(channel="browser", title=record.title, message=record.description, severity=record.severity, organization_id=user.organization_id, recipient_user_id=user.id, required_permission="alerts:read", related_entity="alert", related_id=record.id))

        # Only generate emergency SMS/Email alert when the threat is high or critical severity
        if record.severity and record.severity.lower() in ("critical", "high"):
            try:
                dispatch_critical_threat_alert(
                    title=record.title,
                    details=record.description,
                    hostname="Detection Console",
                    process_name="Threat Detection Engine",
                    severity=record.severity,
                    destination=payload.source,
                )
            except Exception:
                pass
    db.commit()
    return DetectionResult(**result)


@router.post("/suppressions")
def suppress(payload: SuppressionCreate, db: Session = Depends(get_db)) -> dict:
    row = DetectionSuppression(**payload.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"success": True, "data": {"id": row.id, "signature_name": row.signature_name, "source": row.source}}


@router.post("/correlate")
def correlate(payload: dict, db: Session = Depends(get_db)) -> dict:
    window = int(payload.get("window", 25))
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(window).all()
    by_source: dict[str, list[Alert]] = {}
    for alert in alerts:
        by_source.setdefault(alert.source, []).append(alert)
    chains = [
        {
            "source": source,
            "alert_count": len(items),
            "max_severity": "critical" if any(item.severity == "critical" for item in items) else items[0].severity,
            "titles": [item.title for item in items],
            "recommended_action": "Open or update incident" if len(items) >= 2 else "Monitor",
        }
        for source, items in by_source.items()
        if len(items) >= 1
    ]
    return {"success": True, "data": {"window": window, "chains": chains}}
