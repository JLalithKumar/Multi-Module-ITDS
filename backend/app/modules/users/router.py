from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.core.deps import require_permissions
from app.core.security import hash_password, validate_password_strength
from app.db.models import Alert, AuditLog, Role, SessionToken, User
from app.db.session import get_db

router = APIRouter()


class EmployeeCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role_name: str = "Viewer"


class EmployeeUpdate(BaseModel):
    full_name: str | None = None
    role_name: str | None = None
    is_active: bool | None = None


class PasswordResetPayload(BaseModel):
    new_password: str


def _user_dict(user: User, alert_count: int, critical_count: int) -> dict:
    risk_level = "critical" if critical_count > 0 else "high" if alert_count > 3 else "medium" if alert_count > 0 or user.failed_login_count > 2 else "low"
    is_locked = bool(user.locked_until and user.locked_until > datetime.now(timezone.utc))
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.name if user.role else "Viewer",
        "is_active": user.is_active,
        "is_verified": user.is_verified,
        "mfa_enabled": user.mfa_enabled,
        "failed_login_count": user.failed_login_count,
        "is_locked": is_locked,
        "locked_until": user.locked_until.isoformat() if user.locked_until else None,
        "alert_count": alert_count,
        "critical_alert_count": critical_count,
        "risk_level": risk_level,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


@router.get("")
def list_employees(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions("users:read")),
) -> dict:
    users = db.query(User).filter(User.organization_id == current_user.organization_id).order_by(User.id.asc()).all()
    results = []
    for u in users:
        alerts = db.query(Alert).filter(Alert.user_email == u.email).all()
        critical_count = sum(1 for a in alerts if a.severity == "critical")
        results.append(_user_dict(u, len(alerts), critical_count))
    return {"success": True, "data": results}


@router.post("")
def create_employee(
    payload: EmployeeCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions("users:create")),
) -> dict:
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=409, detail="Employee with this email already exists")

    try:
        validate_password_strength(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    role = db.query(Role).filter(Role.name == payload.role_name).first()
    if not role:
        role = db.query(Role).filter(Role.name == "Viewer").first()

    new_user = User(
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role_id=role.id,
        is_active=True,
        is_verified=True,
        organization_id=current_user.organization_id,
    )
    db.add(new_user)
    db.add(
        AuditLog(
            actor=current_user.email,
            action="employee:create",
            entity="users",
            metadata_json={"email": payload.email, "role": role.name},
            ip_address=request.client.host if request.client else "",
        )
    )
    db.commit()
    db.refresh(new_user)
    return {"success": True, "data": _user_dict(new_user, 0, 0)}


@router.get("/{user_id}")
def get_employee(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions("users:read")),
) -> dict:
    user = db.query(User).filter(User.id == user_id, User.organization_id == current_user.organization_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Employee not found")
    alerts = db.query(Alert).filter(Alert.user_email == user.email).all()
    critical_count = sum(1 for a in alerts if a.severity == "critical")
    return {"success": True, "data": _user_dict(user, len(alerts), critical_count)}


@router.patch("/{user_id}")
def update_employee(
    user_id: int,
    payload: EmployeeUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions("users:update")),
) -> dict:
    user = db.query(User).filter(User.id == user_id, User.organization_id == current_user.organization_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Employee not found")

    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.role_name is not None:
        role = db.query(Role).filter(Role.name == payload.role_name).first()
        if role:
            user.role_id = role.id

    db.add(
        AuditLog(
            actor=current_user.email,
            action="employee:update",
            entity="users",
            metadata_json={"user_id": user_id, "changes": payload.model_dump(exclude_unset=True)},
            ip_address=request.client.host if request.client else "",
        )
    )
    db.commit()
    db.refresh(user)
    alerts = db.query(Alert).filter(Alert.user_email == user.email).all()
    critical_count = sum(1 for a in alerts if a.severity == "critical")
    return {"success": True, "data": _user_dict(user, len(alerts), critical_count)}


@router.post("/{user_id}/toggle-lock")
def toggle_lock(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions("users:update")),
) -> dict:
    user = db.query(User).filter(User.id == user_id, User.organization_id == current_user.organization_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Employee not found")

    is_currently_locked = bool(user.locked_until and user.locked_until > datetime.now(timezone.utc))
    if is_currently_locked:
        user.locked_until = None
        user.failed_login_count = 0
        action = "employee:unlock"
    else:
        user.locked_until = datetime.now(timezone.utc) + timedelta(days=365)
        action = "employee:lock"
        # Revoke their active sessions when locked
        db.query(SessionToken).filter(SessionToken.user_id == user.id).update({"revoked": True})

    db.add(
        AuditLog(
            actor=current_user.email,
            action=action,
            entity="users",
            metadata_json={"user_id": user_id, "email": user.email},
            ip_address=request.client.host if request.client else "",
        )
    )
    db.commit()
    return {"success": True, "data": {"is_locked": not is_currently_locked}}


@router.post("/{user_id}/revoke-sessions")
def revoke_sessions(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions("users:update")),
) -> dict:
    user = db.query(User).filter(User.id == user_id, User.organization_id == current_user.organization_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Employee not found")

    revoked_count = db.query(SessionToken).filter(SessionToken.user_id == user.id, SessionToken.revoked.is_(False)).update({"revoked": True})
    db.add(
        AuditLog(
            actor=current_user.email,
            action="employee:revoke_sessions",
            entity="sessions",
            metadata_json={"user_id": user_id, "count": revoked_count},
            ip_address=request.client.host if request.client else "",
        )
    )
    db.commit()
    return {"success": True, "data": {"revoked_sessions": revoked_count}}


@router.post("/{user_id}/reset-password")
def reset_password(
    user_id: int,
    payload: PasswordResetPayload,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions("users:update")),
) -> dict:
    user = db.query(User).filter(User.id == user_id, User.organization_id == current_user.organization_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Employee not found")

    try:
        validate_password_strength(payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    user.password_hash = hash_password(payload.new_password)
    user.force_password_change = True
    user.failed_login_count = 0
    user.locked_until = None
    db.query(SessionToken).filter(SessionToken.user_id == user.id).update({"revoked": True})

    db.add(
        AuditLog(
            actor=current_user.email,
            action="employee:reset_password",
            entity="users",
            metadata_json={"user_id": user_id},
            ip_address=request.client.host if request.client else "",
        )
    )
    db.commit()
    return {"success": True, "message": "Password updated successfully. Active sessions revoked."}


@router.get("/{user_id}/activity")
def employee_activity(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions("users:read")),
) -> dict:
    user = db.query(User).filter(User.id == user_id, User.organization_id == current_user.organization_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Employee not found")

    alerts = db.query(Alert).filter(Alert.user_email == user.email).order_by(Alert.created_at.desc()).limit(20).all()
    audit_logs = db.query(AuditLog).filter(AuditLog.actor == user.email).order_by(AuditLog.created_at.desc()).limit(20).all()

    return {
        "success": True,
        "data": {
            "user": {"id": user.id, "email": user.email, "full_name": user.full_name, "role": user.role.name},
            "alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "status": a.status,
                    "source": a.source,
                    "description": a.description,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in alerts
            ],
            "audit_logs": [
                {
                    "id": log.id,
                    "action": log.action,
                    "entity": log.entity,
                    "ip_address": log.ip_address,
                    "metadata": log.metadata_json,
                    "created_at": log.created_at.isoformat() if log.created_at else None,
                }
                for log in audit_logs
            ],
        },
    }
