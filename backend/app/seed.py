from app.core.config import settings
from app.core.security import hash_password, validate_password_strength
from app.db.models import Alert, Incident, NetworkEvent, Notification, Organization, Permission, Role, SecurityLog, SystemSetting, User
from app.db.session import SessionLocal


ROLE_PERMISSIONS = {
    "Admin": [
        "dashboard:read", "logs:read", "logs:export", "alerts:read", "alerts:create", "alerts:update", "alerts:delete",
        "incidents:read", "incidents:create", "incidents:update", "incidents:assign", "incidents:close",
        "malware:submit", "malware:analyze", "malware:download", "vulnerability:scan", "vulnerability:schedule",
        "threat_intel:read", "threat_intel:update", "reports:read", "reports:create", "reports:export",
        "audit:read", "users:read", "users:create", "users:update", "users:disable", "roles:read", "roles:manage",
        "settings:read", "settings:update",
    ],
    "SOC Manager": [
        "dashboard:read", "logs:read", "logs:export", "alerts:read", "alerts:update", "incidents:read",
        "incidents:create", "incidents:update", "incidents:assign", "incidents:close", "reports:read",
        "reports:create", "reports:export", "audit:read", "users:read", "roles:read", "settings:read",
    ],
    "Senior Security Analyst": [
        "dashboard:read", "logs:read", "logs:export", "alerts:read", "alerts:create", "alerts:update",
        "incidents:read", "incidents:create", "incidents:update", "malware:submit", "malware:analyze",
        "vulnerability:scan", "threat_intel:read", "threat_intel:update", "reports:read",
    ],
    "SOC Analyst": [
        "dashboard:read", "logs:read", "alerts:read", "alerts:update", "incidents:read", "incidents:create",
        "incidents:update", "threat_intel:read", "reports:read",
    ],
    "Security Analyst": [
        "dashboard:read", "logs:read", "alerts:read", "incidents:read", "threat_intel:read", "reports:read",
    ],
    "Malware Analyst": ["dashboard:read", "logs:read", "alerts:read", "malware:submit", "malware:analyze", "malware:download", "reports:read"],
    "Vulnerability Analyst": ["dashboard:read", "logs:read", "alerts:read", "vulnerability:scan", "vulnerability:schedule", "reports:read"],
    "Threat Hunter": ["dashboard:read", "logs:read", "logs:export", "alerts:read", "alerts:create", "threat_intel:read", "threat_intel:update", "reports:read"],
    "Auditor": ["dashboard:read", "reports:read", "audit:read", "settings:read"],
    "Viewer": ["dashboard:read", "alerts:read", "incidents:read", "reports:read"],
}


def seed_database() -> None:
    db = SessionLocal()
    try:
        role_descriptions = {
            "Admin": "Full platform administration",
            "SOC Manager": "Manage SOC operations and reporting",
            "Senior Security Analyst": "Lead analyst with elevated investigation permissions",
            "SOC Analyst": "Investigate alerts and incidents",
            "Security Analyst": "Legacy analyst role",
            "Malware Analyst": "Analyze submitted files and malware reports",
            "Vulnerability Analyst": "Run and schedule vulnerability scans",
            "Threat Hunter": "Hunt and enrich threat intelligence",
            "Auditor": "Read audit and compliance data",
            "Viewer": "Read-only access",
        }
        for name, description in role_descriptions.items():
            if not db.query(Role).filter(Role.name == name).first():
                db.add(Role(name=name, description=description))
        db.flush()

        for role in db.query(Role).all():
            existing_permissions = {permission.action for permission in role.permissions}
            for action in ROLE_PERMISSIONS.get(role.name, ROLE_PERMISSIONS["Viewer"]):
                if action not in existing_permissions:
                    db.add(Permission(role_id=role.id, action=action))

        admin_role = db.query(Role).filter(Role.name == "Admin").first()
        default_org = db.query(Organization).filter(Organization.slug == "default").first()
        if not default_org:
            default_org = Organization(name="Default Organization", slug="default")
            db.add(default_org)
            db.flush()

        for legacy_email in ["admin@cybershield.dev", "admin@cybershield.local"]:
            if legacy_email != settings.ADMIN_BOOTSTRAP_EMAIL:
                legacy_user = db.query(User).filter(User.email == legacy_email).first()
                if legacy_user:
                    legacy_user.is_active = False
                    legacy_user.password_hash = hash_password(settings.generate_secret_hint())
                    legacy_user.force_password_change = True

        if settings.ADMIN_BOOTSTRAP_EMAIL and settings.ADMIN_BOOTSTRAP_PASSWORD:
            validate_password_strength(settings.ADMIN_BOOTSTRAP_PASSWORD)
            bootstrap_user = db.query(User).filter(User.email == settings.ADMIN_BOOTSTRAP_EMAIL).first()
            is_test_env = settings.ENVIRONMENT.lower() == "test"
            force_change = True if is_test_env else False
            if not bootstrap_user:
                db.add(
                    User(
                        email=settings.ADMIN_BOOTSTRAP_EMAIL,
                        full_name="CyberShield Administrator",
                        password_hash=hash_password(settings.ADMIN_BOOTSTRAP_PASSWORD),
                        role_id=admin_role.id,
                        is_verified=True,
                        is_active=True,
                        mfa_enabled=False,
                        force_password_change=force_change,
                        organization_id=default_org.id,
                    )
                )
            else:
                bootstrap_user.is_active = True
                bootstrap_user.is_verified = True
                bootstrap_user.force_password_change = force_change
                bootstrap_user.password_hash = hash_password(settings.ADMIN_BOOTSTRAP_PASSWORD)
                bootstrap_user.role_id = admin_role.id
                bootstrap_user.locked_until = None
                bootstrap_user.failed_login_count = 0

        if settings.LOAD_DEMO_DATA and db.query(SecurityLog).count() == 0:
            db.add_all(
                [
                    SecurityLog(source="waf-east", log_type="nginx", message="GET /search?q=' UNION SELECT password FROM users --", severity="critical", tags=["sql-injection", "waf"]),
                    SecurityLog(source="identity", log_type="windows", message="4625 failed login burst for admin from 203.0.113.13", severity="high", tags=["brute-force"]),
                    SecurityLog(source="edr", log_type="process", message="powershell.exe -enc SQBFAFgA suspicious encoded command", severity="high", tags=["powershell"]),
                    SecurityLog(source="dns", log_type="resolver", message="Long base64-like subdomain observed from FIN-22", severity="medium", tags=["dns-tunneling"]),
                ]
            )

        if settings.LOAD_DEMO_DATA and db.query(Alert).count() == 0:
            db.add_all(
                [
                    Alert(title="SQL Injection Attempt", severity="critical", status="open", source="waf-east", tactic="Initial Access", technique="T1190", confidence=0.96, description="Public-facing app exploit pattern blocked."),
                    Alert(title="Credential Stuffing Burst", severity="high", status="investigating", source="identity", tactic="Credential Access", technique="T1110", confidence=0.88, description="Repeated failed authentication against privileged user."),
                    Alert(title="DNS Beaconing", severity="medium", status="open", source="dns", tactic="Command and Control", technique="T1071", confidence=0.74, description="Periodic DNS callbacks with suspicious entropy."),
                ]
            )

        if settings.LOAD_DEMO_DATA and db.query(Incident).count() == 0:
            db.add_all(
                [
                    Incident(title="Potential web application compromise", severity="critical", status="triage", assignee="Asha Rao", evidence={"alert_ids": [1]}, timeline=[{"event": "Alert correlated", "actor": "engine"}]),
                    Incident(title="Privileged account attack", severity="high", status="contained", assignee="Marcus Lee", evidence={"source_ip": "203.0.113.13"}, timeline=[{"event": "Account locked", "actor": "identity"}]),
                ]
            )

        if settings.LOAD_DEMO_DATA and db.query(NetworkEvent).count() == 0:
            db.add_all(
                [
                    NetworkEvent(src_ip="203.0.113.13", dst_ip="10.0.4.12", protocol="TCP", port=443, bytes_in=18292, bytes_out=921, geo={"country": "US"}),
                    NetworkEvent(src_ip="198.51.100.44", dst_ip="10.0.8.21", protocol="UDP", port=53, bytes_in=4521, bytes_out=7710, geo={"country": "DE"}),
                    NetworkEvent(src_ip="192.0.2.77", dst_ip="10.0.1.6", protocol="TCP", port=22, bytes_in=918, bytes_out=319, geo={"country": "SG"}),
                ]
            )

        if settings.LOAD_DEMO_DATA and db.query(Notification).count() == 0:
            db.add(Notification(channel="browser", title="Critical alert opened", message="SQL Injection Attempt requires triage", delivered=True))

        if db.query(SystemSetting).count() == 0:
            db.add_all(
                [
                    SystemSetting(key="company", value={"name": "CyberShield Labs"}),
                    SystemSetting(key="retention", value={"logs_days": 180, "audit_days": 365}),
                    SystemSetting(key="soc", value={"timezone": "UTC", "severity_sla_hours": {"critical": 4, "high": 12, "medium": 48}}),
                ]
            )

        db.commit()
    finally:
        db.close()
