import base64
import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "HS256"
DEFAULT_PASSWORDS = {"Password123!", "Admin123!", "ChangeMe123!"}


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def validate_password_strength(password: str) -> None:
    if password in DEFAULT_PASSWORDS:
        raise ValueError("Password is a known default and cannot be used")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    checks = [
        re.search(r"[a-z]", password),
        re.search(r"[A-Z]", password),
        re.search(r"\d", password),
        re.search(r"[^A-Za-z0-9]", password),
    ]
    if sum(bool(check) for check in checks) < 4:
        raise ValueError("Password must include uppercase, lowercase, number, and symbol")


def generate_secure_token() -> str:
    return token_urlsafe(32)


def hash_token(token: str) -> str:
    return hmac.new(settings.SECRET_KEY.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def _fernet() -> Fernet:
    material = (settings.FIELD_ENCRYPTION_KEY or settings.SECRET_KEY).encode("utf-8")
    key = base64.urlsafe_b64encode(hashlib.sha256(material).digest())
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")


def create_token(subject: str, expires_delta: timedelta, token_type: str, extra: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "jti": str(uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(subject: str, role: str) -> str:
    return create_token(
        subject,
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "access",
        {"role": role},
    )


def create_refresh_token(subject: str) -> str:
    return create_token(subject, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS), "refresh")


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise ValueError("Invalid or expired token") from exc
