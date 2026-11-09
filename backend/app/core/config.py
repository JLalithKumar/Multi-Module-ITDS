from functools import cached_property
from secrets import token_urlsafe

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "CyberShield XDR"
    ENVIRONMENT: str = "local"
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    RESET_TOKEN_EXPIRE_MINUTES: int = 30
    EMAIL_VERIFICATION_EXPIRE_HOURS: int = 24
    DATABASE_URL: str = "sqlite:///./cybershield.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    BACKEND_CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    CORS_ALLOW_METHODS: str = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    CORS_ALLOW_HEADERS: str = "Authorization,Content-Type,X-Request-ID"
    ADMIN_BOOTSTRAP_EMAIL: str = ""
    ADMIN_BOOTSTRAP_PASSWORD: str = ""
    DEFAULT_PUBLIC_ROLE: str = "Viewer"
    LOAD_DEMO_DATA: bool = True
    AUTO_CREATE_TABLES: bool = True
    FIELD_ENCRYPTION_KEY: str = ""
    MAX_UPLOAD_BYTES: int = 5 * 1024 * 1024
    LOGIN_LOCKOUT_THRESHOLD: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "security@cybershield.local"
    MFA_ISSUER: str = "CyberShield XDR"
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_FROM_PHONE: str = ""
    FAST2SMS_API_KEY: str = ""
    ALERT_RECIPIENT_PHONE: str = "+917806932929"
    SMS_PROVIDER: str = "twilio"

    @cached_property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.BACKEND_CORS_ORIGINS.split(",") if origin.strip()]

    @cached_property
    def cors_methods(self) -> list[str]:
        return [method.strip().upper() for method in self.CORS_ALLOW_METHODS.split(",") if method.strip()]

    @cached_property
    def cors_headers(self) -> list[str]:
        return [header.strip() for header in self.CORS_ALLOW_HEADERS.split(",") if header.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    def validate_runtime_security(self) -> None:
        weak_secret_values = {"", "change-me-in-production", "local-development-secret-change-before-production"}
        if self.is_production:
            missing = [
                name
                for name, value in {
                    "SECRET_KEY": self.SECRET_KEY,
                    "DATABASE_URL": self.DATABASE_URL,
                    "REDIS_URL": self.REDIS_URL,
                    "BACKEND_CORS_ORIGINS": self.BACKEND_CORS_ORIGINS,
                    "FIELD_ENCRYPTION_KEY": self.FIELD_ENCRYPTION_KEY,
                }.items()
                if not value
            ]
            if missing:
                raise RuntimeError(f"Missing production configuration: {', '.join(missing)}")
            if self.SECRET_KEY in weak_secret_values or len(self.SECRET_KEY) < 32:
                raise RuntimeError("SECRET_KEY must be a strong production secret")
            if self.FIELD_ENCRYPTION_KEY in weak_secret_values or len(self.FIELD_ENCRYPTION_KEY) < 32:
                raise RuntimeError("FIELD_ENCRYPTION_KEY must be a strong production secret")
            if "*" in self.cors_origins or not self.cors_origins:
                raise RuntimeError("Production CORS origins must be explicit")
            if self.AUTO_CREATE_TABLES:
                raise RuntimeError("AUTO_CREATE_TABLES must be disabled in production; run Alembic migrations")

    @staticmethod
    def generate_secret_hint() -> str:
        return token_urlsafe(32)


settings = Settings()
