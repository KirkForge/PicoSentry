"""Configuration management for PicoShogun."""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import get_type_hints

from picosentry._core.config import SecureBootCheck, SecurityViolation
from picosentry._core.config import assert_secure as _core_assert_secure

BASE_DIR = Path(__file__).parent.parent


def _env(key: str, default: str = "") -> str:
    """Read env var with PICOSHOGUN_ prefix first, fall back to SHOGUN_ prefix."""
    val = os.environ.get(f"PICOSHOGUN_{key}")
    if val is not None:
        return val
    return os.environ.get(f"SHOGUN_{key}", default)


def _env_bool(key: str, default: str = "false") -> bool:
    """Read boolean env var with PICOSHOGUN_ / SHOGUN_ fallback."""
    return _env(key, default).lower() == "true"


def _parse_cors_origins() -> list[str]:
    """Parse PICOSHOGUN_CORS_ORIGINS (or SHOGUN_CORS_ORIGINS) env var into a list of origins.

    Accepts comma-separated origins, e.g. ``https://app.example.com,https://admin.example.com``.
    Defaults to ``["http://localhost:8765"]`` when the env var is unset.
    In production, set SHOGUN_CORS_ORIGINS to explicit origins — wildcard is insecure.
    """
    raw = _env("CORS_ORIGINS", "").strip()
    if not raw:
        return ["http://localhost:8765"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


@dataclass
class DatabaseConfig:
    backend: str = field(default_factory=lambda: _env("DATABASE_BACKEND", "sqlite"))
    url: str = field(default_factory=lambda: _env("DATABASE_URL", ""))
    path: Path = field(default_factory=lambda: Path(_env("DATABASE_PATH", str(BASE_DIR / "picoshogun.db"))))
    backup_dir: Path = BASE_DIR / "backups"
    max_connections: int = 10
    timeout: int = 30
    backup_retention_days: int = 30
    audit_retention_days: int = 90
    journal_mode: str = "WAL"  # WAL | DELETE | TRUNCATE | PERSIST | MEMORY
    synchronous: str = "NORMAL"  # OFF | NORMAL | FULL
    wal_checkpoint_threshold: int = 1000  # pages before auto-checkpoint

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        """Load database config from environment variables."""
        return cls()  # defaults already read from env via field default_factory

@dataclass
class APIConfig:
    host: str = field(default_factory=lambda: _env("API_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("API_PORT", "8765")))
    workers: int = field(default_factory=lambda: int(_env("API_WORKERS", "1")))
    reload: bool = False
    cors_origins: list[str] = field(default_factory=_parse_cors_origins)
    api_prefix: str = "/api/v1"
    docs_url: str = "/docs"
    redoc_url: str = "/redoc"

    @classmethod
    def from_env(cls) -> "APIConfig":
        """Load API config from environment variables."""
        return cls()  # defaults already read from env via field default_factory

@dataclass
class SecurityConfig:
    secret_key: str = field(default_factory=lambda: _env("SECRET_KEY", "change-me-in-production"))
    # CRITICAL: Set PICOSHOGUN_SECRET_KEY (or SHOGUN_SECRET_KEY) env var in production! assert_secure() will refuse to start
    # with the default key. See config.validate() and config.assert_secure().
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    password_hash_rounds: int = 12
    allowed_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    rate_limit: str = "100/minute"
    ddos_shield_enabled: bool = field(default_factory=lambda: _env_bool("DDOS_SHIELD", "true"))
    allow_registration: bool = field(default_factory=lambda: _env_bool("ALLOW_REGISTRATION", "false"))
    ssl_cert_path: Path | None = None
    ssl_key_path: Path | None = None

    @classmethod
    def from_env(cls) -> "SecurityConfig":
        """Load security config from environment variables."""
        return cls()  # defaults already read from env via field default_factory

@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    max_bytes: int = 10_000_000  # 10MB
    backup_count: int = 10
    log_dir: Path = BASE_DIR / "logs"
    structured: bool = True  # JSON logging for production

@dataclass
class AlertConfig:
    discord_webhook: str | None = field(default_factory=lambda: os.environ.get("DISCORD_WEBHOOK_URL"))
    slack_webhook: str | None = field(default_factory=lambda: os.environ.get("SLACK_WEBHOOK_URL"))
    email_smtp_host: str | None = field(default_factory=lambda: _env("SMTP_HOST"))
    email_smtp_port: int = field(default_factory=lambda: int(_env("SMTP_PORT", "587")))
    email_smtp_user: str | None = field(default_factory=lambda: _env("SMTP_USER"))
    email_smtp_password: str | None = field(default_factory=lambda: _env("SMTP_PASSWORD"))
    email_smtp_use_ssl: bool = field(default_factory=lambda: _env_bool("SMTP_USE_SSL", "false"))
    email_smtp_starttls: bool = field(default_factory=lambda: _env_bool("SMTP_STARTTLS", "true"))
    email_from: str | None = field(default_factory=lambda: _env("EMAIL_FROM", "picoshogun@localhost"))
    email_to: list[str] = field(default_factory=lambda: [
        addr.strip()
        for addr in _env("EMAIL_TO", "").split(",")
        if addr.strip()
    ])
    cooldown_seconds: int = 300
    max_retries: int = 3

    @classmethod
    def from_env(cls) -> "AlertConfig":
        """Load alert config from environment variables."""
        return cls()  # defaults already read from env via field default_factory

@dataclass
class OrchestratorConfig:
    max_concurrent_projects: int = 5
    default_timeout: int = 300  # seconds
    retry_failed: bool = True
    retry_max: int = 3
    retry_delay: int = 60  # seconds
    schedule_enabled: bool = True
    health_check_interval: int = 60  # seconds

    @classmethod
    def from_env(cls) -> "OrchestratorConfig":
        """Load orchestrator config from environment variables."""
        return cls()  # defaults already read from env via field default_factory

class _SslCertCheck:
    """PicoShogun-specific: SSL cert must be configured in production."""

    def __init__(self, settings: "Settings") -> None:
        self._settings = settings

    def check(self) -> SecurityViolation | None:
        if self._settings.is_production() and not self._settings.security.ssl_cert_path:
            return SecurityViolation(
                check="ssl_cert",
                message="No SSL certificate configured in production — set PICOSHOGUN_SSL_CERT_PATH or configure TLS termination",
                severity="ERROR",
            )
        return None


class _WildcardHostsCheck:
    """PicoShogun-specific: wildcard allowed hosts in production is insecure."""

    def __init__(self, settings: "Settings") -> None:
        self._settings = settings

    def check(self) -> SecurityViolation | None:
        if self._settings.is_production() and "*" in self._settings.security.allowed_hosts:
            return SecurityViolation(
                check="wildcard_hosts",
                message="Wildcard allowed hosts in production — specify explicit hosts",
                severity="ERROR",
            )
        return None


@dataclass
class Settings:  # rationale: composed config with injectable sub-configs for testing (PR-02)
    env: str = field(default_factory=lambda: _env("ENV", "development"))
    debug: bool = field(default_factory=lambda: _env_bool("DEBUG", "false"))
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    api: APIConfig = field(default_factory=APIConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)

    def is_production(self) -> bool:
        return self.env == "production"

    def validate(self) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []

        if self.is_production():
            if self.security.secret_key == "change-me-in-production":
                issues.append("SECURITY: Default secret key in production")
            if not self.security.ssl_cert_path:
                issues.append("SECURITY: No SSL certificate configured (set PICOSHOGUN_SSL_CERT_PATH or configure TLS termination upstream)")
            if self.debug:
                issues.append("SECURITY: Debug mode enabled in production")
            if "*" in self.security.allowed_hosts:
                issues.append("SECURITY: Wildcard allowed hosts in production")
            if "*" in self.api.cors_origins and self.api.cors_origins == ["*"]:
                issues.append("SECURITY: Wildcard CORS origin in production — specify explicit origins")

        # Non-production warnings (still logged but not blocking)
        if not self.is_production():
            if self.security.secret_key == "change-me-in-production":
                issues.append("CONFIG: Default secret key — set SHOGUN_SECRET_KEY before production deployment")
            if self.api.host == "0.0.0.0":
                issues.append("CONFIG: Binding to all interfaces — use 127.0.0.1 for local dev or set SHOGUN_API_HOST")

        return issues

    def assert_secure(self) -> None:
        """Enforce secure configuration in production.

        Delegates to picosentry._core.config.assert_secure with PicoShogun-specific
        custom checks (SSL cert, wildcard hosts/CORS).
        Override with PICOSHOGUN_SKIP_SECURE_ASSERT=1 (not recommended).
        """

        if _env("SKIP_SECURE_ASSERT", "") == "1":
            __import__("logging").getLogger("picoshogun.config").warning(
                "SECURITY ASSERT SKIPPED: PICOSHOGUN_SKIP_SECURE_ASSERT=1 is set. This bypasses startup security checks."
            )
            return

        cors_origin_str = ",".join(self.api.cors_origins) if self.api.cors_origins else ""
        custom_checks: list[SecureBootCheck] = [
            _SslCertCheck(self),
            _WildcardHostsCheck(self),
        ]
        _core_assert_secure(
            checks=custom_checks,
            secret_key=self.security.secret_key,
            bind_host=self.api.host,
            cors_origin=cors_origin_str,
            debug=self.debug,
            env=self.env,
        )

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from environment variables.

        Composes sub-configs via their own from_env() classmethods.
        """
        return cls(
            env=_env("ENV", "development"),
            debug=_env_bool("DEBUG", "false"),
            database=DatabaseConfig.from_env(),
            api=APIConfig.from_env(),
            security=SecurityConfig.from_env(),
            logging=LoggingConfig(),
            alerts=AlertConfig.from_env(),
            orchestrator=OrchestratorConfig.from_env(),
        )

    @classmethod
    def from_file(cls, path: Path) -> "Settings":
        """Load settings from JSON file.

        Only known fields are accepted — unknown keys are ignored to prevent
        injection of arbitrary attributes. Nested dataclass fields are
        constructed from their dicts. Config files should be stored outside
        any user-writable path.
        """
        import logging
        from dataclasses import fields as dc_fields
        logger = logging.getLogger("picoshogun.config")
        with open(path) as f:
            data = json.load(f)

        # Resolve type hints (handles forward refs and string annotations)
        known_hints = get_type_hints(cls)
        known_field_names = {f.name for f in dc_fields(cls)}

        # Filter to only known fields to prevent attribute injection
        unknown = set(data.keys()) - known_field_names
        if unknown:
            logger.warning("Ignoring unknown config fields in %s: %s", path, unknown)
        data = {k: v for k, v in data.items() if k in known_field_names}

        # Convert nested dicts to their dataclass types
        for field_name, field_type in known_hints.items():
            if field_name in data and isinstance(data[field_name], dict):
                if hasattr(field_type, "__dataclass_fields__"):
                    data[field_name] = field_type(**data[field_name])

        return cls(**data)

    def to_file(self, path: Path):
        """Save settings to JSON file."""
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2, default=str)



# Global settings instance
settings = Settings()
