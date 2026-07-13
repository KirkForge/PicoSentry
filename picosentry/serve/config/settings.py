import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import get_type_hints

from picosentry._core.config import SecureBootCheck, SecurityViolation
from picosentry._core.config import assert_secure as _core_assert_secure

BASE_DIR = Path(__file__).parent.parent


def _env(key: str, default: str = "") -> str:
    val = os.environ.get(f"PICOSHOGUN_{key}")
    if val is not None:
        return val
    return os.environ.get(f"SHOGUN_{key}", default)


def _env_bool(key: str, default: str = "false") -> bool:
    return _env(key, default).lower() == "true"


def _parse_cors_origins() -> list[str]:
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
    # WAL | DELETE | TRUNCATE | PERSIST | MEMORY
    journal_mode: str = field(default_factory=lambda: _env("JOURNAL_MODE", "WAL"))
    # OFF | NORMAL | FULL
    synchronous: str = field(default_factory=lambda: _env("SYNCHRONOUS", "NORMAL"))
    wal_checkpoint_threshold: int = 1000  # pages before auto-checkpoint

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        return cls()  # defaults already read from env via field default_factory


@dataclass
class APIConfig:
    host: str = field(default_factory=lambda: _env("API_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("API_PORT", "8765")))
    workers: int = field(default_factory=lambda: int(_env("API_WORKERS", "1")))
    reload: bool = False
    cors_origins: list[str] = field(default_factory=_parse_cors_origins)
    api_prefix: str = "/api/v1"
    docs_url: str = field(default_factory=lambda: _env("DOCS_URL", "/docs"))
    redoc_url: str = field(default_factory=lambda: _env("REDOC_URL", "/redoc"))

    @classmethod
    def from_env(cls) -> "APIConfig":
        return cls()  # defaults already read from env via field default_factory


@dataclass
class SecurityConfig:
    # Default to an empty secret key.  An unset key is caught by the
    # denylist in assert_secure() in every environment, so a deployment
    # cannot silently start signing JWTs with a well-known placeholder.
    # For local development without a real key, set ALLOW_INSECURE_SECRET=true.
    secret_key: str = field(default_factory=lambda: _env("SECRET_KEY", ""))

    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    password_hash_rounds: int = 12
    allowed_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    rate_limit: str = "100/minute"
    ddos_shield_enabled: bool = field(default_factory=lambda: _env_bool("DDOS_SHIELD", "true"))
    allow_registration: bool = field(default_factory=lambda: _env_bool("ALLOW_REGISTRATION", "false"))
    ssl_cert_path: Path | None = None
    ssl_key_path: Path | None = None
    # Rate-limit backend: "memory" (default), "sqlite" (per-node persistence),
    # or "redis" (distributed, shared across serve replicas).
    rate_limit_backend: str = field(default_factory=lambda: _env("RATE_LIMIT_BACKEND", "memory"))
    # Redis URL for the distributed rate-limit backend.  Only used when
    # rate_limit_backend=redis.  Falls back to the daemon Redis URL for
    # operators who already configure PICODOME_REDIS_URL.
    redis_url: str = field(
        default_factory=lambda: _env(
            "REDIS_URL",
            os.environ.get("PICODOME_REDIS_URL", "redis://localhost:6379/0"),
        )
    )

    # Workspace root for POST /scans.  The serve mode used to accept any
    # server-local path as a scan target, which in a multi-tenant setup
    # becomes filesystem probing + data disclosure through findings.  We
    # now require scan targets to resolve inside this root.  ``None``
    # means /scans is disabled entirely — operators must opt in by
    # configuring the path.  Set PICOSHOGUN_SCANS_WORKSPACE_ROOT to
    # enable it.  Default is "unset" so a fresh deploy does NOT silently
    # accept arbitrary paths.
    scans_workspace_root: Path | None = field(
        default_factory=lambda: Path(p) if (p := _env("SCANS_WORKSPACE_ROOT", "").strip()) else None
    )

    @classmethod
    def from_env(cls) -> "SecurityConfig":
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
    email_to: list[str] = field(
        default_factory=lambda: [addr.strip() for addr in _env("EMAIL_TO", "").split(",") if addr.strip()]
    )
    cooldown_seconds: int = 300
    max_retries: int = 3

    @classmethod
    def from_env(cls) -> "AlertConfig":
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
        return cls()  # defaults already read from env via field default_factory


def _env_plugin_dirs() -> list[Path]:
    """Parse PICOSHOGUN_PLUGIN_DIR (comma-separated) into a list of Path."""
    raw = _env("PLUGIN_DIR", "").strip()
    if not raw:
        return []
    return [Path(p.strip()) for p in raw.split(",") if p.strip()]


@dataclass
class PluginsConfig:
    """User-supplied plugin directories. The bundled
    picosentry/serve/plugins/ is always scanned; this is for extras.
    """

    plugin_dirs: list[Path] = field(default_factory=_env_plugin_dirs)

    @classmethod
    def from_env(cls) -> "PluginsConfig":
        return cls()  # defaults already read from env via field default_factory


class _SslCertCheck:
    def __init__(self, settings: "Settings") -> None:
        self._settings = settings

    def check(self) -> SecurityViolation | None:
        if self._settings.is_production() and not self._settings.security.ssl_cert_path:
            return SecurityViolation(
                check="ssl_cert",
                message=(
                    "No SSL certificate configured in production — "
                    "set PICOSHOGUN_SSL_CERT_PATH or configure TLS termination"
                ),
                severity="ERROR",
            )
        return None


class _WildcardHostsCheck:
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


class _SignedPluginsCheck:
    def __init__(self, settings: "Settings") -> None:
        self._settings = settings

    def check(self) -> SecurityViolation | None:
        if self._settings.is_production() and os.environ.get("PICOSHOGUN_REQUIRE_SIGNED_PLUGINS", "").lower() not in (
            "1",
            "true",
            "yes",
        ):
            return SecurityViolation(
                check="signed_plugins",
                message="Unsigned plugins allowed in production — set PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1",
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
    plugins: PluginsConfig = field(default_factory=PluginsConfig)

    def is_production(self) -> bool:
        return self.env == "production"

    def validate(self) -> list[str]:
        issues = []

        # Secret-key check is environment-agnostic: a missing or placeholder
        # key must be flagged regardless of PICOSHOGUN_ENV.  assert_secure()
        # is the hard gate that blocks startup; validate() surfaces it early.
        if not self.security.secret_key or self.security.secret_key == "change-me-in-production":
            issues.append(
                "SECURITY: Default secret key is not set or uses a placeholder — "
                "set PICOSHOGUN_SECRET_KEY before deployment"
            )

        if self.is_production():
            if not self.security.ssl_cert_path:
                issues.append(
                    "SECURITY: No SSL certificate configured "
                    "(set PICOSHOGUN_SSL_CERT_PATH or configure TLS termination upstream)"
                )
            if self.debug:
                issues.append("SECURITY: Debug mode enabled in production")
            if "*" in self.security.allowed_hosts:
                issues.append("SECURITY: Wildcard allowed hosts in production")
            if "*" in self.api.cors_origins and self.api.cors_origins == ["*"]:
                issues.append("SECURITY: Wildcard CORS origin in production — specify explicit origins")
            if os.environ.get("PICOSHOGUN_REQUIRE_SIGNED_PLUGINS", "").lower() not in ("1", "true", "yes"):
                issues.append(
                    "SECURITY: Unsigned plugins allowed in production — set PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1"
                )

        if not self.is_production() and self.api.host == "0.0.0.0":
            issues.append("CONFIG: Binding to all interfaces — use 127.0.0.1 for local dev or set SHOGUN_API_HOST")

        return issues

    def assert_secure(self) -> None:

        if _env("SKIP_SECURE_ASSERT", "") == "1":
            __import__("logging").getLogger("picoshogun.config").warning(
                "SECURITY ASSERT SKIPPED: PICOSHOGUN_SKIP_SECURE_ASSERT=1 is set. "
                "This bypasses startup security checks."
            )
            return

        cors_origin_str = ",".join(self.api.cors_origins) if self.api.cors_origins else ""
        custom_checks: list[SecureBootCheck] = [
            _SslCertCheck(self),
            _WildcardHostsCheck(self),
            _SignedPluginsCheck(self),
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
        return cls(
            env=_env("ENV", "development"),
            debug=_env_bool("DEBUG", "false"),
            database=DatabaseConfig.from_env(),
            api=APIConfig.from_env(),
            security=SecurityConfig.from_env(),
            logging=LoggingConfig(),
            alerts=AlertConfig.from_env(),
            orchestrator=OrchestratorConfig.from_env(),
            plugins=PluginsConfig.from_env(),
        )

    @classmethod
    def from_file(cls, path: Path) -> "Settings":
        import logging
        from dataclasses import fields as dc_fields

        logger = logging.getLogger("picoshogun.config")
        with path.open() as f:
            data = json.load(f)

        known_hints = get_type_hints(cls)
        known_field_names = {f.name for f in dc_fields(cls)}

        unknown = set(data.keys()) - known_field_names
        if unknown:
            logger.warning("Ignoring unknown config fields in %s: %s", path, unknown)
        data = {k: v for k, v in data.items() if k in known_field_names}

        for field_name, field_type in known_hints.items():
            if (
                field_name in data
                and isinstance(data[field_name], dict)
                and hasattr(field_type, "__dataclass_fields__")
            ):
                data[field_name] = field_type(**data[field_name])

        return cls(**data)

    def to_file(self, path: Path):
        with path.open("w") as f:
            json.dump(self.__dict__, f, indent=2, default=str)


settings = Settings()
