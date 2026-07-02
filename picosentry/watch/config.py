from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from picosentry._core.config import SecureBootCheck, SecurityViolation
from picosentry._core.config import assert_secure as _core_assert_secure

DEFAULT_RULES_DIR = Path(__file__).parent / "rules"
DEFAULT_THRESHOLD_BLOCK = 0.7
DEFAULT_THRESHOLD_WARN = 0.4
DEFAULT_CLASSIFIER_ENABLED = True
DEFAULT_CLASSIFIER_BLEND_FACTOR = 1.0
DEFAULT_MAX_PROMPT_SIZE = 1_000_000  # 1MB
DEFAULT_MAX_OUTPUT_SIZE = 1_000_000  # 1MB
DEFAULT_MAX_JSON_SCHEMA_NODES = 1_000
DEFAULT_MAX_JSON_SCHEMA_DEPTH = 32
DEFAULT_AUDIT_RETENTION_DAYS = 30
DEFAULT_FAIL_CLOSED = False
DEFAULT_HOST = "127.0.0.1"
DEFAULT_ADMIN_HOST = "127.0.0.1"
DEFAULT_PORT = 8766
DEFAULT_ADMIN_PORT = 9091
DEFAULT_CORPUS_VERSION = "2026.05.1"
DEFAULT_RATE_LIMIT = 100  # requests per minute per IP
DEFAULT_RATE_LIMIT_WINDOW = 60  # seconds

CONFIG_SEARCH_PATHS = [
    Path("picowatch.toml"),
    Path.home() / ".config" / "picowatch" / "picowatch.toml",
    Path("/etc/picowatch/picowatch.toml"),
]


def _find_config_file() -> Path | None:
    for path in CONFIG_SEARCH_PATHS:
        if path.exists():
            return path
    return None


def _load_toml_config(path: Path) -> dict[str, Any]:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return {}

    try:
        with path.open("rb") as f:
            data: dict[str, Any] = tomllib.load(f)
            return data
    except Exception:
        return {}


@dataclass
class PromptGuardConfig:  # rationale: L5 prompt guard config, extracted from PicoWatchConfig for injection (PR-02)
    rules_dir: Path = field(default_factory=lambda: DEFAULT_RULES_DIR)
    threshold_block: float = DEFAULT_THRESHOLD_BLOCK
    threshold_warn: float = DEFAULT_THRESHOLD_WARN
    classifier_enabled: bool = DEFAULT_CLASSIFIER_ENABLED
    classifier_blend_factor: float = DEFAULT_CLASSIFIER_BLEND_FACTOR
    max_prompt_size: int = DEFAULT_MAX_PROMPT_SIZE
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE
    corpus_version: str = DEFAULT_CORPUS_VERSION
    fail_closed: bool = DEFAULT_FAIL_CLOSED


@dataclass
class OutputGuardConfig:  # rationale: L6 output guard config, extracted from PicoWatchConfig (PR-02)
    schema_dir: Path | None = None
    max_json_schema_nodes: int = DEFAULT_MAX_JSON_SCHEMA_NODES
    max_json_schema_depth: int = DEFAULT_MAX_JSON_SCHEMA_DEPTH


@dataclass
class TelemetryConfig:
    otel_endpoint: str | None = None
    audit_retention_days: int = DEFAULT_AUDIT_RETENTION_DAYS


@dataclass
class ServerConfig:
    host: str = DEFAULT_HOST
    admin_host: str = DEFAULT_ADMIN_HOST
    port: int = DEFAULT_PORT
    admin_port: int = DEFAULT_ADMIN_PORT
    api_key: str | None = None
    admin_auth_enabled: bool = True
    enable_docs: bool = False
    rate_limit: int = DEFAULT_RATE_LIMIT
    rate_limit_window: int = DEFAULT_RATE_LIMIT_WINDOW


@dataclass
class PicoWatchConfig:  # rationale: composed config with injectable sub-configs for testing (PR-02)
    prompt_guard: PromptGuardConfig = field(default_factory=PromptGuardConfig)
    output_guard: OutputGuardConfig = field(default_factory=OutputGuardConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    server: ServerConfig = field(default_factory=ServerConfig)

    verify_determinism: bool = False
    verbose: bool = False

    @property
    def rules_dir(self) -> Path:
        return self.prompt_guard.rules_dir

    @rules_dir.setter
    def rules_dir(self, value: Path) -> None:
        self.prompt_guard.rules_dir = value

    @property
    def threshold_block(self) -> float:
        return self.prompt_guard.threshold_block

    @threshold_block.setter
    def threshold_block(self, value: float) -> None:
        self.prompt_guard.threshold_block = value

    @property
    def threshold_warn(self) -> float:
        return self.prompt_guard.threshold_warn

    @threshold_warn.setter
    def threshold_warn(self, value: float) -> None:
        self.prompt_guard.threshold_warn = value

    @property
    def classifier_enabled(self) -> bool:
        return self.prompt_guard.classifier_enabled

    @classifier_enabled.setter
    def classifier_enabled(self, value: bool) -> None:
        self.prompt_guard.classifier_enabled = value

    @property
    def classifier_blend_factor(self) -> float:
        return self.prompt_guard.classifier_blend_factor

    @classifier_blend_factor.setter
    def classifier_blend_factor(self, value: float) -> None:
        self.prompt_guard.classifier_blend_factor = value

    @property
    def max_prompt_size(self) -> int:
        return self.prompt_guard.max_prompt_size

    @max_prompt_size.setter
    def max_prompt_size(self, value: int) -> None:
        self.prompt_guard.max_prompt_size = value

    @property
    def max_output_size(self) -> int:
        return self.prompt_guard.max_output_size

    @max_output_size.setter
    def max_output_size(self, value: int) -> None:
        self.prompt_guard.max_output_size = value

    @property
    def corpus_version(self) -> str:
        return self.prompt_guard.corpus_version

    @corpus_version.setter
    def corpus_version(self, value: str) -> None:
        self.prompt_guard.corpus_version = value

    @property
    def fail_closed(self) -> bool:
        return self.prompt_guard.fail_closed

    @fail_closed.setter
    def fail_closed(self, value: bool) -> None:
        self.prompt_guard.fail_closed = value

    @property
    def schema_dir(self) -> Path | None:
        return self.output_guard.schema_dir

    @schema_dir.setter
    def schema_dir(self, value: Path | None) -> None:
        self.output_guard.schema_dir = value

    @property
    def max_json_schema_nodes(self) -> int:
        return self.output_guard.max_json_schema_nodes

    @max_json_schema_nodes.setter
    def max_json_schema_nodes(self, value: int) -> None:
        self.output_guard.max_json_schema_nodes = value

    @property
    def max_json_schema_depth(self) -> int:
        return self.output_guard.max_json_schema_depth

    @max_json_schema_depth.setter
    def max_json_schema_depth(self, value: int) -> None:
        self.output_guard.max_json_schema_depth = value

    @property
    def otel_endpoint(self) -> str | None:
        return self.telemetry.otel_endpoint

    @otel_endpoint.setter
    def otel_endpoint(self, value: str | None) -> None:
        self.telemetry.otel_endpoint = value

    @property
    def audit_retention_days(self) -> int:
        return self.telemetry.audit_retention_days

    @audit_retention_days.setter
    def audit_retention_days(self, value: int) -> None:
        self.telemetry.audit_retention_days = value

    @property
    def host(self) -> str:
        return self.server.host

    @host.setter
    def host(self, value: str) -> None:
        self.server.host = value

    @property
    def admin_host(self) -> str:
        return self.server.admin_host

    @admin_host.setter
    def admin_host(self, value: str) -> None:
        self.server.admin_host = value

    @property
    def port(self) -> int:
        return self.server.port

    @port.setter
    def port(self, value: int) -> None:
        self.server.port = value

    @property
    def admin_port(self) -> int:
        return self.server.admin_port

    @admin_port.setter
    def admin_port(self, value: int) -> None:
        self.server.admin_port = value

    @property
    def api_key(self) -> str | None:
        return self.server.api_key

    @api_key.setter
    def api_key(self, value: str | None) -> None:
        self.server.api_key = value

    @property
    def admin_auth_enabled(self) -> bool:
        return self.server.admin_auth_enabled

    @admin_auth_enabled.setter
    def admin_auth_enabled(self, value: bool) -> None:
        self.server.admin_auth_enabled = value

    @property
    def enable_docs(self) -> bool:
        return self.server.enable_docs

    @enable_docs.setter
    def enable_docs(self, value: bool) -> None:
        self.server.enable_docs = value

    @property
    def rate_limit(self) -> int:
        return self.server.rate_limit

    @rate_limit.setter
    def rate_limit(self, value: int) -> None:
        self.server.rate_limit = value

    @property
    def rate_limit_window(self) -> int:
        return self.server.rate_limit_window

    @rate_limit_window.setter
    def rate_limit_window(self, value: int) -> None:
        self.server.rate_limit_window = value

    def assert_secure(self) -> None:
        import os as _os

        if _os.environ.get("PICOWATCH_SKIP_SECURE_ASSERT") == "1":
            import logging as _logging

            _logging.getLogger("picowatch.config").warning(
                "SECURITY ASSERT SKIPPED: PICOWATCH_SKIP_SECURE_ASSERT=1 is set. This bypasses startup security checks."
            )
            return

        custom_checks: list[SecureBootCheck] = [_ApiKeyLengthCheck(self), _BindWithoutAuthCheck(self)]
        _core_assert_secure(
            checks=custom_checks,
            secret_key=self.api_key or "",
            bind_host=self.host,
            cors_origin="",
            debug=False,
            env=_os.environ.get("PICOWATCH_ENV", "development"),
        )

    def validate_secure(self) -> list[str]:
        issues = []

        if self.api_key and len(self.api_key) < 32:
            issues.append("SECURITY: API key is shorter than 32 characters — use a strong random key")

        if self.host == "0.0.0.0" and self.api_key:
            issues.append(
                "CONFIG: Binding to 0.0.0.0 with API key set — consider restricting to 127.0.0.1 "
                "or using a reverse proxy"
            )

        if self.host == "0.0.0.0" and not self.api_key:
            issues.append(
                "SECURITY: Binding to 0.0.0.0 without API key — "
                "write endpoints are publicly accessible. Set PICOWATCH_API_KEY or bind to 127.0.0.1"
            )

        if not self.api_key:
            issues.append(
                "CONFIG: No PICOWATCH_API_KEY set — write endpoints are unprotected. "
                "Set PICOWATCH_API_KEY before production deployment"
            )

        return issues

    @classmethod
    def from_env(cls, config_path: Path | None = None) -> PicoWatchConfig:

        file_config: dict[str, object] = {}
        config_file_path = config_path
        if config_path and config_path.exists():
            file_config = _load_toml_config(config_path)
        else:
            discovered = _find_config_file()
            if discovered:
                file_config = _load_toml_config(discovered)
                config_file_path = discovered

        if config_file_path:
            check_config_permissions()

        picowatch_conf: dict[str, Any] = file_config.get("picowatch", file_config)  # type: ignore[assignment]

        def _env_or_file(key: str, env_var: str, default: Any, cast: type = str) -> Any:
            def _cast(value: Any) -> Any:
                if cast is bool and isinstance(value, str):
                    return value.strip().lower() not in {"0", "false", "no", "off", ""}
                return cast(value)

            val = os.environ.get(env_var)
            if val is not None:
                return _cast(val)
            file_val = picowatch_conf.get(key)
            if file_val is not None:
                return _cast(file_val) if not isinstance(file_val, cast) else file_val
            return default

        rules_dir_str = os.environ.get("PICOWATCH_RULES_DIR") or picowatch_conf.get("rules_dir")
        schema_dir_str = os.environ.get("PICOWATCH_SCHEMA_DIR") or picowatch_conf.get("schema_dir")

        config = cls(
            prompt_guard=PromptGuardConfig(
                rules_dir=Path(rules_dir_str) if rules_dir_str else DEFAULT_RULES_DIR,
                threshold_block=_env_or_file(
                    "threshold_block",
                    "PICOWATCH_THRESHOLD_BLOCK",
                    DEFAULT_THRESHOLD_BLOCK,
                    float,
                ),
                threshold_warn=_env_or_file(
                    "threshold_warn", "PICOWATCH_THRESHOLD_WARN", DEFAULT_THRESHOLD_WARN, float
                ),
                classifier_enabled=_env_or_file(
                    "classifier_enabled",
                    "PICOWATCH_CLASSIFIER_ENABLED",
                    DEFAULT_CLASSIFIER_ENABLED,
                    bool,
                ),
                classifier_blend_factor=_env_or_file(
                    "classifier_blend_factor",
                    "PICOWATCH_CLASSIFIER_BLEND_FACTOR",
                    DEFAULT_CLASSIFIER_BLEND_FACTOR,
                    float,
                ),
                max_prompt_size=_env_or_file(
                    "max_prompt_size", "PICOWATCH_MAX_PROMPT_SIZE", DEFAULT_MAX_PROMPT_SIZE, int
                ),
                max_output_size=_env_or_file(
                    "max_output_size", "PICOWATCH_MAX_OUTPUT_SIZE", DEFAULT_MAX_OUTPUT_SIZE, int
                ),
                corpus_version=os.environ.get("PICOWATCH_CORPUS_VERSION")
                or picowatch_conf.get("corpus_version", DEFAULT_CORPUS_VERSION),
                fail_closed=_env_or_file("fail_closed", "PICOSENTRY_WATCH_FAIL_CLOSED", DEFAULT_FAIL_CLOSED, bool),
            ),
            output_guard=OutputGuardConfig(
                schema_dir=Path(schema_dir_str) if schema_dir_str else None,
                max_json_schema_nodes=_env_or_file(
                    "max_json_schema_nodes",
                    "PICOWATCH_MAX_JSON_SCHEMA_NODES",
                    DEFAULT_MAX_JSON_SCHEMA_NODES,
                    int,
                ),
                max_json_schema_depth=_env_or_file(
                    "max_json_schema_depth",
                    "PICOWATCH_MAX_JSON_SCHEMA_DEPTH",
                    DEFAULT_MAX_JSON_SCHEMA_DEPTH,
                    int,
                ),
            ),
            telemetry=TelemetryConfig(
                otel_endpoint=os.environ.get("PICOWATCH_OTEL_ENDPOINT") or picowatch_conf.get("otel_endpoint"),
                audit_retention_days=_env_or_file(
                    "audit_retention_days",
                    "PICOWATCH_AUDIT_RETENTION_DAYS",
                    DEFAULT_AUDIT_RETENTION_DAYS,
                    int,
                ),
            ),
            server=ServerConfig(
                host=os.environ.get("PICOWATCH_HOST") or picowatch_conf.get("host", DEFAULT_HOST),
                admin_host=os.environ.get("PICOWATCH_ADMIN_HOST")
                or picowatch_conf.get("admin_host", DEFAULT_ADMIN_HOST),
                port=_env_or_file("port", "PICOWATCH_PORT", DEFAULT_PORT, int),
                admin_port=_env_or_file("admin_port", "PICOWATCH_ADMIN_PORT", DEFAULT_ADMIN_PORT, int),
                api_key=os.environ.get("PICOWATCH_API_KEY") or picowatch_conf.get("api_key"),
                admin_auth_enabled=_env_or_file("admin_auth_enabled", "PICOWATCH_ADMIN_AUTH_ENABLED", True, bool),
                enable_docs=_env_or_file("enable_docs", "PICOWATCH_ENABLE_DOCS", False, bool),
                rate_limit=_env_or_file("rate_limit", "PICOWATCH_RATE_LIMIT", DEFAULT_RATE_LIMIT, int),
                rate_limit_window=_env_or_file(
                    "rate_limit_window",
                    "PICOWATCH_RATE_LIMIT_WINDOW",
                    DEFAULT_RATE_LIMIT_WINDOW,
                    int,
                ),
            ),
        )

        _validate_env_ranges(config)

        return config


class _ApiKeyLengthCheck:
    def __init__(self, config: PicoWatchConfig) -> None:
        self._config = config

    def check(self) -> SecurityViolation | None:
        if self._config.api_key and len(self._config.api_key) < 32:
            return SecurityViolation(
                check="api_key_length",
                message="API key is shorter than 32 characters — use a strong random key",
                severity="ERROR",
            )
        return None


class _BindWithoutAuthCheck:
    def __init__(self, config: PicoWatchConfig) -> None:
        self._config = config

    def check(self) -> SecurityViolation | None:
        if self._config.host == "0.0.0.0" and not self._config.api_key:
            return SecurityViolation(
                check="bind_without_auth",
                message="Binding to 0.0.0.0 without API key — write endpoints are publicly accessible",
                severity="ERROR",
            )
        return None


def _validate_env_ranges(config: PicoWatchConfig) -> None:
    import logging as _logging

    _logger = _logging.getLogger("picowatch.config")

    if not (0.0 <= config.threshold_block <= 1.0):
        _logger.warning("PICOWATCH_THRESHOLD_BLOCK=%s out of range [0,1]; clamped", config.threshold_block)
        config.threshold_block = max(0.0, min(1.0, config.threshold_block))

    if not (0.0 <= config.threshold_warn <= config.threshold_block):
        _logger.warning(
            "PICOWATCH_THRESHOLD_WARN=%s invalid (must be <= threshold_block=%s)",
            config.threshold_warn,
            config.threshold_block,
        )
        config.threshold_warn = min(config.threshold_warn, config.threshold_block)

    if config.port < 1 or config.port > 65535:
        _logger.warning("PICOWATCH_PORT=%s out of range [1,65535]; using default %d", config.port, DEFAULT_PORT)
        config.port = DEFAULT_PORT

    if config.admin_port < 1 or config.admin_port > 65535:
        _logger.warning(
            "PICOWATCH_ADMIN_PORT=%s out of range [1,65535]; using default %d", config.admin_port, DEFAULT_ADMIN_PORT
        )
        config.admin_port = DEFAULT_ADMIN_PORT

    if config.rate_limit < 1:
        _logger.warning("PICOWATCH_RATE_LIMIT=%s must be >=1; using default %d", config.rate_limit, DEFAULT_RATE_LIMIT)
        config.rate_limit = DEFAULT_RATE_LIMIT

    if config.audit_retention_days < 0:
        _logger.warning(
            "PICOWATCH_AUDIT_RETENTION_DAYS=%s must be >=0; using default %d",
            config.audit_retention_days,
            DEFAULT_AUDIT_RETENTION_DAYS,
        )
        config.audit_retention_days = DEFAULT_AUDIT_RETENTION_DAYS

    if config.api_key and len(config.api_key) < 32:
        _logger.warning("PICOWATCH_API_KEY is shorter than 32 characters — recommend a strong random key")

    if config.max_output_size < 1:
        _logger.warning(
            "PICOWATCH_MAX_OUTPUT_SIZE=%s must be >=1; using default %d",
            config.max_output_size,
            DEFAULT_MAX_OUTPUT_SIZE,
        )
        config.max_output_size = DEFAULT_MAX_OUTPUT_SIZE

    if config.max_json_schema_nodes < 1:
        _logger.warning(
            "PICOWATCH_MAX_JSON_SCHEMA_NODES=%s must be >=1; using default %d",
            config.max_json_schema_nodes,
            DEFAULT_MAX_JSON_SCHEMA_NODES,
        )
        config.max_json_schema_nodes = DEFAULT_MAX_JSON_SCHEMA_NODES

    if config.max_json_schema_depth < 1:
        _logger.warning(
            "PICOWATCH_MAX_JSON_SCHEMA_DEPTH=%s must be >=1; using default %d",
            config.max_json_schema_depth,
            DEFAULT_MAX_JSON_SCHEMA_DEPTH,
        )
        config.max_json_schema_depth = DEFAULT_MAX_JSON_SCHEMA_DEPTH


def check_config_permissions() -> list[str]:
    import logging
    import stat

    logger = logging.getLogger("picowatch.config")
    warnings: list[str] = []

    for path in CONFIG_SEARCH_PATHS:
        if path.exists():
            mode = path.stat().st_mode
            if mode & stat.S_IRGRP:
                msg = (
                    f"Config file {path} is group-readable (mode {oct(stat.S_IMODE(mode))}). Consider: chmod 640 {path}"
                )
                warnings.append(msg)
                logger.warning(msg)
            if mode & stat.S_IROTH:
                msg = (
                    f"Config file {path} is world-readable (mode {oct(stat.S_IMODE(mode))}). Consider: chmod 600 {path}"
                )
                warnings.append(msg)
                logger.warning(msg)

            try:
                content = path.read_text(encoding="utf-8")

                lines = [line.split("#")[0].strip() for line in content.splitlines()]
                has_real_api_key = any(
                    line.startswith("api_key") and "=" in line and line.split("=", 1)[1].strip()
                    for line in lines
                    if line
                )
                if has_real_api_key and (mode & stat.S_IROTH):
                    msg = f"SECURITY: api_key found in world-readable config {path}. Consider: chmod 600 {path}"
                    warnings.append(msg)
                    logger.error(msg)
            except Exception:
                pass

    return warnings
