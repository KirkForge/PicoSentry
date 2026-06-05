"""
PicoDome configuration — .picodome.yml file loader.

Config file is optional. CLI flags override config file values.
Search order: target_dir/.picodome.yml → target_dir/.picodome.yaml

Deterministic: config file is part of scan inputs. Same config = same output.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from picosentry._core.config import SecureBootCheck, SecurityViolation, assert_secure as _core_assert_secure

logger = logging.getLogger("picodome.config")

# Supported config file names (in order of precedence)
CONFIG_NAMES = [".picodome.yml", ".picodome.yaml"]

# Current config schema version
CONFIG_VERSION = 1

# Known config keys (whitelist). Unknown keys are rejected with a warning.
KNOWN_KEYS = frozenset(
    {
        "version",
        "format",
        "no_color",
        "exit_code",
        "fail_on",
        "baseline",
        "severity_overrides",
        "token_budget",
        "timeout",
        "policy",
        "rules",
        "log_format",
        "deterministic_output",
        "store_backend",
        "sqlite_path",
        "cors_origins",
    }
)

# Valid values for enum-like config fields
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_FORMATS = frozenset({"json", "sarif", "table", "ml-context", "github", "cyclonedx"})
VALID_LOG_FORMATS = frozenset({"text", "json"})


class PicoDomeConfig:
    """
    Configuration loaded from .picodome.yml or CLI flags.

    Config file values are defaults; CLI flags override them.

    Deterministic: same config file + same CLI flags = same effective config.
    """

    def __init__(self) -> None:
        # Output settings
        self.format: str = "table"
        self.no_color: bool = False
        self.exit_code: bool = False
        self.deterministic_output: bool = False

        # Failure thresholds
        self.fail_on: str | None = None  # None means no threshold

        # Baseline
        self.baseline: str | None = None

        # Severity overrides (rule_id → severity)
        self.severity_overrides: dict[str, str] = {}

        # Token budget for LLM context output
        self.token_budget: int = 4096

        # Timeout in seconds for sandbox execution
        self.timeout: float = 30.0

        # Policy file path
        self.policy: str | None = None

        # Specific rules to run (None = all)
        self.rules: list[str] | None = None

        # Logging
        self.log_format: str = "text"

        # Storage backend: "sqlite" (default) or "json"
        self.store_backend: str = "sqlite"
        self.sqlite_path: str | None = None

        # CORS origins (comma-separated, or "*" for all)
        self.cors_origins: str = ""

    def merge_from_cli(self, args: Any) -> PicoDomeConfig:
        """Merge CLI args into this config. CLI flags override config file values.

        Uses attribute presence detection to determine if a CLI flag was
        explicitly set. Only overrides values where the user passed a flag.

        Args:
            args: argparse Namespace with CLI arguments.

        Returns:
            New PicoDomeConfig with merged values.
        """
        merged = PicoDomeConfig()

        # Copy config file values first
        merged.format = self.format
        merged.no_color = self.no_color
        merged.exit_code = self.exit_code
        merged.deterministic_output = self.deterministic_output
        merged.fail_on = self.fail_on
        merged.baseline = self.baseline
        merged.severity_overrides = dict(self.severity_overrides)
        merged.token_budget = self.token_budget
        merged.timeout = self.timeout
        merged.policy = self.policy
        merged.rules = list(self.rules) if self.rules else None
        merged.log_format = self.log_format
        merged.store_backend = self.store_backend
        merged.sqlite_path = self.sqlite_path
        merged.cors_origins = self.cors_origins

        # Override with CLI args — only if explicitly set
        if not hasattr(args, "format"):
            return merged

        if getattr(args, "format", None) is not None:
            merged.format = args.format
        if getattr(args, "no_color", False):
            merged.no_color = True
        if getattr(args, "exit_code", False):
            merged.exit_code = True
        if getattr(args, "fail_on", None) is not None:
            merged.fail_on = args.fail_on
            merged.exit_code = True  # fail_on implies exit_code
        if getattr(args, "baseline", None) is not None:
            merged.baseline = args.baseline
        if getattr(args, "deterministic_output", False):
            merged.deterministic_output = True
        if getattr(args, "token_budget", None) is not None:
            merged.token_budget = args.token_budget
        if getattr(args, "timeout", None) is not None:
            merged.timeout = args.timeout
        if getattr(args, "policy", None) is not None:
            merged.policy = str(args.policy)
        if getattr(args, "rules", None) is not None:
            merged.rules = args.rules
        if getattr(args, "log_format", None) is not None and args.log_format != "text":
            merged.log_format = args.log_format

        return merged

    def apply_severity_overrides(self, findings: list) -> list:
        """Apply severity overrides from config. Returns a NEW list of Findings.

        Does NOT mutate the original Findings (they are frozen).
        Each override creates a new Finding with the overridden severity.
        Unknown rule IDs are silently ignored.

        Deterministic: same config + same findings = same result.
        """
        if not self.severity_overrides:
            return findings

        from picosentry.sandbox.models import Finding, Severity

        overridden = []
        for f in findings:
            if f.rule_id in self.severity_overrides:
                new_sev = self.severity_overrides[f.rule_id]
                try:
                    sev_enum = Severity(new_sev.upper())
                    f = Finding(
                        rule_id=f.rule_id,
                        severity=sev_enum,
                        message=f.message,
                        location=f.location,
                        evidence=f.evidence,
                    )
                except ValueError:
                    logger.warning(
                        "Invalid severity override for %s: %s (expected CRITICAL/HIGH/MEDIUM/LOW/INFO)",
                        f.rule_id,
                        new_sev,
                    )
            overridden.append(f)
        return overridden

    def to_dict(self) -> dict[str, Any]:
        """Serialize config to dict for JSON output."""
        return {
            "format": self.format,
            "no_color": self.no_color,
            "exit_code": self.exit_code,
            "deterministic_output": self.deterministic_output,
            "fail_on": self.fail_on,
            "baseline": self.baseline,
            "severity_overrides": dict(self.severity_overrides),
            "token_budget": self.token_budget,
            "timeout": self.timeout,
            "policy": self.policy,
            "rules": self.rules,
            "log_format": self.log_format,
        }

    def assert_secure(self) -> None:
        """Enforce secure configuration in production.

        Delegates to picosentry._core.config.assert_secure with PicoDome-specific
        custom checks (mTLS cert presence in production).
        Override with PICODOME_SKIP_SECURE_ASSERT=1 (NOT recommended).
        """
        import os as _os

        if _os.environ.get("PICODOME_SKIP_SECURE_ASSERT") == "1":
            logger.warning(
                "SECURITY ASSERT SKIPPED: PICODOME_SKIP_SECURE_ASSERT=1 is set. This bypasses startup security checks."
            )
            return

        custom_checks: list[SecureBootCheck] = [_MtlsCertCheck(self)]
        _core_assert_secure(
            checks=custom_checks,
            secret_key="",
            bind_host="127.0.0.1",
            cors_origin=self.cors_origins,
            debug=False,
            env=_os.environ.get("PICODOME_ENV", "development"),
        )


class _MtlsCertCheck:
    """PicoDome-specific: mTLS cert must be present in production."""

    def __init__(self, config: PicoDomeConfig) -> None:
        self._config = config

    def check(self) -> SecurityViolation | None:
        import os as _os
        env = _os.environ.get("PICODOME_ENV", "development")
        if env in ("production", "staging"):
            mtls_cert = _os.environ.get("PICODOME_TLS_CERT", "")
            mtls_dev = _os.environ.get("PICODOME_TLS_DEV", "") == "1"
            if not mtls_cert and not mtls_dev:
                return SecurityViolation(
                    check="mtls_cert",
                    message="No mTLS certificate configured in production — set PICODOME_TLS_CERT or PICODOME_TLS_DEV=1 for dev certs",
                    severity="WARN",
                )
        return None


def _validate_config_keys(data: dict, config_path: Path) -> None:
    """Validate config keys against known keys and warn about unknown keys.

    Prevents silent config rot (e.g., typo in key name like 'severity_overides').
    """
    unknown = sorted(set(data.keys()) - KNOWN_KEYS)
    for key in unknown:
        logger.warning(
            "Unknown config key '%s' in %s — will be ignored. Did you mean one of: %s?",
            key,
            config_path,
            ", ".join(sorted(KNOWN_KEYS)),
        )


# ── Environment Variable Overrides ───────────────────────────────────

# Map of PICODOME_* env vars to config attribute names.
# Precedence: CLI args > env vars > config file > defaults

_ENV_TO_ATTR = {
    "PICODOME_FORMAT": "format",
    "PICODOME_NO_COLOR": "no_color",
    "PICODOME_EXIT_CODE": "exit_code",
    "PICODOME_FAIL_ON": "fail_on",
    "PICODOME_BASELINE": "baseline",
    "PICODOME_TOKEN_BUDGET": "token_budget",
    "PICODOME_TIMEOUT": "timeout",
    "PICODOME_POLICY": "policy",
    "PICODOME_LOG_FORMAT": "log_format",
    "PICODOME_DETERMINISTIC_OUTPUT": "deterministic_output",
}


def apply_env_overrides(config: PicoDomeConfig) -> PicoDomeConfig:
    """Apply PICODOME_* environment variable overrides to config.

    Boolean values: "true", "1", "yes" → True; "false", "0", "no" → False.
    Numeric values: parsed as float/int.
    String values: used as-is.

    Precedence: env vars override config file values.
    CLI flags (applied after this) override env vars.
    """
    # Attributes that accept string values
    _STRING_ATTRS = {"format", "fail_on", "baseline", "policy", "log_format", "store_backend", "sqlite_path", "cors_origins"}

    for env_name, attr_name in _ENV_TO_ATTR.items():
        env_val = os.environ.get(env_name)
        if env_val is None or env_val == "":
            continue

        lower = env_val.lower()
        if lower in ("true", "1", "yes"):
            setattr(config, attr_name, True)
        elif lower in ("false", "0", "no"):
            setattr(config, attr_name, False)
        elif attr_name in _STRING_ATTRS:
            setattr(config, attr_name, env_val)
        else:
            try:
                val = float(env_val)
                # Use int if no decimal part and attribute expects int
                if attr_name == "token_budget":
                    setattr(config, attr_name, int(val))
                else:
                    setattr(config, attr_name, val)
            except ValueError:
                logger.warning("Invalid value for %s: %s (expected number)", env_name, env_val)
                continue

    return config


def load_config(target_dir: Path) -> PicoDomeConfig:
    """Load configuration from target directory.

    Searches for .picodome.yml or .picodome.yaml in the target directory.
    Returns default config if no file found.
    Unknown keys are warned about but do not cause a hard error.

    Deterministic: same directory = same config (or default).
    """
    config = PicoDomeConfig()

    config_path = _find_config(target_dir)
    if config_path is None:
        return config

    logger.info("Loading config from %s", config_path)

    try:
        import yaml

        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except ImportError:
        # YAML not available — try JSON fallback
        try:
            import json

            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse config file %s: %s", config_path, e)
            return config
    except Exception as e:
        logger.warning("Failed to parse config file %s: %s", config_path, e)
        return config

    if not isinstance(data, dict):
        logger.warning("Config file %s is not a mapping, ignoring", config_path)
        return config

    # Validate against known keys
    _validate_config_keys(data, config_path)

    # Parse config fields
    if "version" in data and data["version"] != CONFIG_VERSION:
        logger.warning(
            "Config version %s != expected %s, some fields may be ignored",
            data["version"],
            CONFIG_VERSION,
        )

    if "format" in data:
        val = data["format"]
        if val not in VALID_FORMATS:
            logger.warning(
                "Invalid format %r in %s (expected: %s)",
                val,
                config_path,
                ", ".join(sorted(VALID_FORMATS)),
            )
        else:
            config.format = val

    if "no_color" in data:
        config.no_color = bool(data["no_color"])

    if "exit_code" in data:
        config.exit_code = bool(data["exit_code"])

    if "deterministic_output" in data:
        config.deterministic_output = bool(data["deterministic_output"])

    if "fail_on" in data:
        val = str(data["fail_on"]).lower()
        if val not in VALID_SEVERITIES:
            logger.warning(
                "Invalid fail_on %r in %s (expected: %s)",
                data["fail_on"],
                config_path,
                ", ".join(sorted(VALID_SEVERITIES)),
            )
        else:
            config.fail_on = val

    if "baseline" in data:
        baseline_path = data["baseline"]
        if not Path(baseline_path).is_absolute():
            baseline_path = str(config_path.parent / baseline_path)
        config.baseline = baseline_path

    if "severity_overrides" in data:
        try:
            config.severity_overrides = {str(k): str(v) for k, v in data["severity_overrides"].items()}
        except (AttributeError, TypeError, ValueError) as e:
            logger.warning("Invalid severity_overrides in %s: %s", config_path, e)

    if "token_budget" in data:
        try:
            config.token_budget = int(data["token_budget"])
        except (ValueError, TypeError) as e:
            logger.warning("Invalid token_budget %r in %s: %s", data["token_budget"], config_path, e)

    if "timeout" in data:
        try:
            config.timeout = float(data["timeout"])
        except (ValueError, TypeError) as e:
            logger.warning("Invalid timeout %r in %s: %s", data["timeout"], config_path, e)

    if "policy" in data:
        policy_path = data["policy"]
        if not Path(policy_path).is_absolute():
            policy_path = str(config_path.parent / policy_path)
        config.policy = policy_path

    if "rules" in data:
        if isinstance(data["rules"], list):
            config.rules = [str(r) for r in data["rules"]]
        else:
            logger.warning("rules in %s is not a list, ignoring", config_path)

    if "log_format" in data:
        val = data["log_format"]
        if val not in VALID_LOG_FORMATS:
            logger.warning(
                "Invalid log_format %r in %s (expected: %s)",
                val,
                config_path,
                ", ".join(sorted(VALID_LOG_FORMATS)),
            )
        else:
            config.log_format = val

    if "store_backend" in data:
        val = str(data["store_backend"])
        if val not in ("sqlite", "json"):
            logger.warning("Invalid store_backend %r in %s (expected: sqlite or json)", val, config_path)
        else:
            config.store_backend = val

    if "sqlite_path" in data:
        sqlite_path = data["sqlite_path"]
        if not Path(sqlite_path).is_absolute():
            sqlite_path = str(config_path.parent / sqlite_path)
        config.sqlite_path = sqlite_path

    if "cors_origins" in data:
        config.cors_origins = str(data["cors_origins"])

    # Apply environment variable overrides
    config = apply_env_overrides(config)

    return config


def _find_config(target_dir: Path) -> Path | None:
    """Search for config file in target directory.

    Returns first match in precedence order:
    .picodome.yml → .picodome.yaml
    """
    for name in CONFIG_NAMES:
        candidate = target_dir / name
        if candidate.is_file():
            return candidate
    return None
