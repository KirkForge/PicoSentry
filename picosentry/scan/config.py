"""
PicoSentry configuration — .picosentry.yml file loader.

Config file is optional. CLI flags override config file values.
Search order: target_dir/.picosentry.yml → target_dir/.picosentry.yaml
              → target_dir/picosentry.config.yml

Deterministic: config file is part of scan inputs. Same config = same output.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from picosentry._core.config import SecureBootCheck, SecurityViolation
from picosentry._core.config import assert_secure as _core_assert_secure

if TYPE_CHECKING:
    from picosentry.scan.policy import Policy

logger = logging.getLogger("picosentry.config")

# Supported config file names (in order of precedence)
CONFIG_NAMES = [".picosentry.yml", ".picosentry.yaml", "picosentry.config.yml"]

# Current config schema version
CONFIG_VERSION = 1

# Known config keys (whitelist). Unknown keys are rejected with a warning.
KNOWN_KEYS = frozenset(
    {
        "version",
        "format",
        "output",
        "rules",
        "corpus",
        "advisory_db",
        "no_color",
        "token_budget",
        "exit_code",
        "severity_threshold",
        "fail_on",
        "quiet",
        "summary",
        "deterministic_output",
        "baseline",
        "baseline_update",
        "sarif_file",
        "severity_overrides",
        "ignore_paths",
        "ignore_packages",
        "log_format",
        "policy",
        "daemon",
        "cache",
        "updates",
    }
)

# Valid values for enum-like config fields
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


_UNSET = object()


class PicoSentryConfig:
    """
    Configuration loaded from .picosentry.yml or CLI flags.

    Config file values are defaults; CLI flags override them.

    Deterministic: same config file + same CLI flags = same effective config.
    """

    def __init__(self) -> None:
        self.format: str = "table"
        self.output: str | None = None
        self.rules: list[str] | None = None  # None means "all rules"
        self.corpus: str | None = None
        self.advisory_db: str | None = None  # Path to advisory database directory
        self.no_color: bool = False
        self.token_budget: int = 4096
        self.exit_code: bool = False
        self.severity_threshold: str | None = None
        self.fail_on: str | None = None
        self.quiet: bool = False
        self.summary: bool = False
        self.baseline: str | None = None
        self.baseline_update: bool = False
        self.sarif_file: str = "sarif.json"
        self.deterministic_output: bool = False
        self.log_format: str = "text"
        # Config-file-only settings
        self.severity_overrides: dict[str, str] = {}  # rule_id → severity
        self.ignore_paths: list[str] = []  # glob patterns to skip
        self.ignore_packages: list[str] = []  # package names to skip
        # Policy fields (from .picosentry-policy.yml or inline)
        self.policy_file: str | None = None  # path to policy file
        self.allow_licenses: list[str] = []  # SPDX license allow-list
        self.deny_licenses: list[str] = []  # SPDX license deny-list
        self.deny_packages: list[str] = []  # blocked packages
        self.waivers: list[dict] = []  # policy waivers
        self.fail_on_severity: str = "high"  # minimum severity to fail CI
        # Daemon settings (from daemon: section in config or env vars)
        self.daemon: dict = {}
        # Cache governance settings
        self.cache_max_entries: int = 0  # 0 = unlimited
        self.cache_max_size_mb: float = 0  # 0 = unlimited
        self.cache_ttl_seconds: int = 3600  # 1 hour
        self.cache_dir: str | None = None  # None = default (~/.cache/picosentry)
        # Scan settings
        self.force_json: bool = False  # Force JSON output even for TTY
        self.incremental: bool = False  # Only scan changed files (incremental mode)
        self.jobs: int = 1  # Parallel scan jobs
        # Update policy settings
        self.updates_enabled: bool = True  # False = hard-disable network updates
        self.updates_allowed_sources: list[str] = []  # allowlist of URLs
        self.updates_require_integrity: bool = True  # fail-closed on bad signatures
        self.corpus_require_signature: bool = True  # reject unsigned corpus packs (fail-closed default)

    def get_effective_policy(self) -> Policy | None:
        """Build a Policy from this config, using the policy file as source of truth.

        When a policy file is configured, its values take precedence over
        the duplicated config fields (allow_licenses, deny_licenses,
        deny_packages, waivers, fail_on_severity) to avoid field drift.

        Returns None if no policy file and no policy-related config is set.
        """
        from picosentry.scan.policy import Policy
        # If a policy file is set, load it as the authoritative source
        if self.policy_file:
            policy_path = Path(self.policy_file)
            if policy_path.is_file():
                return Policy.from_file(policy_path)
        # Otherwise, build from config fields (backward compat)
        has_any = self.allow_licenses or self.deny_licenses or self.deny_packages or self.waivers
        if not has_any:
            return None
        return Policy(
            fail_on_severity=self.fail_on_severity,
            allow_licenses=self.allow_licenses,
            deny_licenses=self.deny_licenses,
            deny_packages=self.deny_packages,
            waivers=self._build_waivers(),
        )
    def _build_waivers(self) -> list:
        """Build Waiver objects from config waiver dicts.

        Lazy-imports Waiver to avoid circular dependency at module level.
        """
        from picosentry.scan.policy import Waiver
        return [Waiver(**w) for w in self.waivers] if self.waivers else []

    def assert_secure(self) -> None:
        """Enforce secure configuration in production.

        Delegates to picosentry._core.config.assert_secure with PicoSentry-specific
        custom checks (corpus signature enforcement).
        Override with PICOSENTRY_SKIP_SECURE_ASSERT=1 (NOT recommended).
        """
        import os as _os

        if _os.environ.get("PICOSENTRY_SKIP_SECURE_ASSERT") == "1":
            logger.warning(
                "SECURITY ASSERT SKIPPED: PICOSENTRY_SKIP_SECURE_ASSERT=1 is set. This bypasses startup security checks."
            )
            return

        custom_checks: list[SecureBootCheck] = [_CorpusSignatureCheck(self)]
        _core_assert_secure(
            checks=custom_checks,
            secret_key="",
            bind_host="127.0.0.1",
            cors_origin="",
            debug=False,
            env=_os.environ.get("PICOSENTRY_ENV", "development"),
        )

    def merge_cli(self, args: Any) -> PicoSentryConfig:
        """Merge CLI args into this config. CLI flags override config file values.

        Uses None-sentinel pattern to detect explicitly-set CLI flags.
        Optional args use default=None in argparse; when the user passes a flag,
        argparse stores the explicit value (not None). We check is not None
        to detect overrides. For store_true flags, we check truthiness.

        This means: if a user explicitly passes --log-format text, it IS treated
        as an override (because args.log_format will be "text", not None). This
        is correct — explicit flags should override config even with same value.
        """
        merged = PicoSentryConfig()
        # Copy config file values
        merged.format = self.format
        merged.output = self.output
        merged.rules = self.rules
        merged.corpus = self.corpus
        merged.advisory_db = self.advisory_db
        merged.no_color = self.no_color
        merged.token_budget = self.token_budget
        merged.exit_code = self.exit_code
        merged.severity_threshold = self.severity_threshold
        merged.fail_on = self.fail_on
        merged.quiet = self.quiet
        merged.deterministic_output = self.deterministic_output
        merged.summary = self.summary
        merged.baseline = self.baseline
        merged.baseline_update = self.baseline_update
        merged.sarif_file = self.sarif_file
        merged.log_format = self.log_format
        merged.severity_overrides = dict(self.severity_overrides)
        merged.ignore_paths = list(self.ignore_paths)
        merged.ignore_packages = list(self.ignore_packages)
        merged.policy_file = self.policy_file
        merged.allow_licenses = list(self.allow_licenses)
        merged.deny_licenses = list(self.deny_licenses)
        merged.deny_packages = list(self.deny_packages)
        merged.waivers = list(self.waivers)

        if not hasattr(args, "format"):
            return merged

        # Override with CLI args — compare against argparse defaults.
        # Use getattr for safe access (tests may pass minimal Namespaces).
        # Defaults as defined in cli.py add_argument() calls.
        if getattr(args, "format", None) is not None:
            merged.format = args.format
        if getattr(args, "output", None) is not None:
            merged.output = args.output
        if getattr(args, "rules", None) is not None:
            merged.rules = args.rules
        if getattr(args, "corpus", None) is not None:
            merged.corpus = args.corpus
        if getattr(args, "advisory_db", None) is not None:
            merged.advisory_db = args.advisory_db
        if getattr(args, "no_color", False):
            merged.no_color = True
        if getattr(args, "token_budget", None) is not None:
            merged.token_budget = args.token_budget
        if getattr(args, "exit_code", False):
            merged.exit_code = True
        if getattr(args, "severity_threshold", None) is not None:
            merged.severity_threshold = args.severity_threshold
        if getattr(args, "fail_on", None) is not None:
            merged.fail_on = args.fail_on
            merged.exit_code = True  # fail_on implies exit_code
        if getattr(args, "deterministic_output", False):
            merged.deterministic_output = True
        if getattr(args, "quiet", False):
            merged.quiet = True
        if getattr(args, "summary", False):
            merged.summary = True
            merged.quiet = True  # summary implies quiet
        if getattr(args, "baseline", None) is not None:
            merged.baseline = args.baseline
        if getattr(args, "baseline_update", False):
            merged.baseline_update = True
        if getattr(args, "sarif_file", None) is not None:
            merged.sarif_file = args.sarif_file
        if getattr(args, "log_format", None) is not None:
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

        from picosentry.scan.models import Finding, Severity

        overridden = []
        for f in findings:
            if f.rule_id in self.severity_overrides:
                new_sev = self.severity_overrides[f.rule_id]
                try:
                    sev_enum = Severity(new_sev.upper())
                    f = Finding(
                        rule_id=f.rule_id,
                        severity=sev_enum,
                        confidence=f.confidence,
                        package=f.package,
                        file=f.file,
                        message=f.message,
                        evidence=f.evidence,
                        remediation=f.remediation,
                        references=f.references,
                        line=f.line,
                    )
                except ValueError:
                    logger.warning(
                        "Invalid severity override for %s: %s (expected CRITICAL/HIGH/MEDIUM/LOW/INFO)",
                        f.rule_id,
                        new_sev,
                    )
            overridden.append(f)
        return overridden

    def should_ignore_package(self, package_name: str) -> bool:
        """Check if a package should be ignored based on config."""
        return package_name in self.ignore_packages

    def should_ignore_path(self, file_path: str) -> bool:
        """Check if a file path should be ignored based on config glob patterns.

        Simple glob matching: * matches any sequence, ? matches single char.
        """
        if not self.ignore_paths:
            return False
        from fnmatch import fnmatch

        return any(fnmatch(file_path, pat) for pat in self.ignore_paths)


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

# Map of PICOSENTRY_* env vars to config attribute names.
# Precedence: CLI args > env vars > config file > defaults

_ENV_TO_ATTR = {
    "PICOSENTRY_FORMAT": "format",
    "PICOSENTRY_OUTPUT": "output",
    "PICOSENTRY_RULES": "rules",
    "PICOSENTRY_CORPUS": "corpus",
    "PICOSENTRY_NO_COLOR": "no_color",
    "PICOSENTRY_TOKEN_BUDGET": "token_budget",
    "PICOSENTRY_EXIT_CODE": "exit_code",
    "PICOSENTRY_SEVERITY_THRESHOLD": "severity_threshold",
    "PICOSENTRY_FAIL_ON": "fail_on",
    "PICOSENTRY_QUIET": "quiet",
    "PICOSENTRY_SUMMARY": "summary",
    "PICOSENTRY_BASELINE": "baseline",
    "PICOSENTRY_POLICY": "policy_file",
    "PICOSENTRY_CACHE_MAX_ENTRIES": "cache_max_entries",
    "PICOSENTRY_CACHE_MAX_SIZE_MB": "cache_max_size_mb",
    "PICOSENTRY_CACHE_TTL_SECONDS": "cache_ttl_seconds",
    "PICOSENTRY_CACHE_DIR": "cache_dir",
    "PICOSENTRY_UPDATES_ENABLED": "updates_enabled",
    "PICOSENTRY_UPDATES_REQUIRE_INTEGRITY": "updates_require_integrity",
    "PICOSENTRY_CORPUS_REQUIRE_SIGNATURE": "corpus_require_signature",
    "PICOSENTRY_ADVISORY_DB": "advisory_db",
    "PICOSENTRY_FORCE_JSON": "force_json",
    "PICOSENTRY_INCREMENTAL": "incremental",
    "PICOSENTRY_JOBS": "jobs",

}


def apply_env_overrides(config: PicoSentryConfig) -> PicoSentryConfig:
    """Apply PICOSENTRY_* environment variable overrides to config.

    Boolean values: "true", "1", "yes" → True; "false", "0", "no" → False.
    Integer values: parsed as int (token_budget, jobs).
    String values: used as-is (format, output, baseline, etc.).

    Precedence: env vars override config file values.
    CLI flags (applied after this) override env vars.
    """
    for env_name, attr_name in _ENV_TO_ATTR.items():
        env_val = os.environ.get(env_name)
        if env_val is None or env_val == "":
            continue

        # Parse by type
        lower = env_val.lower()
        if lower in ("true", "1", "yes"):
            setattr(config, attr_name, True)
        elif lower in ("false", "0", "no"):
            setattr(config, attr_name, False)
        else:
            # Try float first (for cache_max_size_mb), then int, fall back to string
            try:
                val = float(env_val)
                if val == int(val) and "." not in env_val:
                    setattr(config, attr_name, int(val))
                else:
                    setattr(config, attr_name, val)
            except ValueError:
                setattr(config, attr_name, env_val)

    return config


class _CorpusSignatureCheck:
    """PicoSentry-specific: unsigned corpus packs in production are risky."""

    def __init__(self, config: PicoSentryConfig) -> None:
        self._config = config

    def check(self) -> SecurityViolation | None:
        import os as _os
        env = _os.environ.get("PICOSENTRY_ENV", "development")
        if env in ("production", "staging") and not self._config.corpus_require_signature:
            return SecurityViolation(
                check="corpus_signature",
                message="Corpus signature verification disabled in production — set PICOSENTRY_CORPUS_REQUIRE_SIGNATURE=true",
                severity="WARN",
            )
        return None


def load_config(target_dir: Path) -> PicoSentryConfig:
    """Load configuration from target directory.

    Searches for .picosentry.yml, .picosentry.yaml, or picosentry.config.yml
    in the target directory. Returns default config if no file found.
    Unknown keys are warned about but do not cause a hard error.

    Deterministic: same directory = same config (or default).
    """
    config = PicoSentryConfig()

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
        config.format = data["format"]
    if "output" in data:
        config.output = data["output"]
    if "rules" in data:
        config.rules = data["rules"]
    if "corpus" in data:
        config.corpus = data["corpus"]

    if "advisory_db" in data:
        config.advisory_db = data["advisory_db"]
    if "no_color" in data:
        config.no_color = bool(data["no_color"])
    if "token_budget" in data:
        try:
            config.token_budget = int(data["token_budget"])
        except (ValueError, TypeError) as e:
            logger.warning("Invalid token_budget %r in %s: %s", data["token_budget"], config_path, e)
    if "exit_code" in data:
        config.exit_code = bool(data["exit_code"])
    if "severity_threshold" in data:
        val = str(data["severity_threshold"]).lower()
        if val not in VALID_SEVERITIES:
            logger.warning(
                "Invalid severity_threshold %r in %s (expected: %s)",
                data["severity_threshold"],
                config_path,
                ", ".join(sorted(VALID_SEVERITIES)),
            )
        else:
            config.severity_threshold = val
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
    if "quiet" in data:
        config.quiet = bool(data["quiet"])
    if "deterministic_output" in data:
        config.deterministic_output = bool(data["deterministic_output"])
    if "summary" in data:
        config.summary = bool(data["summary"])
    if "baseline" in data:
        # Resolve relative paths against config file directory
        baseline_path = data["baseline"]
        if not Path(baseline_path).is_absolute():
            baseline_path = str(config_path.parent / baseline_path)
        config.baseline = baseline_path
    if "baseline_update" in data:
        config.baseline_update = bool(data["baseline_update"])
    if "log_format" in data:
        config.log_format = data["log_format"]

    # Config-file-only settings
    if "severity_overrides" in data:
        try:
            config.severity_overrides = {str(k): str(v) for k, v in data["severity_overrides"].items()}
        except (AttributeError, TypeError, ValueError) as e:
            logger.warning("Invalid severity_overrides in %s: %s", config_path, e)
    if "ignore_paths" in data:
        if not isinstance(data["ignore_paths"], list):
            logger.warning("ignore_paths in %s is not a list, ignoring", config_path)
        else:
            config.ignore_paths = [str(p) for p in data["ignore_paths"]]
    if "ignore_packages" in data:
        if not isinstance(data["ignore_packages"], list):
            logger.warning("ignore_packages in %s is not a list, ignoring", config_path)
        else:
            config.ignore_packages = [str(p) for p in data["ignore_packages"]]

    # Load policy file if specified or found
    policy_path = None
    if data.get("policy"):
        policy_path = Path(data["policy"])
        if not policy_path.is_absolute():
            policy_path = config_path.parent / policy_path
    else:
        # Auto-discover .picosentry-policy.yml next to config
        auto_policy = config_path.parent / ".picosentry-policy.yml"
        if auto_policy.is_file():
            policy_path = auto_policy

    if policy_path and policy_path.is_file():
        config.policy_file = str(policy_path)
        try:
            from picosentry.scan.policy import Policy

            policy = Policy.from_file(policy_path)
            config.allow_licenses = policy.allow_licenses
            config.deny_licenses = policy.deny_licenses
            config.deny_packages = policy.deny_packages
            config.waivers = [w.to_dict() for w in policy.waivers]
            config.fail_on_severity = policy.fail_on_severity
        except Exception:
            logger.warning("Failed to load policy file %s", policy_path)

    # Load daemon section
    if "daemon" in data and isinstance(data["daemon"], dict):
        config.daemon = data["daemon"]

    # Load cache governance settings
    if "cache" in data and isinstance(data["cache"], dict):
        cache_data = data["cache"]
        if "max_entries" in cache_data:
            config.cache_max_entries = int(cache_data["max_entries"])
        if "max_size_mb" in cache_data:
            config.cache_max_size_mb = float(cache_data["max_size_mb"])
        if "ttl_seconds" in cache_data:
            config.cache_ttl_seconds = int(cache_data["ttl_seconds"])

    # Load update policy settings
    if "updates" in data and isinstance(data["updates"], dict):
        updates_data = data["updates"]
        if "enabled" in updates_data:
            config.updates_enabled = bool(updates_data["enabled"])
        if "allowed_sources" in updates_data and isinstance(updates_data["allowed_sources"], list):
            config.updates_allowed_sources = [str(s) for s in updates_data["allowed_sources"]]
        if "require_integrity" in updates_data:
            config.updates_require_integrity = bool(updates_data["require_integrity"])
        if "corpus_require_signature" in updates_data:
            config.corpus_require_signature = bool(updates_data["corpus_require_signature"])

    return config


def _find_config(target_dir: Path) -> Path | None:
    """Search for config file in target directory.

    Returns first match in precedence order:
    .picosentry.yml → .picosentry.yaml → picosentry.config.yml
    """
    for name in CONFIG_NAMES:
        candidate = target_dir / name
        if candidate.is_file():
            return candidate
    return None
