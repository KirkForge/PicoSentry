from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from picosentry._core.config import SecureBootCheck, SecurityViolation
from picosentry._core.config import assert_secure as _core_assert_secure

if TYPE_CHECKING:
    from picosentry.scan.policy import Policy

logger = logging.getLogger("picosentry.config")

try:
    import yaml as _yaml
except ImportError:  # pragma: no cover - PyYAML optional unless extra installed
    _yaml = cast("Any", None)

# Expose yaml module under a stable name for tests that need to monkeypatch it.
yaml = _yaml

# Operational errors that can occur while parsing a config file.  ImportError
# is handled separately (PyYAML not installed -> JSON fallback); these are the
# parse/read failures we expect and tolerate by returning defaults.
_CONFIG_PARSE_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
)
if cast("Any", _yaml) is not None:
    _CONFIG_PARSE_ERRORS = (*_CONFIG_PARSE_ERRORS, _yaml.YAMLError)


CONFIG_NAMES = [".picosentry.yml", ".picosentry.yaml", "picosentry.config.yml"]


CONFIG_VERSION = 1


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


VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


_UNSET = object()


class PicoSentryConfig:
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
        self.sarif_file: str | None = None
        self.deterministic_output: bool = False
        self.log_format: str = "text"

        self.severity_overrides: dict[str, str] = {}  # rule_id → severity
        self.ignore_paths: list[str] = []  # glob patterns to skip
        self.ignore_packages: list[str] = []  # package names to skip

        self.policy_file: str | None = None  # path to policy file
        self.allow_licenses: list[str] = []  # SPDX license allow-list
        self.deny_licenses: list[str] = []  # SPDX license deny-list
        self.deny_packages: list[str] = []  # blocked packages
        self.waivers: list[dict] = []  # policy waivers
        self.fail_on_severity: str = "high"  # minimum severity to fail CI

        self.daemon: dict = {}

        self.cache_max_entries: int = 0  # 0 = unlimited
        self.cache_max_size_mb: float = 0  # 0 = unlimited
        self.cache_ttl_seconds: int = 3600  # 1 hour
        self.cache_dir: str | None = None  # None = default (~/.cache/picosentry)

        self.force_json: bool = False  # Force JSON output even for TTY
        self.incremental: bool = False  # Only scan changed files (incremental mode)
        self.jobs: int = 1  # Parallel scan jobs

        self.updates_enabled: bool = True  # False = hard-disable network updates
        self.updates_allowed_sources: list[str] = []  # allowlist of URLs
        self.updates_require_integrity: bool = True  # fail-closed on bad signatures
        self.corpus_require_signature: bool = True  # reject unsigned corpus packs (fail-closed default)

    def get_effective_policy(self) -> Policy | None:
        from picosentry.scan.policy import Policy

        if self.policy_file:
            policy_path = Path(self.policy_file)
            if policy_path.is_file():
                return Policy.from_file(policy_path)

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
        from picosentry.scan.policy import Waiver

        return [Waiver(**w) for w in self.waivers] if self.waivers else []

    def assert_secure(self) -> None:
        import os as _os

        if _os.environ.get("PICOSENTRY_SKIP_SECURE_ASSERT") == "1":
            logger.warning(
                "SECURITY ASSERT SKIPPED: PICOSENTRY_SKIP_SECURE_ASSERT=1 is set. "
                "This bypasses startup security checks."
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
        merged = PicoSentryConfig()

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
        if not self.severity_overrides:
            return findings

        from picosentry.scan.models import Finding, Severity

        overridden = []
        for finding in findings:
            f = finding
            if finding.rule_id in self.severity_overrides:
                new_sev = self.severity_overrides[finding.rule_id]
                try:
                    sev_enum = Severity(new_sev.upper())
                    f = Finding(
                        rule_id=finding.rule_id,
                        severity=sev_enum,
                        confidence=finding.confidence,
                        package=finding.package,
                        file=finding.file,
                        message=finding.message,
                        evidence=finding.evidence,
                        remediation=finding.remediation,
                        references=finding.references,
                        line=finding.line,
                    )
                except ValueError:
                    logger.warning(
                        "Invalid severity override for %s: %s (expected CRITICAL/HIGH/MEDIUM/LOW/INFO)",
                        finding.rule_id,
                        new_sev,
                    )
            overridden.append(f)
        return overridden

    def should_ignore_package(self, package_name: str) -> bool:
        return package_name in self.ignore_packages

    def should_ignore_path(self, file_path: str) -> bool:
        if not self.ignore_paths:
            return False
        from fnmatch import fnmatch

        return any(fnmatch(file_path, pat) for pat in self.ignore_paths)


def _validate_config_keys(data: dict, config_path: Path) -> None:
    unknown = sorted(set(data.keys()) - KNOWN_KEYS)
    for key in unknown:
        logger.warning(
            "Unknown config key '%s' in %s — will be ignored. Did you mean one of: %s?",
            key,
            config_path,
            ", ".join(sorted(KNOWN_KEYS)),
        )


class _CorpusSignatureCheck:
    def __init__(self, config: PicoSentryConfig) -> None:
        self._config = config

    def check(self) -> SecurityViolation | None:
        import os as _os

        env = _os.environ.get("PICOSENTRY_ENV", "development")
        if env in ("production", "staging") and not self._config.corpus_require_signature:
            return SecurityViolation(
                check="corpus_signature",
                message=(
                    "Corpus signature verification disabled in production — "
                    "set PICOSENTRY_CORPUS_REQUIRE_SIGNATURE=true"
                ),
                severity="WARN",
            )
        return None


def load_config(target_dir: Path) -> PicoSentryConfig:
    config = PicoSentryConfig()

    config_path = _find_config(target_dir)
    if config_path is None:
        return config

    logger.info("Loading config from %s", config_path)

    data: dict[str, Any] | None = None
    if yaml is None:
        try:
            import json

            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse config file %s: %s", config_path, e)
            return config
        # JSON parsed successfully; fall through to validation below.
    else:
        try:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except _CONFIG_PARSE_ERRORS as e:
            logger.warning("Failed to parse config file %s: %s", config_path, e)
            return config

    # yaml.safe_load may return None for an empty file; treat as empty dict.
    if data is None:
        data = {}

    if not isinstance(data, dict):
        logger.warning("Config file %s is not a mapping, ignoring", config_path)
        return config

    _validate_config_keys(data, config_path)

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
        baseline_path = data["baseline"]
        if not Path(baseline_path).is_absolute():
            baseline_path = str(config_path.parent / baseline_path)
        config.baseline = baseline_path
    if "baseline_update" in data:
        config.baseline_update = bool(data["baseline_update"])
    if "log_format" in data:
        config.log_format = data["log_format"]

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

    policy_path = None
    if data.get("policy"):
        policy_path = Path(data["policy"])
        if not policy_path.is_absolute():
            policy_path = config_path.parent / policy_path
    else:
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
        except (OSError, RuntimeError, ValueError, TypeError):
            logger.warning("Failed to load policy file %s", policy_path)

    if "daemon" in data and isinstance(data["daemon"], dict):
        config.daemon = data["daemon"]

    if "cache" in data and isinstance(data["cache"], dict):
        cache_data = data["cache"]
        if "max_entries" in cache_data:
            config.cache_max_entries = int(cache_data["max_entries"])
        if "max_size_mb" in cache_data:
            config.cache_max_size_mb = float(cache_data["max_size_mb"])
        if "ttl_seconds" in cache_data:
            config.cache_ttl_seconds = int(cache_data["ttl_seconds"])

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
    for name in CONFIG_NAMES:
        candidate = target_dir / name
        if candidate.is_file():
            return candidate
    return None
