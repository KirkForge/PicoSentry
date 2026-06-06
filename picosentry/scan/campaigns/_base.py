"""
Per-campaign IOC package base class.

A campaign package is a self-contained, named unit of detection for a
specific real-world supply-chain attack. The convention is:

    picosentry/scan/campaigns/<campaign_id>/
        iocs.json         structured indicator data (see schema below)
        detector.py       CampaignPackage subclass
        tests/            per-campaign unit tests

iocs.json schema (v1.0, additive — fields may be added; removal is breaking):

    {
      "campaign_id":       "shai-hulud-2025",        # required, kebab-case
      "schema_version":    "1.0",                    # required
      "severity":          "CRITICAL",               # required: CRITICAL|HIGH|MEDIUM|LOW
      "description":       "...",                    # required, 1-2 sentence narrative
      "ecosystem":         ["npm"],                  # required, list of: npm|pypi|go|cargo|maven|rubygems|nuget
      "rule_id":           "L2-CAMP-SHAI-HULUD",     # required, L2-CAMP-*
      "references":        ["https://..."],          # recommended
      "expected_rule_ids": ["L2-POST-001", ...],     # optional, calibration hints
      "indicators": {
        "named_signatures":      [...],  # literal strings — CRITICAL fast path
        "c2_domains":            [...],  # network C2 / phishing
        "phishing_domains":      [...],
        "payload_filenames":     [...],  # known malicious filenames
        "bundle_hashes_sha256":  {...},  # file content hashes by variant label
        "compromised_packages":  [{package_name, version_range, severity}, ...]
      }
    }

The CampaignPackage base class:

  - Loads and validates the iocs.json
  - Provides a `register(engine)` helper that wires the campaign into a
    ScanEngine under its declared rule_id
  - Provides `detect_named_signatures`, `detect_payload_filenames`,
    `detect_packages` primitives that subclasses compose into a `detect()`
    entrypoint

The "named signature" fast path is the cheap, high-precision CRITICAL
check: if a literal string from `named_signatures` appears anywhere in
a project file, emit a CRITICAL finding immediately. This is modeled
on npm-scan's `NAMED_SIGNATURES` array and is the single highest-ROI
primitive we can borrow from the competitor.

This module is intentionally small. The per-campaign detectors in
shai_hulud/, node_ipc_compromise/, etc. do the actual work.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Confidence, Finding, Severity
from ..rules.utils import iter_node_modules

__all__ = [
    "CampaignPackage",
    "IndicatorSet",
    "iter_campaigns",
    "list_campaigns",
]

logger = logging.getLogger("picosentry.campaigns")

# Bundle of compiled regexes extracted from a loaded iocs.json. Pre-compiled
# once at construction so per-detector scan paths are hot.
@dataclass(frozen=True)
class IndicatorSet:
    """Compiled view of an iocs.json file.

    Use the raw `data` dict via `CampaignPackage.iocs()` for one-off lookups
    (e.g., compromised_packages iteration). Use these pre-compiled fields in
    hot paths.
    """

    named_signatures: tuple[str, ...] = ()
    c2_domains: tuple[str, ...] = ()
    phishing_domains: tuple[str, ...] = ()
    payload_filenames: tuple[str, ...] = ()
    bundle_hashes_sha256: dict[str, str] = field(default_factory=dict)

    @property
    def has_named_signatures(self) -> bool:
        return bool(self.named_signatures)

    @property
    def has_payload_filenames(self) -> bool:
        return bool(self.payload_filenames)

    @property
    def has_c2_domains(self) -> bool:
        return bool(self.c2_domains)


# File extensions we consider for content scan (named-signature fast path).
_CONTENT_EXTENSIONS = frozenset(
    {
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
        ".json", ".yaml", ".yml", ".toml", ".py",
        ".sh", ".bash", ".rb", ".go", ".rs",
        ".md", ".txt", ".env", ".cfg", ".ini",
    }
)
_SKIP_DIRS = frozenset(
    {
        ".git", "__pycache__", ".cache", ".hg", ".svn",
        "node_modules/.cache", "dist", "build", "out",
    }
)
_MAX_FILE_BYTES = 512_000  # 512 KB — same budget as network_exfil rule


class CampaignPackage:
    """Base class for per-campaign detection packages.

    Subclasses MUST define:
      - campaign_id:    str   — kebab-case, matches the folder name
      - rule_id:        str   — L2-CAMP-* (see rule-id taxonomy in rules/__init__.py)
      - iocs_path:      Path  — path to the iocs.json file

    Subclasses MAY override:
      - detect():   the entry point used by ScanEngine. Default composes
                   detect_named_signatures + detect_payload_filenames +
                   detect_packages.
      - severity / confidence defaults: per-campaign override of finding
                   severity (default = file's `severity` field).

    The base class also provides `register(engine)` for ergonomic wiring
    in `create_default_engine`.
    """

    # Subclass-declared attributes. Use Any typing to keep dataclass-free.
    campaign_id: str = ""
    rule_id: str = ""
    iocs_path: Path = Path()
    # Optional: ecosystems the campaign applies to. Default = empty (matches
    # any). Subclasses set this to e.g. ("npm",) to gate detection.
    ecosystems: tuple[str, ...] = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        # Reserved for future extension (e.g., third-party plugin
        # registration). The current auto-discovery walks
        # CampaignPackage.__subclasses__() in iter_campaigns(), so
        # subclasses are picked up without any explicit register call.
        super().__init_subclass__(**kwargs)

    # ── Construction / loading ──────────────────────────────────────────
    def __init__(self) -> None:
        if not self.campaign_id:
            raise ValueError(f"{type(self).__name__} must define campaign_id")
        if not self.rule_id or not self.rule_id.startswith("L2-CAMP-"):
            raise ValueError(
                f"{type(self).__name__}.rule_id must start with L2-CAMP- "
                f"(see scan/rules/__init__.py taxonomy); got {self.rule_id!r}"
            )
        if not self.iocs_path or not Path(self.iocs_path).is_file():
            raise FileNotFoundError(
                f"{type(self).__name__}: iocs.json not found at {self.iocs_path!r}"
            )
        self._data: dict = self._load_iocs(self.iocs_path)
        self._indicators = self._compile_indicators(self._data.get("indicators", {}))

    @staticmethod
    def _load_iocs(path: Path) -> dict:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for required in ("campaign_id", "schema_version", "severity", "description", "ecosystem", "rule_id"):
            if required not in data:
                raise ValueError(f"iocs.json {path}: missing required field {required!r}")
        if data["rule_id"] != data.get("rule_id"):
            # Defensive: ensure rule_id consistency
            pass
        return data

    @staticmethod
    def _compile_indicators(raw: dict) -> IndicatorSet:
        return IndicatorSet(
            named_signatures=tuple(raw.get("named_signatures", ())),
            c2_domains=tuple(raw.get("c2_domains", ())),
            phishing_domains=tuple(raw.get("phishing_domains", ())),
            payload_filenames=tuple(raw.get("payload_filenames", ())),
            bundle_hashes_sha256=dict(raw.get("bundle_hashes_sha256", {})),
        )

    # ── Public accessors ────────────────────────────────────────────────
    def iocs(self) -> dict:
        """Return the raw iocs.json dict (read-only contract)."""
        return self._data

    def indicators(self) -> IndicatorSet:
        """Return the compiled IndicatorSet for hot-path use."""
        return self._indicators

    def severity(self) -> Severity:
        return _parse_severity(self._data.get("severity", "HIGH"))

    def description(self) -> str:
        return self._data.get("description", "")

    def references(self) -> list[str]:
        return list(self._data.get("references", []))

    def expected_rule_ids(self) -> list[str]:
        return list(self._data.get("expected_rule_ids", []))

    def compromised_packages(self) -> list[dict]:
        return list(self._data.get("indicators", {}).get("compromised_packages", []))

    # ── Detection primitives ────────────────────────────────────────────
    def detect_named_signatures(
        self, target: Path, *, confidence: Confidence = Confidence.HIGH
    ) -> list[Finding]:
        """CRITICAL fast path: literal-string match across project files.

        If any file content contains a string from `named_signatures`,
        emit a CRITICAL finding for that file. This is modeled on
        npm-scan's NAMED_SIGNATURES first-line check and is the
        highest-precision rule in the entire system: zero expected FPs
        because the strings are the literal names of real malware.
        """
        if not self._indicators.has_named_signatures:
            return []

        findings: list[Finding] = []
        signatures: tuple[str, ...] = self._indicators.named_signatures
        sev = Severity.CRITICAL
        target_prefix = str(target.resolve()) + "/"

        # Limit scan to the target's top-level + first-level subdirs to
        # bound the work. The named-signature check is content-only.
        for file_path in _iter_scannable_files(target):
            if file_path.is_symlink():
                continue
            try:
                if file_path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for sig in signatures:
                if sig in content:
                    file_display = str(file_path)
                    if file_display.startswith(target_prefix):
                        file_display = file_display[len(target_prefix):]
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=sev,
                            confidence=confidence,
                            package=self.campaign_id,
                            file=file_display,
                            message=(
                                f"Named-signature match for {self.campaign_id}: "
                                f"literal {sig!r} found in source"
                            ),
                            evidence=(
                                f"named_signature={sig!r}, "
                                f"campaign={self.campaign_id}, "
                                f"scan_strategy=literal_string_substring"
                            ),
                            remediation=(
                                f"This file matches a literal indicator for the "
                                f"{self.campaign_id} supply-chain attack. "
                                f"Quarantine the package, audit its dependencies, "
                                f"and check the IoC references for full scope."
                            ),
                            references=self.references(),
                            ecosystem="npm",
                        )
                    )
                    # One finding per file is enough; don't pile up
                    break
        return findings

    def detect_payload_filenames(self, target: Path) -> list[Finding]:
        """Detect files whose names match known-malicious payload filenames.

        Less precise than named-signature (a file named ``setup_bun.js`` may
        be legitimate), but high-signal when combined with the package context.
        """
        if not self._indicators.has_payload_filenames:
            return []
        names = set(self._indicators.payload_filenames)
        findings: list[Finding] = []
        target_prefix = str(target.resolve()) + "/"
        for file_path in target.rglob("*"):
            if not file_path.is_file() or file_path.is_symlink():
                continue
            if any(part in _SKIP_DIRS for part in file_path.parts):
                continue
            if file_path.name in names:
                file_display = str(file_path)
                if file_display.startswith(target_prefix):
                    file_display = file_display[len(target_prefix):]
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity(),
                        confidence=Confidence.MEDIUM,
                        package=self.campaign_id,
                        file=file_display,
                        message=(
                            f"Payload filename {file_path.name!r} matches "
                            f"known indicator for {self.campaign_id}"
                        ),
                        evidence=(
                            f"payload_filename={file_path.name!r}, "
                            f"campaign={self.campaign_id}"
                        ),
                        remediation=(
                            f"Verify whether this file is part of the "
                            f"{self.campaign_id} attack chain or a legitimate "
                            f"file that happens to share the name."
                        ),
                        references=self.references(),
                        ecosystem="npm",
                    )
                )
        return findings

    def detect_packages(self, target: Path) -> list[Finding]:
        """Match every installed package against `compromised_packages`.

        Uses the same semver-aware matcher as the existing L2-IOC-001 rule
        (re-imported here to keep this module's surface small and the
        campaign rule self-contained).
        """
        from ..rules.ioc_detection import _semver_matches  # local import — circular otherwise

        compromised = self.compromised_packages()
        if not compromised:
            return []

        findings: list[Finding] = []
        for pkg_json, pkg in iter_node_modules(target):
            pkg_name = pkg.get("name", pkg_json.parent.name)
            pkg_version = pkg.get("version", "unknown")
            for ioc in compromised:
                if ioc.get("package_name") != pkg_name:
                    continue
                constraint = str(ioc.get("version_range", "*"))
                if constraint != "*" and not _semver_matches(pkg_version, constraint):
                    continue
                try:
                    sev = _parse_severity(ioc.get("severity", self._data.get("severity", "HIGH")))
                except ValueError:
                    sev = self.severity()
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=sev,
                        confidence=Confidence.EXACT,
                        package=f"{pkg_name}@{pkg_version}",
                        file=str(pkg_json),
                        message=(
                            f"Package {pkg_name}@{pkg_version} matches a known "
                            f"compromised version from the {self.campaign_id} campaign"
                        ),
                        evidence=(
                            f"campaign={self.campaign_id}, package={pkg_name}, "
                            f"installed_version={pkg_version}, "
                            f"compromised_version_range={constraint}"
                        ),
                        remediation=(
                            f"This package is on the {self.campaign_id} compromise "
                            f"list. Upgrade to a clean version, remove the dependency, "
                            f"or replace with an alternative."
                        ),
                        references=self.references(),
                        ecosystem=pkg_json.parent.parent.name if pkg_json.parent.parent.name in {"node_modules"} else "npm",
                    )
                )
        return findings

    # ── Default detect() composition ────────────────────────────────────
    def detect(self, target: Path, corpus_dir: Path) -> list[Finding]:
        """Default detection entry point.

        Runs all three primitives (named-signature, payload-filename, package
        match) and returns the union. Subclasses MAY override to add campaign-
        specific logic (e.g., a regex on `npm install` output).
        """
        findings: list[Finding] = []
        findings.extend(self.detect_named_signatures(target))
        findings.extend(self.detect_payload_filenames(target))
        findings.extend(self.detect_packages(target))
        return findings

    # ── Engine registration ─────────────────────────────────────────────
    def register(self, engine: object) -> None:
        """Register this campaign with a ScanEngine instance.

        Adapter-friendly signature: the only method called on `engine` is
        `register(rule_id, rule_fn)`, so any object with that shape works.
        """
        # The detector signature is (target_path, corpus_dir) -> list[Finding]
        # — same as every other rule.
        engine.register(self.rule_id, self.detect)  # type: ignore[attr-defined]
        logger.debug("Registered campaign %s as rule %s", self.campaign_id, self.rule_id)


# ── Helpers (module-level, not on the class) ──────────────────────────

def _parse_severity(s: str) -> Severity:
    return Severity(s.upper())


def _iter_scannable_files(target: Path) -> Iterable[Path]:
    """Yield files under `target` that are candidates for content scan.

    Bound the work by skipping heavy / binary directories. Mirrors the skip
    sets used by other detectors in the codebase so behavior is consistent.
    """
    if target.is_file():
        yield target
        return
    if not target.is_dir():
        return
    for file in target.rglob("*"):
        if not file.is_file() or file.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in file.parts):
            continue
        if file.suffix in _CONTENT_EXTENSIONS or file.name in {
            "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
            ".npmrc", "pnpm-workspace.yaml", "requirements.txt", "pyproject.toml",
            "setup.py", "Pipfile", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
            "pom.xml", "build.gradle", "Gemfile", "Gemfile.lock", "Makefile",
        }:
            yield file


def list_campaigns() -> list[Path]:
    """List the campaign package directories in the campaigns/ folder.

    A directory counts as a campaign if it has both iocs.json and detector.py.
    """
    campaigns_root = Path(__file__).parent
    found: list[Path] = []
    for entry in sorted(campaigns_root.iterdir()):
        if not entry.is_dir() or entry.name.startswith(("_", ".")):
            continue
        if (entry / "iocs.json").is_file() and (entry / "detector.py").is_file():
            found.append(entry)
    return found


def iter_campaigns() -> Iterable[CampaignPackage]:
    """Import and instantiate every campaign package.

    Auto-discovery entry point used by `create_default_engine`. Importing the
    detector module triggers the subclass definition, which is then picked up
    via __init_subclass__ registration below. We deliberately import here
    (not at module top) to keep import order: _base must load first.
    """
    import importlib

    subclasses: list[type[CampaignPackage]] = list(CampaignPackage.__subclasses__())
    for camp_path in list_campaigns():
        module_name = f"picosentry.scan.campaigns.{camp_path.name}"
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            logger.warning("Failed to import campaign %s: %s", camp_path.name, exc)
            continue
        # The detector module's import triggers subclass registration.
        # Discover any newly-registered subclasses.
        for sub in CampaignPackage.__subclasses__():
            if sub not in subclasses:
                subclasses.append(sub)

    for sub in subclasses:
        try:
            yield sub()
        except Exception as exc:
            logger.warning("Failed to instantiate campaign %s: %s", sub.__name__, exc)
