"""
Advisory database integration for PicoSentry.

Loads OSV-format vulnerability data from a local directory and matches
installed packages against known CVEs, GHSA advisories, and npm advisories.

Enterprise teams can mirror the OSV database locally for air-gapped scanning:
    gsutil cp gs://osv-vulnerabilities/npm/all.zip .
    unzip all.zip -d advisories/
    picosentry scan . --advisory-db advisories/

Offline-only. No network calls at scan time.
Supports: OSV JSON format, GitHub Advisory Database (GHSA), npm advisory format.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("picosentry.advisory")

# Semver parsing: extract major.minor.patch and pre-release from a version string.
# Pre-release versions (e.g. 1.2.3-alpha) sort lower than their release counterpart.
_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:[-.]([a-zA-Z0-9._-]+))?")
_PRE_RELEASE_RE = re.compile(r"^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$")


@dataclass
class Advisory:
    """A single security advisory from an OSV-format database."""

    id: str = ""  # CVE-2024-xxxx, GHSA-xxxx-xxxx, etc.
    package_name: str = ""  # npm package name
    summary: str = ""
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    fixed_version: str = ""  # First patched version
    affected_versions: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published: str = ""
    database_specific: dict = field(default_factory=dict)
    affected_ranges: list[tuple[str, str, bool]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "package_name": self.package_name,
            "summary": self.summary,
            "severity": self.severity,
            "fixed_version": self.fixed_version,
            "affected_versions": self.affected_versions,
            "cwe_ids": self.cwe_ids,
            "references": self.references,
            "published": self.published,
            "affected_ranges": self.affected_ranges,
        }

    @staticmethod
    def from_osv(data: dict) -> Advisory | None:
        """Parse an OSV-format advisory entry.

        OSV schema: https://ossf.github.io/osv-schema/
        """
        adv_id = data.get("id", "")
        summary = data.get("summary", "")
        details = data.get("details", "")
        if not summary and details:
            summary = details[:200]

        # Extract package name from "affected" array
        pkg_name = ""
        affected_versions: list[str] = []
        affected_ranges: list[tuple[str, str, bool]] = []
        for affected in data.get("affected", []):
            pkg = affected.get("package", {})
            ecosystem = pkg.get("ecosystem", "")
            if ecosystem.lower() in ("npm", "pypi", "go", "cargo", "maven", "rubygems", "nuget"):
                pkg_name = pkg.get("name", "")
            for r in affected.get("ranges", []):
                introduced = ""
                fixed = ""
                last_affected = ""
                for event in r.get("events", []):
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                    if "last_affected" in event:
                        last_affected = event["last_affected"]
                if introduced:
                    if fixed:
                        # fixed is exclusive upper bound (< fixed)
                        affected_ranges.append((introduced, fixed, False))
                    elif last_affected:
                        # last_affected is inclusive upper bound (<= last_affected)
                        affected_ranges.append((introduced, last_affected, True))
                    else:
                        # No upper bound — all versions >= introduced are affected
                        affected_ranges.append((introduced, "", False))
            for ver in affected.get("versions", []):
                if ver not in affected_versions:
                    affected_versions.append(ver)

        if not pkg_name:
            return None

        # Determine severity from database_specific or aliases
        severity = "MEDIUM"
        db_specific = data.get("database_specific", {})
        if isinstance(db_specific, dict):
            sev = db_specific.get("severity", "").upper()
            if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                severity = sev

        # Extract fixed version
        fixed_version = ""
        for affected in data.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]

        return Advisory(
            id=adv_id,
            package_name=pkg_name,
            summary=summary,
            severity=severity,
            fixed_version=fixed_version,
            affected_versions=affected_versions,
            affected_ranges=affected_ranges,
            cwe_ids=data.get("database_specific", {}).get("cwe_ids", [])
            if isinstance(data.get("database_specific"), dict)
            else [],
            references=[ref.get("url", "") for ref in data.get("references", [])],
            published=data.get("published", ""),
            database_specific=db_specific if isinstance(db_specific, dict) else {},
        )

    @staticmethod
    def from_ghsa(data: dict) -> Advisory | None:
        """Parse a GitHub Advisory Database (GHSA) entry."""
        adv_id = data.get("ghsa_id", data.get("id", ""))
        return Advisory(
            id=adv_id,
            package_name=data.get("package", {}).get("name", ""),
            summary=data.get("summary", ""),
            severity=data.get("severity", "MEDIUM").upper(),
            fixed_version=data.get("first_patched_version", {}).get("identifier", ""),
            affected_versions=[data.get("vulnerable_version_range", "")],
            cwe_ids=[c.get("cwe_id", "") for c in data.get("cwes", [])],
            references=data.get("references", []),
            published=data.get("published_at", ""),
        )


class AdvisoryDB:
    """Offline advisory database loaded from local OSV-format files.

    Directory structure expected:
        advisories/
          npm/
            CVE-2024-xxxx.json
            GHSA-xxxx-xxxx.json
          or flat .json files

    Each file is a single OSV-format advisory entry.
    """

    def __init__(self, db_dir: Path | None = None) -> None:
        self._advisories: dict[str, list[Advisory]] = {}  # pkg_name → advisories
        self._loaded = False
        self._loaded_at: float | None = None  # monotonic timestamp of when DB was loaded
        self._db_dir = db_dir
        if db_dir and db_dir.is_dir():
            self.load(db_dir)

    def load(self, db_dir: Path) -> int:
        """Load all advisory files from a directory.

        Returns number of advisories loaded.
        """
        import time
        count = 0
        for json_file in sorted(db_dir.rglob("*.json")):
            if json_file.is_symlink():
                continue
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                logger.debug("Failed to read advisory file: %s", json_file)
                continue

            # Support both single advisory and array of advisories
            entries = data if isinstance(data, list) else [data]

            for entry in entries:
                adv = Advisory.from_osv(entry)
                if adv is None:
                    continue
                self._advisories.setdefault(adv.package_name, []).append(adv)
                count += 1

        self._loaded = True
        self._loaded_at = time.monotonic()
        logger.info("Loaded %d advisories for %d packages", count, len(self._advisories))
        return count

    def check(self, pkg_name: str, pkg_version: str) -> list[Advisory]:
        """Check a package against known advisories.

        Returns list of advisories affecting this package.
        Simple version matching: checks if version is in affected range
        or below the fixed version.
        """
        advisories = self._advisories.get(pkg_name, [])
        if not advisories:
            return []

        results: list[Advisory] = []
        for adv in advisories:
            if self._version_affected(pkg_version, adv):
                results.append(adv)

        return results

    def _version_affected(self, version: str, adv: Advisory) -> bool:
        """Check if a version is affected by an advisory.

        Checks structured range intervals first (with AND logic within each
        range), then falls back to fixed_version heuristic and explicit
        affected_versions list for backward compatibility.
        """
        v_tuple = self._parse_version(version)
        if v_tuple is None:
            return False  # Can't parse, assume not affected (conservative)

        # Check structured range intervals (AND logic within each range)
        for introduced, upper, upper_inclusive in adv.affected_ranges:
            iv = self._parse_version(introduced)
            if iv is None:
                continue
            if v_tuple < iv:
                continue
            if upper:
                uv = self._parse_version(upper)
                if uv is not None:
                    if upper_inclusive:
                        if v_tuple > uv:
                            continue
                    else:
                        if v_tuple >= uv:
                            continue
            return True

        # Fallback: if fixed version is set and version < fixed_version,
        # the package is affected (used by GHSA and other sources without ranges).
        # Skip this heuristic when structured ranges are available, since
        # ranges encode both lower and upper bounds correctly.
        if not adv.affected_ranges:
            fv_tuple = self._parse_version(adv.fixed_version)
            if fv_tuple and v_tuple < fv_tuple:
                return True

        # Check explicit affected version matches
        return any(self._version_in_range(v_tuple, av) for av in adv.affected_versions)

    @staticmethod
    def _parse_version(version_str: str) -> tuple | None:
        """Parse a semver-ish string into a comparable tuple.

        Returns (major, minor, patch, pre_release) where pre_release is
        a tuple of identifiers. Pre-release versions sort lower than the
        release: 1.2.3-alpha < 1.2.3, 1.2.3-alpha.1 < 1.2.3-alpha.2.
        A release version (no pre-release tag) uses an empty tuple for
        pre_release, which sorts higher than any pre-release tuple per
        semver spec (§11).
        """
        if not version_str:
            return None
        m = _SEMVER_RE.search(version_str)
        if m:
            pre = m.group(4) or ""
            # Strip build metadata (+build.xxx) that follows pre-release
            if "+" in pre:
                pre = pre[: pre.index("+")]
            # Parse pre-release identifiers: "alpha.1" → (0, "alpha", 1)
            # Pre-release versions sort lower than release (0, ...) < (1,)
            # per semver spec §11.
            if pre:
                parts: list[int | str] = []
                for ident in pre.split("."):
                    try:
                        parts.append(int(ident))
                    except ValueError:
                        parts.append(ident)
                pre_tuple = (0, *tuple(parts))
            else:
                pre_tuple = (1,)  # release sorts higher than any pre-release
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre_tuple)
        return None

    @staticmethod
    def _version_in_range(v_tuple: tuple, range_str: str) -> bool:
        """Check if version falls within a simple range like '>=1.0.0' or '<2.0.0'."""
        range_str = range_str.strip()
        if range_str.startswith(">="):
            rv = AdvisoryDB._parse_version(range_str[2:])
            return rv is not None and v_tuple >= rv
        if range_str.startswith("<="):
            rv = AdvisoryDB._parse_version(range_str[2:])
            return rv is not None and v_tuple <= rv
        if range_str.startswith(">"):
            rv = AdvisoryDB._parse_version(range_str[1:])
            return rv is not None and v_tuple > rv
        if range_str.startswith("<"):
            rv = AdvisoryDB._parse_version(range_str[1:])
            return rv is not None and v_tuple < rv
        # Exact version match
        rv = AdvisoryDB._parse_version(range_str)
        return rv is not None and v_tuple == rv

    @property
    def package_count(self) -> int:
        return len(self._advisories)

    @property
    def advisory_count(self) -> int:
        return sum(len(v) for v in self._advisories.values())

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def is_stale(self) -> bool:
        """Check if the advisory database is stale (loaded > 24h ago).

        Returns True if the database was never loaded or loaded more than
        24 hours ago, indicating it should be refreshed.
        """
        import time
        if self._loaded_at is None:
            return True
        return (time.monotonic() - self._loaded_at) > 86400  # 24 hours


# ── Bundled advisory snapshot ─────────────────────────────────────────


def load_bundled_advisories() -> AdvisoryDB:
    """Load the bundled advisory snapshot that ships with PicoSentry.

    The snapshot contains a curated set of critical/high severity
    npm advisories for air-gapped and offline environments.
    For the full advisory database, use `picosentry advisories fetch`
    or run `scripts/download-advisories.sh`.

    Returns:
        AdvisoryDB loaded with bundled advisories.
    """
    bundled_path = Path(__file__).parent / "corpus" / "advisories" / "npm-critical-advisories.json"
    db = AdvisoryDB()
    if not bundled_path.is_file():
        logger.warning("Bundled advisory file not found: %s", bundled_path)
        return db

    try:
        data = json.loads(bundled_path.read_text(encoding="utf-8"))
        advisory_list = data.get("advisories", [])
        if not advisory_list:
            logger.info("Bundled advisory snapshot is empty — run scripts/bundle-advisories.py to populate")
            return db

        for entry in advisory_list:
            adv = Advisory.from_osv(entry)
            if adv is None:
                continue
            db._advisories.setdefault(adv.package_name, []).append(adv)

        db._loaded = True
        meta = data.get("metadata", {})
        logger.info(
            "Loaded %d bundled advisories for %d packages (source: %s)",
            len(advisory_list),
            len(db._advisories),
            meta.get("source", "unknown"),
        )
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load bundled advisories: %s", e)

    return db


def default_advisory_dir() -> Path:
    """Return default advisory database directory path.

    Preference order:
        1. $PICOSENTRY_ADVISORY_DIR env var (canonical)
        2. $PICOADVISORY_DIR env var (backward compat)
        3. ~/.local/share/picosentry/advisories/
    """
    import os

    explicit = os.environ.get("PICOSENTRY_ADVISORY_DIR") or os.environ.get("PICOADVISORY_DIR")
    if explicit:
        return Path(explicit)
    return Path.home() / ".local" / "share" / "picosentry" / "advisories"
