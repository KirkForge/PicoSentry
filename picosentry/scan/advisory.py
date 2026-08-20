from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("picosentry.advisory")


_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:[-.]([a-zA-Z0-9._-]+))?")
_PRE_RELEASE_RE = re.compile(r"^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$")


_KNOWN_ECOSYSTEMS = frozenset(("npm", "pypi", "go", "cargo", "maven", "rubygems", "nuget"))

# PEP 503 normalized name: runs of [-_.] → single "-", lowercase. PyPI, Go, and
# other ecosystems that index by canonical name need the query normalized too —
# ``Flask``/``flask`` and ``ruamel.yaml``/``ruamel-yaml`` are the same package
# (WO6.0.0-006). Applied at index AND lookup so collectors stay raw.
_NORMALIZE_RE = re.compile(r"[-_.]+")


def _normalize_name(name: str) -> str:
    return _NORMALIZE_RE.sub("-", name).lower()


def _cvss_score_to_severity(score: float) -> str:
    # CVSS v3/v4 base-score buckets (spec §7.4): <4 LOW, <7 MEDIUM, <9 HIGH,
    # else CRITICAL. Used when ``database_specific.severity`` is absent and the
    # raw OSV record carries only ``severity: [{type: CVSS_V3, score}]``.
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


@dataclass
class Advisory:
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
    def from_osv(data: dict) -> list[Advisory]:
        """Parse an OSV record into one Advisory per affected package entry.

        Multi-package records (one advisory naming several packages) yield one
        Advisory each, carrying only that entry's ranges/versions — a single
        flattened Advisory would index just the last package while inheriting
        every other package's ranges (WO5.0.0-009).
        """
        adv_id = data.get("id", "")
        summary = data.get("summary", "")
        details = data.get("details", "")
        if not summary and details:
            summary = details[:200]

        severity = "MEDIUM"
        db_specific = data.get("database_specific", {})
        if isinstance(db_specific, dict):
            sev = db_specific.get("severity", "").upper()
            if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                severity = sev
            else:
                # Raw PyPI/Go OSV records often carry only
                # ``severity: [{type: CVSS_V3, score: "CVSS:3.1/AV:.../..."}]``
                # → derive the bucket from the base score so connected-mode
                # queries don't flatten every record to MEDIUM (WO6.0.0-006).
                severity = _severity_from_osv_severity_list(data.get("severity", []))

        advisories: list[Advisory] = []
        for affected in data.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("ecosystem", "").lower() not in _KNOWN_ECOSYSTEMS:
                continue
            pkg_name = pkg.get("name", "")
            if not pkg_name:
                continue

            affected_versions: list[str] = []
            affected_ranges: list[tuple[str, str, bool]] = []
            fixed_version = ""
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
                        affected_ranges.append((introduced, fixed, False))
                    elif last_affected:
                        affected_ranges.append((introduced, last_affected, True))
                    else:
                        affected_ranges.append((introduced, "", False))
                if fixed and not fixed_version:
                    fixed_version = fixed
            for ver in affected.get("versions", []):
                if ver not in affected_versions:
                    affected_versions.append(ver)

            advisories.append(
                Advisory(
                    id=adv_id,
                    package_name=pkg_name,
                    summary=summary,
                    severity=severity,
                    fixed_version=fixed_version,
                    affected_versions=affected_versions,
                    affected_ranges=affected_ranges,
                    cwe_ids=db_specific.get("cwe_ids", []) if isinstance(db_specific, dict) else [],
                    references=[ref.get("url", "") for ref in data.get("references", [])],
                    published=data.get("published", ""),
                    database_specific=db_specific if isinstance(db_specific, dict) else {},
                )
            )

        return advisories


def _severity_from_osv_severity_list(entries: object) -> str:
    """Pick a severity bucket from an OSV record's top-level ``severity`` list.

    Each entry is ``{"type": "CVSS_V3", "score": <score>}`` where ``<score>``
    is either a bare numeric string (the common GitHub-advisory shape, e.g.
    ``"7.5"``) or a full CVSS vector string. We only bucket the numeric form —
    deriving a base score from a CVSS vector needs a vendor library, and
    guessing from the trailing segment misclassifies (``A:H`` is not 8.0).
    Unknown shapes fall back to MEDIUM (the Advisory default), never louder.
    """
    if not isinstance(entries, list):
        return "MEDIUM"
    best = 0.0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if score is None:
            continue
        score_str = str(score).strip()
        try:
            best = max(best, float(score_str))
            continue
        except ValueError:
            # ponytail: CVSS vector strings (``CVSS:3.1/AV:N/...``) need a
            # vendor library to derive the base score; ceiling: fall back to
            # MEDIUM rather than misclassify. Upgrade path: cvss-bsc lib when
            # vector-only records become the dominant connected-mode shape.
            continue
    return _cvss_score_to_severity(best) if best > 0.0 else "MEDIUM"


class AdvisoryDB:
    def __init__(self, db_dir: Path | None = None) -> None:
        self._advisories: dict[str, list[Advisory]] = {}  # pkg_name → advisories
        self._loaded = False
        self._loaded_at: float | None = None  # monotonic timestamp of when DB was loaded
        self._db_dir = db_dir
        if db_dir and db_dir.is_dir():
            self.load(db_dir)

    def load(self, db_dir: Path) -> int:
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

            if isinstance(data, list):
                entries = data
            elif isinstance(data.get("advisories"), list):
                # Bundled-snapshot envelope {"metadata": ..., "advisories": [...]}
                # (corpus/advisories/*.json) — parsing it as a raw OSV record
                # yielded 0 advisories and a silent no-op default check
                # (WO5.0.0-009).
                entries = data["advisories"]
            else:
                entries = [data]

            for entry in entries:
                for adv in Advisory.from_osv(entry):
                    # PEP 503 normalization at index time — collectors stay raw
                    # but the canonical key makes ``Flask``/``flask`` and
                    # ``ruamel.yaml``/``ruamel-yaml`` resolve to one record
                    # (WO6.0.0-006). The Advisory keeps its original
                    # package_name for display; only the key is normalized.
                    key = _normalize_name(adv.package_name)
                    self._advisories.setdefault(key, []).append(adv)
                    count += 1

        self._loaded = True
        self._loaded_at = time.monotonic()
        logger.info("Loaded %d advisories for %d packages", count, len(self._advisories))
        return count

    def check(self, pkg_name: str, pkg_version: str) -> list[Advisory]:
        # PEP 503 normalization at lookup time matches the index key — same
        # ``_normalize_name`` at both ends so ``check('Flask')`` ==
        # ``check('flask')`` and ``ruamel.yaml`` finds the
        # ``ruamel-yaml``-keyed record (WO6.0.0-006).
        advisories = self._advisories.get(_normalize_name(pkg_name), [])
        if not advisories:
            return []

        return [adv for adv in advisories if self._version_affected(pkg_version, adv)]

    def _version_affected(self, version: str, adv: Advisory) -> bool:
        v_tuple = self._parse_version(version)
        if v_tuple is None:
            return False  # Can't parse, assume not affected (conservative)

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
                    elif v_tuple >= uv:
                        continue
            return True

        if not adv.affected_ranges:
            fv_tuple = self._parse_version(adv.fixed_version)
            if fv_tuple and v_tuple < fv_tuple:
                return True

        return any(self._version_in_range(v_tuple, av) for av in adv.affected_versions)

    @staticmethod
    def _parse_version(version_str: str) -> tuple | None:
        if not version_str:
            return None
        m = _SEMVER_RE.search(version_str)
        if not m:
            # Ecosystems commonly use 1- or 2-component versions ("1.30",
            # "9.0"). Normalize to semver by zero-padding the tail so they
            # compare against X.Y.Z ranges instead of failing to parse
            # (unparseable == silently not affected).
            m2 = re.match(r"^v?(\d+)(?:\.(\d+))?$", version_str.strip())
            if not m2:
                return None
            major, minor = int(m2.group(1)), int(m2.group(2) or 0)
            return (major, minor, 0, (1,))
        pre = m.group(4) or ""

        if "+" in pre:
            pre = pre[: pre.index("+")]

        if pre:
            # Tag each identifier so numeric and alphanumeric identifiers are
            # mutually comparable (semver §11: numeric < alphanumeric); a bare
            # int|str mix would raise TypeError on tuple comparison.
            parts: list[tuple[int, int | str]] = []
            for ident in pre.split("."):
                try:
                    parts.append((0, int(ident)))
                except ValueError:
                    parts.append((1, ident))
            pre_tuple = (0, *tuple(parts))
        else:
            pre_tuple = (1,)  # release sorts higher than any pre-release
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre_tuple)

    @staticmethod
    def _version_in_range(v_tuple: tuple, range_str: str) -> bool:
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
        import time

        if self._loaded_at is None:
            return True
        return (time.monotonic() - self._loaded_at) > 86400  # 24 hours


def load_bundled_advisories() -> AdvisoryDB:
    bundled_dir = Path(__file__).parent / "corpus" / "advisories"
    db = AdvisoryDB(bundled_dir if bundled_dir.is_dir() else None)
    if db.advisory_count == 0:
        logger.warning("Bundled advisory snapshot is empty — run scripts/bundle-advisories.py to populate")
    return db


def default_advisory_dir() -> Path:
    import os

    explicit = os.environ.get("PICOSENTRY_ADVISORY_DIR") or os.environ.get("PICOADVISORY_DIR")
    if explicit:
        return Path(explicit)
    return Path.home() / ".local" / "share" / "picosentry" / "advisories"
