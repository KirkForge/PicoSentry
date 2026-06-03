"""
L2-ADV-001: Advisory database vulnerability detection.

Checks installed packages against a local OSV-format advisory database.
Flags packages with known CVEs, GHSA advisories, or npm security advisories.

Pure function: (target_path, corpus_dir) → List[Finding]

Requires: advisory database directory (set via --advisory-db or $PICOADVISORY_DIR).
Without an advisory DB, this rule produces no findings.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from ..advisory import AdvisoryDB, default_advisory_dir
from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

logger = logging.getLogger("picosentry.advisory_check")

__all__ = ["detect_advisory_vulnerabilities"]


def _get_advisory_db(corpus_dir: Path, advisory_db_path: str | None = None) -> AdvisoryDB | None:
    """Get an AdvisoryDB instance, using a module-level cache.

    Search order:
        1. advisory_db_path — explicitly provided (CLI --advisory-db / config)
        2. corpus_dir/advisories/ — if it exists and has content
        3. $PICOADVISORY_DIR env var (via default_advisory_dir())
    """
    # Cache key: (advisory_db_path or "", corpus_dir)
    cache_key = (advisory_db_path or "", str(corpus_dir))
    if cache_key in _advisory_db_cache:
        db = _advisory_db_cache[cache_key]
        if db.is_stale:
            logger.warning("Advisory DB is stale (loaded > 24h ago). Run 'picosentry advisories fetch' to refresh.")
        return db

    # 1. Explicit path takes priority
    if advisory_db_path:
        path = Path(advisory_db_path)
        db = AdvisoryDB(path)
        if db.advisory_count > 0:
            logger.info("Loaded advisory DB from %s: %d advisories", advisory_db_path, db.advisory_count)
            _advisory_db_cache[cache_key] = db
            return db
        logger.warning("Advisory DB at %s has no advisories", advisory_db_path)
        return None

    # 2. Corpus-adjacent advisories
    candidate = corpus_dir / "advisories"
    if candidate.is_dir():
        db = AdvisoryDB(candidate)
        if db.advisory_count > 0:
            logger.info("Loaded advisory DB from corpus: %d advisories", db.advisory_count)
            _advisory_db_cache[cache_key] = db
            return db

    # 3. Default location ($PICOADVISORY_DIR / ~/.local/share/picosentry/advisories)
    default_dir = default_advisory_dir()
    if default_dir.is_dir():
        db = AdvisoryDB(default_dir)
        if db.advisory_count > 0:
            logger.info("Loaded advisory DB from default: %d advisories", db.advisory_count)
            _advisory_db_cache[cache_key] = db
            return db

    return None


def _check_package_against_advisories(
    pkg_name: str,
    pkg_version: str,
    pkg_label: str,
    pkg_json: Path,
    db: AdvisoryDB,
) -> list[Finding]:
    """Check a single package against the advisory database."""
    findings: list[Finding] = []

    advisories = db.check(pkg_name, pkg_version)
    if not advisories:
        return findings

    for adv in advisories:
        severity = Severity.HIGH
        with contextlib.suppress(ValueError):
            severity = Severity(adv.severity)

        fixed_hint = f" Upgrade to >= {adv.fixed_version}." if adv.fixed_version else ""

        findings.append(
            Finding(
                rule_id="L2-ADV-001",
                severity=severity,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=f"{adv.id}: {adv.summary}",
                evidence=f"advisory={adv.id}, severity={adv.severity}, fixed={adv.fixed_version or 'N/A'}",
                remediation=f"Vulnerability in {pkg_name}@{pkg_version}.{fixed_hint} See {adv.references[0] if adv.references else 'advisory database'} for details.",
                references=adv.references[:5] if adv.references else [],
            )
        )

    return findings


def detect_advisory_vulnerabilities(
    target: Path, corpus_dir: Path, advisory_db_path: str | None = None
) -> list[Finding]:
    """
    Detect packages with known security advisories.

    Loads advisory database from local files. No network calls.
    Without an advisory DB, returns empty list.
    """
    findings: list[Finding] = []

    db = _get_advisory_db(corpus_dir, advisory_db_path)
    if db is None:
        logger.debug("No advisory DB loaded — skipping advisory check")
        return findings

    # Check root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            pkg_name = pkg.get("name", "root")
            pkg_version = pkg.get("version", "unknown")
            pkg_label = f"{pkg_name}@{pkg_version}"
            findings.extend(_check_package_against_advisories(pkg_name, pkg_version, pkg_label, root_pkg, db))

    # Check all node_modules packages
    for pkg_json, pkg in iter_node_modules(target):
        pkg_name = pkg.get("name", pkg_json.parent.name)
        pkg_version = pkg.get("version", "unknown")
        pkg_label = f"{pkg_name}@{pkg_version}"

        findings.extend(_check_package_against_advisories(pkg_name, pkg_version, pkg_label, pkg_json, db))

    return findings


# Module-level advisory DB cache to avoid re-reading all advisory JSON
# files from disk on every call to detect_advisory_vulnerabilities.
_advisory_db_cache: dict[tuple[str, str], AdvisoryDB] = {}
