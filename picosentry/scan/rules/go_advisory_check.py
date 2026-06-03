"""
L2-GO-ADV-001: Go module advisory database vulnerability detection.

Checks Go module dependencies against a local OSV-format advisory database.
Flags modules with known CVEs or Go security advisories.

Pure function: (target_path, corpus_dir) -> List[Finding]

Follows the same pattern as npm/PyPI advisory check but for the Go ecosystem.
Go modules use the "Go" ecosystem in OSV format.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from ..advisory import AdvisoryDB, default_advisory_dir
from ..models import Confidence, Finding, Severity
from .go_utils import detect_go_project, parse_go_mod, parse_go_sum

logger = logging.getLogger("picosentry.go_advisory_check")

__all__ = ["detect_go_advisory_vulnerabilities"]


def _get_advisory_db(corpus_dir: Path, advisory_db_path: str | None = None) -> AdvisoryDB | None:
    """Get an AdvisoryDB instance, loading from the best available source.

    Search order:
        1. advisory_db_path (explicit — CLI --advisory-db)
        2. corpus_dir/advisories/ (shipped with the package or downloaded)
        3. Default location ($PICOADVISORY_DIR)
    """
    # Check advisory DB cache first
    cache_key = (advisory_db_path or "", str(corpus_dir))
    if cache_key in _advisory_db_cache:
        return _advisory_db_cache[cache_key]

    db: AdvisoryDB | None = None

    # 1. Explicit path takes priority
    if advisory_db_path:
        path = Path(advisory_db_path)
        db_candidate = AdvisoryDB(path)
        if db_candidate.advisory_count > 0:
            logger.info("Loaded advisory DB from %s: %d advisories", advisory_db_path, db_candidate.advisory_count)
            db = db_candidate

    if db is None:
        # 2. Corpus-adjacent advisories
        candidate = corpus_dir / "advisories"
        if candidate.is_dir():
            db_candidate = AdvisoryDB(candidate)
            if db_candidate.advisory_count > 0:
                logger.info("Loaded advisory DB from corpus: %d advisories", db_candidate.advisory_count)
                db = db_candidate

    if db is None:
        # 3. Default location
        default_dir = default_advisory_dir()
        if default_dir.is_dir():
            db_candidate = AdvisoryDB(default_dir)
            if db_candidate.advisory_count > 0:
                logger.info("Loaded advisory DB from default: %d advisories", db_candidate.advisory_count)
                db = db_candidate

    if db is not None:
        _advisory_db_cache[cache_key] = db
    return db


def _get_go_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    """Collect all (name, version, label, source_path) tuples for a Go project.

    Gathers from:
    - go.mod (declared dependencies with version constraints)
    - go.sum (pinned versions with content hashes)
    """
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    # From go.mod direct and indirect deps
    go_mod_data = parse_go_mod(target)
    if go_mod_data:
        # Direct deps
        for mod_path, version in go_mod_data.get("require", []):
            if mod_path and version and (mod_path, version) not in seen:
                seen.add((mod_path, version))
                packages.append((mod_path, version, f"{mod_path}@{version}", target / "go.mod"))

        # Indirect deps
        for mod_path, version in go_mod_data.get("indirect", []):
            if mod_path and version and (mod_path, version) not in seen:
                seen.add((mod_path, version))
                packages.append((mod_path, version, f"{mod_path}@{version}", target / "go.mod"))

    # From go.sum (more versions may be listed)
    go_sum_entries = parse_go_sum(target)
    for mod_path, version, _hash_val in go_sum_entries:
        if mod_path and version and (mod_path, version) not in seen:
            seen.add((mod_path, version))
            packages.append((mod_path, version, f"{mod_path}@{version}", target / "go.sum"))

    return packages


def detect_go_advisory_vulnerabilities(
    target: Path, corpus_dir: Path, advisory_db_path: str | None = None
) -> list[Finding]:
    """
    Detect Go modules with known security advisories.

    Loads advisory database from local files. No network calls.
    Without an advisory DB, returns empty list.
    """
    findings: list[Finding] = []

    if not detect_go_project(target):
        return findings

    db = _get_advisory_db(corpus_dir, advisory_db_path)
    if db is None:
        logger.debug("No advisory DB loaded — skipping Go advisory check")
        return findings

    packages = _get_go_packages(target)

    for mod_path, mod_version, pkg_label, source_path in packages:
        advisories = db.check(mod_path, mod_version)
        if not advisories:
            continue

        for adv in advisories:
            severity = Severity.HIGH
            with contextlib.suppress(ValueError):
                severity = Severity(adv.severity)

            fixed_hint = f" Upgrade to >= {adv.fixed_version}." if adv.fixed_version else ""

            findings.append(
                Finding(
                    rule_id="L2-GO-ADV-001",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(source_path),
                    message=f"{adv.id}: {adv.summary}",
                    evidence=f"advisory={adv.id}, severity={adv.severity}, fixed={adv.fixed_version or 'N/A'}",
                    remediation=f"Vulnerability in {mod_path}@{mod_version}.{fixed_hint} See {adv.references[0] if adv.references else 'advisory database'} for details.",
                    references=adv.references[:5] if adv.references else [],
                    ecosystem="go",
                )
            )

    return findings


_advisory_db_cache: dict[tuple[str, str], AdvisoryDB] = {}