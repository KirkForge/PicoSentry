"""
L2-NUGET-ADV-001: NuGet package advisory database vulnerability detection.

Checks .NET package dependencies against a local OSV-format advisory database.
Flags packages with known CVEs or security advisories.

Pure function: (target_path, corpus_dir) -> List[Finding]

Follows the same pattern as Go/npm/Cargo advisory check but for the NuGet ecosystem.
.NET packages use the "NuGet" ecosystem in OSV format.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from ..advisory import AdvisoryDB, default_advisory_dir
from ..models import Confidence, Finding, Severity
from .nuget_utils import (
    collect_nuget_deps,
    detect_nuget_project,
)

logger = logging.getLogger("picosentry.nuget_advisory_check")

__all__ = ["detect_nuget_advisory_vulnerabilities"]

_advisory_db_cache: dict[tuple[str, str], AdvisoryDB] = {}


def _get_advisory_db(corpus_dir: Path, advisory_db_path: str | None = None) -> AdvisoryDB | None:
    """Get an AdvisoryDB instance, loading from the best available source."""
    cache_key = (advisory_db_path or "", str(corpus_dir))
    if cache_key in _advisory_db_cache:
        return _advisory_db_cache[cache_key]

    db: AdvisoryDB | None = None

    if advisory_db_path:
        path = Path(advisory_db_path)
        db_candidate = AdvisoryDB(path)
        if db_candidate.advisory_count > 0:
            logger.info("Loaded advisory DB from %s: %d advisories", advisory_db_path, db_candidate.advisory_count)
            db = db_candidate

    if db is None:
        candidate = corpus_dir / "advisories"
        if candidate.is_dir():
            db_candidate = AdvisoryDB(candidate)
            if db_candidate.advisory_count > 0:
                logger.info("Loaded advisory DB from corpus: %d advisories", db_candidate.advisory_count)
                db = db_candidate

    if db is None:
        default_dir = default_advisory_dir()
        if default_dir.is_dir():
            db_candidate = AdvisoryDB(default_dir)
            if db_candidate.advisory_count > 0:
                logger.info("Loaded advisory DB from default: %d advisories", db_candidate.advisory_count)
                db = db_candidate

    if db is not None:
        _advisory_db_cache[cache_key] = db
    return db


def _get_nuget_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    """Collect all (name, version, label, source_path) tuples for a NuGet project."""
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    deps = collect_nuget_deps(target)
    for pkg_id, version, source in deps:
        if pkg_id and version and (pkg_id, version) not in seen:
            seen.add((pkg_id, version))
            packages.append((pkg_id, version, f"{pkg_id}@{version}", target / source))

    return packages


def detect_nuget_advisory_vulnerabilities(
    target: Path, corpus_dir: Path, advisory_db_path: str | None = None
) -> list[Finding]:
    """
    Detect .NET packages with known security advisories.

    Loads advisory database from local files. No network calls.
    Without an advisory DB, returns empty list.
    """
    findings: list[Finding] = []

    if not detect_nuget_project(target):
        return findings

    db = _get_advisory_db(corpus_dir, advisory_db_path)
    if db is None:
        logger.debug("No advisory DB loaded — skipping NuGet advisory check")
        return findings

    packages = _get_nuget_packages(target)

    for pkg_name, pkg_version, pkg_label, source_path in packages:
        advisories = db.check(pkg_name, pkg_version)
        if not advisories:
            continue

        for adv in advisories:
            severity = Severity.HIGH
            with contextlib.suppress(ValueError):
                severity = Severity(adv.severity)

            fixed_hint = f" Upgrade to >= {adv.fixed_version}." if adv.fixed_version else ""

            findings.append(
                Finding(
                    rule_id="L2-NUGET-ADV-001",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(source_path),
                    message=f"{adv.id}: {adv.summary}",
                    evidence=f"advisory={adv.id}, severity={adv.severity}, fixed={adv.fixed_version or 'N/A'}",
                    remediation=f"Vulnerability in {pkg_name}@{pkg_version}.{fixed_hint} See {adv.references[0] if adv.references else 'advisory database'} for details.",
                    references=adv.references[:5] if adv.references else [],
                    ecosystem="nuget",
                )
            )

    return findings