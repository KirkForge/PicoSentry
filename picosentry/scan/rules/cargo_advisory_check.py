"""
L2-CARGO-ADV-001: Cargo crate advisory database vulnerability detection.

Checks Rust crate dependencies against a local OSV-format advisory database.
Flags crates with known CVEs or Rust security advisories.

Pure function: (target_path, corpus_dir) -> List[Finding]

Follows the same pattern as Go/npm/PyPI advisory check but for the Cargo ecosystem.
Rust crates use the "cargo" ecosystem in OSV format (also known as "crates.io").
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from ..advisory import AdvisoryDB, default_advisory_dir
from ..models import Confidence, Finding, Severity
from .cargo_utils import detect_cargo_project, parse_cargo_lock, parse_cargo_toml

logger = logging.getLogger("picosentry.cargo_advisory_check")

__all__ = ["detect_cargo_advisory_vulnerabilities"]


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


def _get_cargo_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    """Collect all (name, version, label, source_path) tuples for a Cargo project.

    Gathers from:
    - Cargo.toml (declared dependencies with version constraints)
    - Cargo.lock (pinned versions with source identifiers)
    """
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    # From Cargo.toml dependencies
    cargo_data = parse_cargo_toml(target)
    if cargo_data:
        for section_name, deps in [("dependencies", cargo_data.get("dependencies", {})),
                                     ("dev_dependencies", cargo_data.get("dev_dependencies", {})),
                                     ("build_dependencies", cargo_data.get("build_dependencies", {}))]:
            for crate_name, version in deps.items():
                if crate_name and version and (crate_name, str(version)) not in seen:
                    seen.add((crate_name, str(version)))
                    packages.append((crate_name, str(version), f"{crate_name}@{version}", target / "Cargo.toml"))

    # From Cargo.lock (more precise versions)
    cargo_lock_pkgs = parse_cargo_lock(target)
    if cargo_lock_pkgs:
        for pkg in cargo_lock_pkgs:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version and (name, version) not in seen:
                seen.add((name, version))
                packages.append((name, version, f"{name}@{version}", target / "Cargo.lock"))

    return packages


def detect_cargo_advisory_vulnerabilities(
    target: Path, corpus_dir: Path, advisory_db_path: str | None = None
) -> list[Finding]:
    """
    Detect Rust crates with known security advisories.

    Loads advisory database from local files. No network calls.
    Without an advisory DB, returns empty list.
    """
    findings: list[Finding] = []

    if not detect_cargo_project(target):
        return findings

    db = _get_advisory_db(corpus_dir, advisory_db_path)
    if db is None:
        logger.debug("No advisory DB loaded — skipping Cargo advisory check")
        return findings

    packages = _get_cargo_packages(target)

    for crate_name, crate_version, pkg_label, source_path in packages:
        advisories = db.check(crate_name, crate_version)
        if not advisories:
            continue

        for adv in advisories:
            severity = Severity.HIGH
            with contextlib.suppress(ValueError):
                severity = Severity(adv.severity)

            fixed_hint = f" Upgrade to >= {adv.fixed_version}." if adv.fixed_version else ""

            findings.append(
                Finding(
                    rule_id="L2-CARGO-ADV-001",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(source_path),
                    message=f"{adv.id}: {adv.summary}",
                    evidence=f"advisory={adv.id}, severity={adv.severity}, fixed={adv.fixed_version or 'N/A'}",
                    remediation=f"Vulnerability in {crate_name}@{crate_version}.{fixed_hint} See {adv.references[0] if adv.references else 'advisory database'} for details.",
                    references=adv.references[:5] if adv.references else [],
                    ecosystem="cargo",
                )
            )

    return findings


_advisory_db_cache: dict[tuple[str, str], AdvisoryDB] = {}