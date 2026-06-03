"""
L2-PYPI-ADV-001: PyPI advisory database vulnerability detection.

Checks installed Python packages against a local OSV-format advisory database.
Flags packages with known CVEs, GHSA advisories, or PyPI security advisories.

Pure function: (target_path, corpus_dir) -> List[Finding]

Follows the same pattern as npm advisory_check but for the PyPI ecosystem.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from ..advisory import AdvisoryDB, default_advisory_dir
from ..models import Confidence, Finding, Severity
from .pypi_lock_parser import parse_poetry_lock, parse_requirements_txt, parse_uv_lock
from .pypi_utils import detect_pypi_project, iter_site_packages, load_pyproject_toml

logger = logging.getLogger("picosentry.pypi_advisory_check")

__all__ = ["detect_pypi_advisory_vulnerabilities"]


def _get_advisory_db(corpus_dir: Path, advisory_db_path: str | None = None) -> AdvisoryDB | None:
    """Get an AdvisoryDB instance, loading from the best available source.

    Search order:
        1. advisory_db_path (explicit — CLI --advisory-db)
        2. corpus_dir/advisories/ (shipped with the package or downloaded)
        3. Default location ($PICOADVISORY_DIR)
    """
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


def _get_pypi_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    """Collect all (name, version, label, source_path) tuples for a PyPI project.

    Gathers from:
    - site-packages (installed packages)
    - lockfiles (declared packages)
    - pyproject.toml (project metadata)
    """
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    # From site-packages (exact installed versions)
    for meta_path, metadata in iter_site_packages(target):
        if metadata:
            name = metadata.get("name", "")
            version = metadata.get("version", "")
            if name and version and (name, version) not in seen:
                seen.add((name, version))
                packages.append((name, version, f"{name}@{version}", meta_path))

    # From lockfiles
    for lockfile_name in ("poetry.lock", "uv.lock", "requirements.txt"):
        lockfile = target / lockfile_name
        if lockfile.is_file():
            parser_map = {
                "poetry.lock": parse_poetry_lock,
                "uv.lock": parse_uv_lock,
                "requirements.txt": parse_requirements_txt,
            }
            parser = parser_map.get(lockfile_name)
            if parser:
                entries = parser(lockfile)
                for name, version, extras in entries:
                    if version and version != "*" and (name, version) not in seen:
                        seen.add((name, version))
                        packages.append((name, version, f"{name}@{version}", lockfile))

    # From pyproject.toml project name/version
    project_data = load_pyproject_toml(target)
    if project_data:
        proj = project_data.get("project", project_data)
        name = proj.get("name", "")
        version = proj.get("version", "")
        if isinstance(name, str) and isinstance(version, str) and name and version:
            if (name, version) not in seen:
                seen.add((name, version))
                packages.append((name, version, f"{name}@{version}", target / "pyproject.toml"))

    return packages


def detect_pypi_advisory_vulnerabilities(
    target: Path, corpus_dir: Path, advisory_db_path: str | None = None
) -> list[Finding]:
    """
    Detect Python packages with known security advisories.

    Loads advisory database from local files. No network calls.
    Without an advisory DB, returns empty list.
    """
    findings: list[Finding] = []

    if not detect_pypi_project(target):
        return findings

    db = _get_advisory_db(corpus_dir, advisory_db_path)
    if db is None:
        logger.debug("No advisory DB loaded — skipping PyPI advisory check")
        return findings

    packages = _get_pypi_packages(target)

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
                    rule_id="L2-PYPI-ADV-001",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(source_path),
                    message=f"{adv.id}: {adv.summary}",
                    evidence=f"advisory={adv.id}, severity={adv.severity}, fixed={adv.fixed_version or 'N/A'}",
                    remediation=f"Vulnerability in {pkg_name}@{pkg_version}.{fixed_hint} See {adv.references[0] if adv.references else 'advisory database'} for details.",
                    references=adv.references[:5] if adv.references else [],
                    ecosystem="pypi",
                )
            )

    return findings


_advisory_db_cache: dict[tuple[str, str], AdvisoryDB] = {}