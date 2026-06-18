from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..advisory import AdvisoryDB, default_advisory_dir
from ..models import Confidence, Finding, Severity
from .cargo_utils import detect_cargo_project, parse_cargo_lock, parse_cargo_toml
from .go_utils import detect_go_project, parse_go_mod, parse_go_sum
from .maven_utils import detect_maven_project, parse_gradle_build, parse_pom_xml
from .nuget_utils import collect_nuget_deps, detect_nuget_project
from .pypi_lock_parser import parse_poetry_lock, parse_requirements_txt, parse_uv_lock
from .pypi_utils import detect_pypi_project, iter_site_packages, load_pyproject_toml
from .rubygems_utils import detect_rubygems_project, parse_gemfile, parse_gemfile_lock
from .utils import iter_node_modules, load_package_json

logger = logging.getLogger("picosentry.advisory_check")

__all__ = ["detect_all_advisory_vulnerabilities"]


_advisory_db_cache: dict[tuple[str, str], tuple[AdvisoryDB, float]] = {}


def _get_advisory_db(corpus_dir: Path, advisory_db_path: str | None = None) -> AdvisoryDB | None:
    import time
    cache_key = (advisory_db_path or "", str(corpus_dir))
    if cache_key in _advisory_db_cache:
        db, load_time = _advisory_db_cache[cache_key]
        if time.time() - load_time > 86400:
            logger.warning("Advisory DB is stale (loaded > 24h ago). Run 'picosentry advisories fetch' to refresh.")
        return db


    if advisory_db_path:
        path = Path(advisory_db_path)
        db = AdvisoryDB(path)
        if db.advisory_count > 0:
            logger.info("Loaded advisory DB from %s: %d advisories", advisory_db_path, db.advisory_count)
            _advisory_db_cache[cache_key] = (db, time.time())
            return db
        logger.warning("Advisory DB at %s has no advisories", advisory_db_path)
        return None


    candidate = corpus_dir / "advisories"
    if candidate.is_dir():
        db = AdvisoryDB(candidate)
        if db.advisory_count > 0:
            logger.info("Loaded advisory DB from corpus: %d advisories", db.advisory_count)
            _advisory_db_cache[cache_key] = (db, time.time())
            return db


    default_dir = default_advisory_dir()
    if default_dir.is_dir():
        db = AdvisoryDB(default_dir)
        if db.advisory_count > 0:
            logger.info("Loaded advisory DB from default: %d advisories", db.advisory_count)
            _advisory_db_cache[cache_key] = (db, time.time())
            return db

    return None


@dataclass(frozen=True)
class AdvisoryConfig:

    ecosystem: str
    rule_id: str
    detect_project: Callable[[Path], bool]
    collect_packages: Callable[[Path], list[tuple[str, str, str, Path]]]

    def __hash__(self):
        return hash(self.ecosystem)


def _collect_npm_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    packages: list[tuple[str, str, str, Path]] = []

    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            pkg_name = pkg.get("name", "root")
            pkg_version = pkg.get("version", "unknown")
            packages.append((pkg_name, pkg_version, f"{pkg_name}@{pkg_version}", root_pkg))

    for pkg_json, pkg in iter_node_modules(target):
        pkg_name = pkg.get("name", pkg_json.parent.name)
        pkg_version = pkg.get("version", "unknown")
        packages.append((pkg_name, pkg_version, f"{pkg_name}@{pkg_version}", pkg_json))

    return packages


def _collect_go_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    go_mod_data = parse_go_mod(target)
    if go_mod_data:
        for mod_path, version in go_mod_data.get("require", []):
            if mod_path and version and (mod_path, version) not in seen:
                seen.add((mod_path, version))
                packages.append((mod_path, version, f"{mod_path}@{version}", target / "go.mod"))
        for mod_path, version in go_mod_data.get("indirect", []):
            if mod_path and version and (mod_path, version) not in seen:
                seen.add((mod_path, version))
                packages.append((mod_path, version, f"{mod_path}@{version}", target / "go.mod"))

    go_sum_entries = parse_go_sum(target)
    for mod_path, version, _hash_val in go_sum_entries:
        if mod_path and version and (mod_path, version) not in seen:
            seen.add((mod_path, version))
            packages.append((mod_path, version, f"{mod_path}@{version}", target / "go.sum"))

    return packages


def _collect_cargo_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    cargo_data = parse_cargo_toml(target)
    if cargo_data:
        for section_name in ("dependencies", "dev_dependencies", "build_dependencies"):
            deps = cargo_data.get(section_name, {})
            for crate_name, version in deps.items():
                if crate_name and version and (crate_name, str(version)) not in seen:
                    seen.add((crate_name, str(version)))
                    packages.append((crate_name, str(version), f"{crate_name}@{version}", target / "Cargo.toml"))

    cargo_lock_pkgs = parse_cargo_lock(target)
    if cargo_lock_pkgs:
        for pkg in cargo_lock_pkgs:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version and (name, version) not in seen:
                seen.add((name, version))
                packages.append((name, version, f"{name}@{version}", target / "Cargo.lock"))

    return packages


def _collect_pypi_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    for meta_path, metadata in iter_site_packages(target):
        name = metadata.get("name", "")
        version = metadata.get("version", "")
        if name and version and (name, version) not in seen:
            seen.add((name, version))
            packages.append((name, version, f"{name}@{version}", meta_path))

    project_data = load_pyproject_toml(target)
    if project_data:
        project_section = project_data.get("project", project_data)
        deps = project_section.get("dependencies", [])
        if isinstance(deps, list):
            for dep in deps:

                if isinstance(dep, str) and dep:
                    name = dep.split(">")[0].split("<")[0].split("=")[0].split("!")[0].strip()
                    if name and (name, "unknown") not in seen:
                        seen.add((name, "unknown"))
                        packages.append((name, "unknown", f"{name}@unknown", target / "pyproject.toml"))


    for lock_parser, lock_file in [
        (parse_poetry_lock, "poetry.lock"),
        (parse_requirements_txt, "requirements.txt"),
        (parse_uv_lock, "uv.lock"),
    ]:
        lock_path = target / lock_file
        if lock_path.exists():
            try:
                for name, version, _extras in lock_parser(lock_path):
                    if name and version and (name, version) not in seen:
                        seen.add((name, version))
                        packages.append((name, version, f"{name}@{version}", lock_path))
            except Exception:
                continue

    return packages


def _collect_maven_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    pom_data = parse_pom_xml(target)
    if pom_data:
        for dep in pom_data.get("dependencies", []):
            group_id, artifact_id, version, _scope = dep if len(dep) == 4 else (dep[0], dep[1], dep[2], "")

            pkg_key = artifact_id
            if pkg_key and version and (pkg_key, version) not in seen:
                seen.add((pkg_key, version))
                packages.append((pkg_key, version, f"{group_id}:{artifact_id}@{version}", target / "pom.xml"))

    gradle_data = parse_gradle_build(target)
    if gradle_data:
        for dep in gradle_data.get("dependencies", []):
            group, artifact, version = dep if len(dep) >= 3 else (dep[0], dep[1], "")
            pkg_key = f"{group}:{artifact}"
            if pkg_key and version and (pkg_key, version) not in seen:
                seen.add((pkg_key, version))
                packages.append((pkg_key, version, f"{pkg_key}@{version}", target / "build.gradle"))

    return packages


def _collect_nuget_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    for pkg_id, version, source in collect_nuget_deps(target):
        if pkg_id and version and (pkg_id, version) not in seen:
            seen.add((pkg_id, version))
            src = Path(source) if source else target
            packages.append((pkg_id, version, f"{pkg_id}@{version}", src))

    return packages


def _collect_rubygems_packages(target: Path) -> list[tuple[str, str, str, Path]]:
    packages: list[tuple[str, str, str, Path]] = []
    seen: set[tuple[str, str]] = set()

    gemfile_data = parse_gemfile(target)
    if gemfile_data:

        for entry in gemfile_data.get("dependencies", []):
            if not isinstance(entry, tuple) or len(entry) < 2:
                continue
            gem_name, version = entry[0], entry[1]
            if gem_name and version and (gem_name, str(version)) not in seen:
                seen.add((gem_name, str(version)))
                packages.append((gem_name, str(version), f"{gem_name}@{version}", target / "Gemfile"))

    lock_data = parse_gemfile_lock(target)
    if lock_data:
        for entry in lock_data:
            name = entry.get("name", "")
            version = entry.get("version", "")
            if name and version and (name, version) not in seen:
                seen.add((name, version))
                packages.append((name, version, f"{name}@{version}", target / "Gemfile.lock"))

    return packages


def _check_packages(
    packages: list[tuple[str, str, str, Path]],
    db: AdvisoryDB,
    config: AdvisoryConfig,
) -> list[Finding]:
    findings: list[Finding] = []

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
                    rule_id=config.rule_id,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(source_path),
                    message=f"{adv.id}: {adv.summary}",
                    evidence=f"advisory={adv.id}, severity={adv.severity}, fixed={adv.fixed_version or 'N/A'}",
                    remediation=(
                        f"Vulnerability in {pkg_name}@{pkg_version}.{fixed_hint} "
                        f"See {adv.references[0] if adv.references else 'advisory database'} for details."
                    ),
                    references=adv.references[:5] if adv.references else [],
                    ecosystem=config.ecosystem,
                )
            )

    return findings


_ECOSYSTEMS: list[AdvisoryConfig] = [
    AdvisoryConfig(
        ecosystem="npm",
        rule_id="L2-ADV-001",
        detect_project=lambda p: (p / "package.json").exists(),
        collect_packages=_collect_npm_packages,
    ),
    AdvisoryConfig(
        ecosystem="go",
        rule_id="L2-GO-ADV-001",
        detect_project=detect_go_project,
        collect_packages=_collect_go_packages,
    ),
    AdvisoryConfig(
        ecosystem="cargo",
        rule_id="L2-CARGO-ADV-001",
        detect_project=detect_cargo_project,
        collect_packages=_collect_cargo_packages,
    ),
    AdvisoryConfig(
        ecosystem="pypi",
        rule_id="L2-PYPI-ADV-001",
        detect_project=detect_pypi_project,
        collect_packages=_collect_pypi_packages,
    ),
    AdvisoryConfig(
        ecosystem="maven",
        rule_id="L2-MAVEN-ADV-001",
        detect_project=detect_maven_project,
        collect_packages=_collect_maven_packages,
    ),
    AdvisoryConfig(
        ecosystem="nuget",
        rule_id="L2-NUGET-ADV-001",
        detect_project=detect_nuget_project,
        collect_packages=_collect_nuget_packages,
    ),
    AdvisoryConfig(
        ecosystem="rubygems",
        rule_id="L2-RUBYGEMS-ADV-001",
        detect_project=detect_rubygems_project,
        collect_packages=_collect_rubygems_packages,
    ),
]


def detect_all_advisory_vulnerabilities(
    target: Path, corpus_dir: Path, advisory_db_path: str | None = None
) -> list[Finding]:
    findings: list[Finding] = []

    db = _get_advisory_db(corpus_dir, advisory_db_path)
    if db is None:
        logger.debug("No advisory DB loaded — skipping advisory check")
        return findings

    for config in _ECOSYSTEMS:
        if not config.detect_project(target):
            continue
        packages = config.collect_packages(target)
        if packages:
            findings.extend(_check_packages(packages, db, config))

    return findings
