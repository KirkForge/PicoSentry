from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding
from .cargo_utils import detect_cargo_project, get_cargo_dep_names, parse_cargo_toml
from .go_utils import detect_go_project, get_module_short_name, parse_go_mod
from .maven_utils import detect_maven_project, get_maven_dep_identifiers, parse_gradle_build, parse_pom_xml
from .nuget_utils import detect_nuget_project, get_nuget_dep_names, parse_csproj_file, parse_packages_config
from .pypi_utils import (
    detect_pypi_project,
    get_python_dep_names,
    iter_site_packages,
    load_pyproject_toml,
    parse_requirements_file,
)
from .rubygems_utils import detect_rubygems_project, get_rubygems_dep_names, parse_gemfile
from .typosquat_utils import (
    BUILTIN_CARGO_TOP_100,
    BUILTIN_GO_TOP_100,
    BUILTIN_MAVEN_TOP_100,
    BUILTIN_NUGET_TOP_100,
    BUILTIN_PYPI_TOP_100,
    BUILTIN_RUBYGEMS_TOP_100,
    BUILTIN_TOP_100,
    check_typosquat,
    load_corpus_for_ecosystem,
    typosquat_severity_confidence,
)
from .utils import get_dep_names, load_package_json

logger = logging.getLogger("picosentry.typosquat")

__all__ = ["detect_all_typosquat"]


@dataclass(frozen=True)
class TyposquatConfig:

    ecosystem: str
    rule_id: str
    detect_project: Callable[[Path], bool]
    builtin_corpus: list[str]
    known_legitimate: frozenset[str] = field(default_factory=frozenset)

    use_short_name: bool = False

    manifest_file: str = ""

    collect_deps: Callable[[Path], set[str]] | None = None

    file_detection_fn: Callable[[Path], str] | None = None

    def __hash__(self):
        return hash(self.ecosystem)


def _detect_all_typosquat_standard(target: Path, corpus_dir: Path, config: TyposquatConfig) -> list[Finding]:
    findings: list[Finding] = []

    if not config.detect_project(target):
        return findings

    corpus = load_corpus_for_ecosystem(corpus_dir, config.ecosystem, config.builtin_corpus)

    all_deps = config.collect_deps(target) if config.collect_deps else set()
    if not all_deps:
        return findings

    for dep_name in sorted(all_deps):
        compare_name = dep_name
        if config.use_short_name:
            compare_name = get_module_short_name(dep_name)
            if not compare_name:
                continue

        if not compare_name or compare_name in config.known_legitimate:
            continue


        if compare_name in corpus:
            continue

        close_matches = check_typosquat(compare_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(compare_name, best_match, best_dist)

            manifest_path = config.manifest_file
            if config.file_detection_fn:
                manifest_path = config.file_detection_fn(target)
            elif manifest_path and not manifest_path.startswith("/"):
                manifest_path = str(target / manifest_path)

            if config.use_short_name:
                message = (
                    f"Go module '{dep_name}' (short name: {compare_name}) "
                    f"may be a typosquat of popular package '{best_match}'"
                )
            else:
                message = (
                    f"{config.ecosystem.capitalize()} package '{dep_name}' may be a typosquat "
                    f"of popular package '{best_match}'"
                )

            findings.append(
                Finding(
                    rule_id=config.rule_id,
                    severity=severity,
                    confidence=confidence,
                    package=dep_name,
                    file=manifest_path if isinstance(manifest_path, str) else str(manifest_path),
                    message=message,
                    evidence=f"edit_distance({compare_name}, {best_match}) = {best_dist}",
                    remediation=(
                        f"Verify that '{dep_name}' is the intended package, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the source and author before installing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks/",
                    ],
                    ecosystem=config.ecosystem,
                )
            )

    return findings


def _collect_go_deps(target: Path) -> set[str]:
    deps: set[str] = set()
    go_mod_data = parse_go_mod(target)
    if not go_mod_data:
        return deps
    module_name = go_mod_data.get("module", "")
    if module_name:
        deps.add(module_name)
    for mod_path, _version in go_mod_data.get("require", []):
        if mod_path:
            deps.add(mod_path)
    for mod_path, _version in go_mod_data.get("indirect", []):
        if mod_path:
            deps.add(mod_path)
    return deps


def _collect_cargo_deps(target: Path) -> set[str]:
    deps: set[str] = set()
    cargo_data = parse_cargo_toml(target)
    if cargo_data:
        deps.update(get_cargo_dep_names(cargo_data))

        pkg_name = cargo_data.get("package_name", "")
        if isinstance(pkg_name, str) and pkg_name:
            deps.add(pkg_name)
    return deps


def _collect_pypi_deps(target: Path) -> set[str]:
    deps: set[str] = set()
    project_data = load_pyproject_toml(target)
    if project_data:
        project_section = project_data.get("project", project_data)
        deps.update(get_python_dep_names(project_section))

        pkg_name = project_section.get("name", "")
        if isinstance(pkg_name, str) and pkg_name:
            deps.add(pkg_name)
    for req_file in ("requirements.txt", "requirements-dev.txt"):
        req_path = target / req_file
        if req_path.is_file():
            for name, _version in parse_requirements_file(req_path):
                deps.add(name)
    for _meta_path, metadata in iter_site_packages(target):
        deps.update(get_python_dep_names(metadata))
    return deps


def _collect_maven_deps(target: Path) -> set[str]:
    deps: set[str] = set()
    pom_data = parse_pom_xml(target)
    if pom_data:
        deps.update(get_maven_dep_identifiers(pom_data))

        artifact_id = pom_data.get("artifact_id", "")
        if isinstance(artifact_id, str) and artifact_id:
            deps.add(artifact_id)
    gradle_data = parse_gradle_build(target)
    if gradle_data:
        deps.update(get_maven_dep_identifiers(gradle_data))
    return deps


def _collect_nuget_deps(target: Path) -> set[str]:
    deps: set[str] = set()
    csproj_data = parse_csproj_file(target)
    if csproj_data:
        deps.update(get_nuget_dep_names(csproj_data))
    config_packages = parse_packages_config(target)
    if config_packages:
        deps.update(get_nuget_dep_names(config_packages))
    return deps


def _collect_rubygems_deps(target: Path) -> set[str]:
    gemfile_data = parse_gemfile(target)
    if gemfile_data:
        return get_rubygems_dep_names(gemfile_data)
    return set()


def _maven_finding_file(target: Path) -> str:
    pom = target / "pom.xml"
    if pom.exists():
        return str(pom)
    gradle = target / "build.gradle"
    if gradle.exists():
        return str(gradle)
    return str(target)


def _nuget_finding_file(target: Path) -> str:
    for f in sorted(target.iterdir()):
        if f.suffix == ".csproj":
            return str(f)
    if (target / "packages.config").exists():
        return str(target / "packages.config")
    return str(target)


def _pypi_finding_file(target: Path) -> str:
    if (target / "pyproject.toml").exists():
        return str(target / "pyproject.toml")
    return str(target)


_GO_CONFIG = TyposquatConfig(
    ecosystem="go",
    rule_id="L2-GO-TYPO-001",
    detect_project=detect_go_project,
    builtin_corpus=BUILTIN_GO_TOP_100,
    known_legitimate=frozenset({
        "x", "v2", "v3", "api", "client", "server",
        "internal", "cmd", "pkg",
    }),
    use_short_name=True,
    manifest_file="go.mod",
    collect_deps=_collect_go_deps,
)

_CARGO_CONFIG = TyposquatConfig(
    ecosystem="cargo",
    rule_id="L2-CARGO-TYPO-001",
    detect_project=detect_cargo_project,
    builtin_corpus=BUILTIN_CARGO_TOP_100,
    known_legitimate=frozenset({
        "x", "v2", "v3", "api", "client", "server",
        "core", "sys", "bindings", "ffi", "derive",
    }),
    manifest_file="Cargo.toml",
    collect_deps=_collect_cargo_deps,
)

_PYPI_CONFIG = TyposquatConfig(
    ecosystem="pypi",
    rule_id="L2-PYPI-TYPO-001",
    detect_project=detect_pypi_project,
    builtin_corpus=BUILTIN_PYPI_TOP_100,
    known_legitimate=frozenset({
        "ruamel-yaml", "python-dateutil", "typing-extensions",
        "importlib-metadata", "importlib-resources", "pkgutil-resolve-name",
    }),
    collect_deps=_collect_pypi_deps,
    file_detection_fn=_pypi_finding_file,
)

_MAVEN_CONFIG = TyposquatConfig(
    ecosystem="maven",
    rule_id="L2-MAVEN-TYPO-001",
    detect_project=detect_maven_project,
    builtin_corpus=BUILTIN_MAVEN_TOP_100,
    known_legitimate=frozenset({
        "api", "core", "client", "server", "common", "util",
        "utils", "annotations", "model", "dto", "service",
        "dao", "impl", "shared", "parent", "starter", "boot",
        "cloud", "data", "jpa", "security", "web", "config",
        "support", "base", "abstract", "spi",
    }),
    collect_deps=_collect_maven_deps,
    file_detection_fn=_maven_finding_file,
)

_NUGET_CONFIG = TyposquatConfig(
    ecosystem="nuget",
    rule_id="L2-NUGET-TYPO-001",
    detect_project=detect_nuget_project,
    builtin_corpus=BUILTIN_NUGET_TOP_100,
    known_legitimate=frozenset({
        "api", "client", "server", "core", "common", "extensions",
        "abstractions", "implementation", "interfaces", "models",
        "services", "data", "entity", "domain", "infrastructure",
        "provider", "contracts", "helpers", "logging", "configuration",
        "security", "serialization", "validation", "componentmodel",
        "component", "design", "runtime", "sdk",
    }),
    collect_deps=_collect_nuget_deps,
    file_detection_fn=_nuget_finding_file,
)

_RUBYGEMS_CONFIG = TyposquatConfig(
    ecosystem="rubygems",
    rule_id="L2-RUBYGEMS-TYPO-001",
    detect_project=detect_rubygems_project,
    builtin_corpus=BUILTIN_RUBYGEMS_TOP_100,
    known_legitimate=frozenset({
        "api", "client", "server", "core", "ext", "base",
        "common", "mixins", "helpers", "utils", "engine",
        "rails", "active", "action", "rack", "middleware",
        "plugin", "adapter", "provider", "strategy",
    }),
    manifest_file="Gemfile",
    collect_deps=_collect_rubygems_deps,
)


def _detect_npm_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    corpus = load_corpus_for_ecosystem(corpus_dir, "npm", BUILTIN_TOP_100)

    KNOWN_LEGITIMATE: frozenset[str] = frozenset({
        "preact", "remix", "vite", "vitest", "svelte", "solid-js",
        "pino", "ora", "got", "prettier", "knex", "mobx", "zod",
    })

    root_pkg = target / "package.json"
    if not root_pkg.is_file():
        return findings

    pkg = load_package_json(root_pkg)
    if not pkg:
        return findings


    pkg_name = pkg.get("name", "")
    if pkg_name and not pkg_name.startswith("@") and pkg_name not in corpus and pkg_name not in KNOWN_LEGITIMATE:
        close_matches = check_typosquat(pkg_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(pkg_name, best_match, best_dist)
            findings.append(
                Finding(
                    rule_id="L2-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=pkg_name,
                    file=str(root_pkg),
                    message=(
                        f"Package '{pkg_name}' may be a typosquat of popular package(s): "
                        f"{', '.join(m[0] for m in close_matches)}"
                    ),
                    evidence=f"package_name({pkg_name}) is edit_distance {best_dist} from {best_match}",
                    remediation=(
                        f"Verify that '{pkg_name}' is the intended package, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the npm page and author before installing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks-on-npm/",
                    ],
                    ecosystem="npm",
                )
            )

    all_deps = get_dep_names(pkg)


    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            pkg_json = child / "package.json"
            if pkg_json.is_file():
                dep_data = load_package_json(pkg_json)
                if dep_data:
                    all_deps.update(get_dep_names(dep_data))

            if child.name.startswith("@") and child.is_dir():
                for scoped_child in sorted(child.iterdir()):
                    if not scoped_child.is_dir():
                        continue
                    scoped_pkg = scoped_child / "package.json"
                    if scoped_pkg.is_file():
                        dep_data = load_package_json(scoped_pkg)
                        if dep_data:
                            all_deps.update(get_dep_names(dep_data))

    for dep_name in sorted(all_deps):
        if dep_name in corpus or dep_name in KNOWN_LEGITIMATE:
            continue
        close_matches = check_typosquat(dep_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(dep_name, best_match, best_dist)
            findings.append(
                Finding(
                    rule_id="L2-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=dep_name,
                    file=str(root_pkg),
                    message=(
                        f"Dependency '{dep_name}' may be a typosquat of popular package(s): "
                        f"{', '.join(m[0] for m in close_matches)}"
                    ),
                    evidence=f"edit_distance({dep_name}, {best_match}) = {best_dist}",
                    remediation=(
                        f"Verify that '{dep_name}' is the intended package, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the npm page and author before installing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks-on-npm/",
                    ],
                    ecosystem="npm",
                )
            )

    return findings


def detect_all_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    findings: list[Finding] = []


    findings.extend(_detect_npm_typosquat(target, corpus_dir))


    for config in (_GO_CONFIG, _CARGO_CONFIG, _PYPI_CONFIG, _MAVEN_CONFIG, _NUGET_CONFIG, _RUBYGEMS_CONFIG):
        findings.extend(_detect_all_typosquat_standard(target, corpus_dir, config))

    return findings
