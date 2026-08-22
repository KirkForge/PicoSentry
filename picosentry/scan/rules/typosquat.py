from __future__ import annotations

import logging
import re
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Confidence, Finding, Severity
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
from ._typosquat_corpus import (
    BUILTIN_CARGO_TOP_100,
    BUILTIN_GO_TOP_100,
    BUILTIN_MAVEN_TOP_100,
    BUILTIN_NUGET_TOP_100,
    BUILTIN_PYPI_TOP_100,
    BUILTIN_RUBYGEMS_TOP_100,
    BUILTIN_TOP_100,
)
from .corpus_index import check_typosquat_against_index, load_indexed_corpus
from .typosquat_utils import typosquat_severity_confidence
from .utils import get_dep_names, load_package_json

if TYPE_CHECKING:
    from ..package_intel import PackageIntel

logger = logging.getLogger("picosentry.typosquat")

__all__ = ["detect_all_typosquat"]

_PEP503_RE = re.compile(r"[-_.]+")


def _pep503_normalize(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of - _ . → single -."""
    return _PEP503_RE.sub("-", name).lower()


@dataclass(frozen=True)
class TyposquatConfig:
    ecosystem: str
    rule_id: str
    detect_project: Callable[[Path], bool]
    builtin_corpus: list[str]
    known_legitimate: frozenset[str] = field(default_factory=frozenset)

    use_short_name: bool = False

    min_name_length: int = 3

    use_keyboard: bool = False

    manifest_file: str = ""

    collect_deps: Callable[[Path], set[str]] | None = None

    file_detection_fn: Callable[[Path], str] | None = None


_PREWARM_DEP_THRESHOLD = 8
# Ecosystems whose index has been force-built this process.  Keyed by corpus
# directory + ecosystem so a rebuilt engine does not re-probe cold corpora.
_prewarmed: set[tuple[str, str]] = set()


def _npm_dep_probe(target: Path) -> int:
    pkg = load_package_json(target / "package.json")
    if not pkg:
        return 0
    count = len(get_dep_names(pkg))
    nm = target / "node_modules"
    if nm.is_dir():
        with suppress(OSError):
            count += sum(1 for _ in nm.iterdir())
    return count


def _manifest_line_probe(target: Path, filenames: tuple[str, ...]) -> int:
    count = 0
    for filename in filenames:
        path = target / filename
        if not path.is_file():
            continue
        try:
            count += sum(
                1
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.lstrip().startswith(("#", "//", "[", "source", "group", "plugins", "var "))
            )
        except OSError:
            continue
    return count


_PREWARM_PROBES: dict[str, Callable[[Path], int]] = {
    "npm": _npm_dep_probe,
    "pypi": lambda t: _manifest_line_probe(t, ("requirements.txt",)) + (1 if (t / "pyproject.toml").is_file() else 0),
    "go": lambda t: _manifest_line_probe(t, ("go.mod",)),
    "cargo": lambda t: _manifest_line_probe(t, ("Cargo.toml",)),
    "maven": lambda t: _manifest_line_probe(t, ("pom.xml", "build.gradle")),
    "nuget": lambda t: _manifest_line_probe(t, ("packages.config",)),
    "rubygems": lambda t: _manifest_line_probe(t, ("Gemfile",)),
}


def prewarm_typosquat_indexes(target: Path, corpus_dir: Path, detected: frozenset[str] | None = None) -> None:
    """Finish building delete indexes for dep-heavy targets before rules run.

    The typosquat rules build a SymSpell-style delete index incrementally (one
    chunk of corpus names per query) so no single rule blows its timebox —
    but a cold, dependency-heavy scan would still pay most of the build inside
    the first such rule.  This probe runs at scan() start, outside the rule
    timebox, and force-completes the build when the target looks dep-heavy.
    The probe is intentionally cheap and approximate (root manifest entry
    counts); anything it misses falls back to the in-rule incremental build,
    which stays exact.

    WO6.0.0-019: ``detected`` limits probing to ecosystems the scan actually
    selected (``_detect_ecosystems`` already ran in ``scan()``). A polyglot
    repo with only npm + pypi markers no longer pays the go/cargo/maven/
    nuget/rubygems probe cost (~6s/180MB saved on a 2-ecosystem scan). When
    ``detected`` is None (back-compat / direct callers) all ecosystems probe.
    """
    ecosystems = tuple(detected) if detected is not None else tuple(_PREWARM_PROBES)
    for eco in ecosystems:
        probe = _PREWARM_PROBES.get(eco)
        if probe is None:
            continue
        key = (str(corpus_dir), eco)
        if key in _prewarmed:
            continue
        try:
            count = probe(target)
        except Exception:  # pragma: no cover - probes must never break a scan
            logger.debug("typosquat prewarm probe failed for %s", eco, exc_info=True)
            continue
        if count < _PREWARM_DEP_THRESHOLD:
            continue
        builtin = _ECOSYSTEM_BUILTINS.get(eco)
        if builtin is None:
            continue
        index = load_indexed_corpus(corpus_dir, eco, builtin)
        index.finish_delete_index()
        _prewarmed.add(key)
        logger.debug("prewarmed %s typosquat delete index (%d probe deps)", eco, count)


def _detect_all_typosquat_standard(target: Path, corpus_dir: Path, config: TyposquatConfig) -> list[Finding]:
    findings: list[Finding] = []

    if not config.detect_project(target):
        return findings

    index = load_indexed_corpus(corpus_dir, config.ecosystem, config.builtin_corpus)
    all_deps = config.collect_deps(target) if config.collect_deps else set()
    if not all_deps:
        return findings

    for dep_name in sorted(all_deps):
        compare_name = dep_name
        if config.use_short_name:
            compare_name = get_module_short_name(dep_name)
            if not compare_name:
                continue

        # WO7-012: known_legitimate and the corpus index store PEP 503-
        # normalized names (ruamel-yaml); deps are collected raw (ruamel.yaml).
        # Normalize before the membership checks so a package is not its own
        # typosquat at edit distance 1.
        normalized = _pep503_normalize(compare_name) if config.ecosystem == "pypi" else compare_name

        if not normalized or normalized in config.known_legitimate:
            continue

        if len(normalized) < config.min_name_length:
            continue

        if normalized in index:
            continue

        close_matches = check_typosquat_against_index(normalized, index, use_keyboard=config.use_keyboard)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(normalized, best_match, best_dist)

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
                    evidence=f"edit_distance({normalized}, {best_match}) = {best_dist}",
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
    known_legitimate=frozenset(
        {
            "x",
            "v2",
            "v3",
            "api",
            "client",
            "server",
            "internal",
            "cmd",
            "pkg",
            "go",
            "etcd",
            "fmt",
        }
    ),
    use_short_name=True,
    min_name_length=3,
    use_keyboard=True,
    manifest_file="go.mod",
    collect_deps=_collect_go_deps,
    # ponytail: ceiling — use_keyboard=True forces the trie path (keyboard
    # distance has no SymSpell completeness argument), measured 2.3s/420deps
    # on dev hardware (2.2x headroom under the 5s box HERE; CI runners slower;
    # ~800+ modules silently timebox out on slower machines — the SA-AJ
    # class). Upgrade path: dep-count threshold → fall back to non-keyboard
    # matching (SymSpell-accelerated) above ~600 deps, trading keyboard
    # sensitivity for guaranteed completion. Pinned by
    # test_go_typosquat_keyboard_perf_ceiling in the slow tier.
)

_CARGO_CONFIG = TyposquatConfig(
    ecosystem="cargo",
    rule_id="L2-CARGO-TYPO-001",
    detect_project=detect_cargo_project,
    builtin_corpus=BUILTIN_CARGO_TOP_100,
    known_legitimate=frozenset(
        {
            "x",
            "v2",
            "v3",
            "api",
            "client",
            "server",
            "core",
            "sys",
            "bindings",
            "ffi",
            "derive",
        }
    ),
    manifest_file="Cargo.toml",
    collect_deps=_collect_cargo_deps,
)

_PYPI_CONFIG = TyposquatConfig(
    ecosystem="pypi",
    rule_id="L2-PYPI-TYPO-001",
    detect_project=detect_pypi_project,
    builtin_corpus=BUILTIN_PYPI_TOP_100,
    known_legitimate=frozenset(
        {
            "ruamel-yaml",
            "python-dateutil",
            "typing-extensions",
            "importlib-metadata",
            "importlib-resources",
            "pkgutil-resolve-name",
        }
    ),
    collect_deps=_collect_pypi_deps,
    file_detection_fn=_pypi_finding_file,
)

_MAVEN_CONFIG = TyposquatConfig(
    ecosystem="maven",
    rule_id="L2-MAVEN-TYPO-001",
    detect_project=detect_maven_project,
    builtin_corpus=BUILTIN_MAVEN_TOP_100,
    known_legitimate=frozenset(
        {
            "api",
            "core",
            "client",
            "server",
            "common",
            "util",
            "utils",
            "annotations",
            "model",
            "dto",
            "service",
            "dao",
            "impl",
            "shared",
            "parent",
            "starter",
            "boot",
            "cloud",
            "data",
            "jpa",
            "security",
            "web",
            "config",
            "support",
            "base",
            "abstract",
            "spi",
        }
    ),
    collect_deps=_collect_maven_deps,
    file_detection_fn=_maven_finding_file,
)

_NUGET_CONFIG = TyposquatConfig(
    ecosystem="nuget",
    rule_id="L2-NUGET-TYPO-001",
    detect_project=detect_nuget_project,
    builtin_corpus=BUILTIN_NUGET_TOP_100,
    known_legitimate=frozenset(
        {
            "api",
            "client",
            "server",
            "core",
            "common",
            "extensions",
            "abstractions",
            "implementation",
            "interfaces",
            "models",
            "services",
            "data",
            "entity",
            "domain",
            "infrastructure",
            "provider",
            "contracts",
            "helpers",
            "logging",
            "configuration",
            "security",
            "serialization",
            "validation",
            "componentmodel",
            "component",
            "design",
            "runtime",
            "sdk",
        }
    ),
    collect_deps=_collect_nuget_deps,
    file_detection_fn=_nuget_finding_file,
)

_RUBYGEMS_CONFIG = TyposquatConfig(
    ecosystem="rubygems",
    rule_id="L2-RUBYGEMS-TYPO-001",
    detect_project=detect_rubygems_project,
    builtin_corpus=BUILTIN_RUBYGEMS_TOP_100,
    known_legitimate=frozenset(
        {
            "api",
            "client",
            "server",
            "core",
            "ext",
            "base",
            "common",
            "mixins",
            "helpers",
            "utils",
            "engine",
            "rails",
            "active",
            "action",
            "rack",
            "middleware",
            "plugin",
            "adapter",
            "provider",
            "strategy",
        }
    ),
    manifest_file="Gemfile",
    collect_deps=_collect_rubygems_deps,
)

_ECOSYSTEM_BUILTINS: dict[str, list[str]] = {
    "npm": BUILTIN_TOP_100,
    "go": BUILTIN_GO_TOP_100,
    "cargo": BUILTIN_CARGO_TOP_100,
    "pypi": BUILTIN_PYPI_TOP_100,
    "maven": BUILTIN_MAVEN_TOP_100,
    "nuget": BUILTIN_NUGET_TOP_100,
    "rubygems": BUILTIN_RUBYGEMS_TOP_100,
}


def _enforce_evidence(finding: Finding, dep_name: str, package_intel: dict[str, PackageIntel] | None) -> Finding:
    if package_intel is None:
        return finding
    intel = package_intel.get(dep_name)
    if intel is None:
        return finding
    severity = finding.severity
    confidence = finding.confidence
    evidence_parts = [finding.evidence]

    if intel.anonymous_maintainer:
        evidence_parts.append("anonymous maintainer")
    if intel.maintainer_count == 0:
        evidence_parts.append("no maintainers")
    if intel.has_install_scripts:
        evidence_parts.append("has install scripts")
    if intel.risk_score > 0.5:
        evidence_parts.append(f"risk score {intel.risk_score:.2f}")
    if not intel.has_repository_url:
        evidence_parts.append("no repository URL")

    if (intel.maintainer_count == 0 or intel.anonymous_maintainer) and severity != Severity.CRITICAL:
        severity = Severity.CRITICAL

    if intel.has_install_scripts and intel.has_postinstall_script:
        evidence_parts.append("install + postinstall scripts present — code execution on install")

    if intel.risk_score > 0.5 and confidence == Confidence.MEDIUM:
        confidence = Confidence.HIGH

    if intel.has_repository_url and intel.maintainer_count > 5 and severity == Severity.HIGH:
        severity = Severity.MEDIUM
        evidence_parts.append("well-maintained package with repository — likely legitimate")

    from dataclasses import replace

    return replace(finding, severity=severity, confidence=confidence, evidence="; ".join(evidence_parts))


def _detect_npm_typosquat(
    target: Path, corpus_dir: Path, package_intel: dict[str, PackageIntel] | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    index = load_indexed_corpus(corpus_dir, "npm", BUILTIN_TOP_100)

    KNOWN_LEGITIMATE: frozenset[str] = frozenset(
        {
            "preact",
            "remix",
            "vite",
            "vitest",
            "svelte",
            "solid-js",
            "pino",
            "ora",
            "got",
            "prettier",
            "knex",
            "mobx",
            "zod",
            # WO5.0.0-028 short-name calibration: real packages whose <=3-char
            # names sit at edit distance 1 from corpus shorts (pkg->pg,
            # uid->uuid, num->npm). Structurally indistinguishable from real
            # short-name typosquats (nx1->next), so legitimacy lists are the
            # only honest separator; grown per reported FP.
            "pkg",
            "uid",
            "num",
        }
    )

    root_pkg = target / "package.json"
    if not root_pkg.is_file():
        return findings

    pkg = load_package_json(root_pkg)
    if not pkg:
        return findings

    pkg_name = pkg.get("name", "")
    if pkg_name and not pkg_name.startswith("@") and pkg_name not in index and pkg_name not in KNOWN_LEGITIMATE:
        close_matches = check_typosquat_against_index(pkg_name, index)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(pkg_name, best_match, best_dist)
            findings.append(
                _enforce_evidence(
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
                    ),
                    pkg_name,
                    package_intel,
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
        if dep_name in index or dep_name in KNOWN_LEGITIMATE:
            continue
        close_matches = check_typosquat_against_index(dep_name, index)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(dep_name, best_match, best_dist)
            findings.append(
                _enforce_evidence(
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
                    ),
                    dep_name,
                    package_intel,
                )
            )

    return findings


def detect_all_typosquat(
    target: Path, corpus_dir: Path, package_intel: dict[str, PackageIntel] | None = None
) -> list[Finding]:
    findings: list[Finding] = []

    findings.extend(_detect_npm_typosquat(target, corpus_dir, package_intel))

    for config in (_GO_CONFIG, _CARGO_CONFIG, _PYPI_CONFIG, _MAVEN_CONFIG, _NUGET_CONFIG, _RUBYGEMS_CONFIG):
        findings.extend(_detect_all_typosquat_standard(target, corpus_dir, config))

    return findings
