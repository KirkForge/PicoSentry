from __future__ import annotations

import logging
import re
from pathlib import Path

from ._dep_confusion_config import (
    DepConfusionConfig,
    _CARGO_CONFIG,
    _GO_CONFIG,
    _INTERNAL_ALL_PATTERNS,
    _MAVEN_KNOWN_SAFE_ARTIFACTS,
    _MAVEN_PUBLIC_GROUP_PREFIXES,
    _NUGET_CONFIG,
    _PYPI_CONFIG,
    _RUBYGEMS_CONFIG,
)
from ..models import Confidence, Finding, Severity


from .cargo_utils import detect_cargo_project, detect_private_cargo_registry, get_cargo_dep_names, parse_cargo_toml
from .go_utils import detect_go_project, detect_goproxy_private, get_go_dep_names, parse_go_mod
from .maven_utils import (
    detect_maven_project,
    detect_private_maven_repository,
    parse_gradle_build,
    parse_pom_xml,
)
from .nuget_utils import (
    collect_nuget_deps,
    detect_nuget_project,
    detect_private_nuget_source,
)
from .pypi_utils import detect_pypi_project, get_python_dep_names, load_pyproject_toml, parse_requirements_file
from .rubygems_utils import (
    detect_private_rubygems_source,
    detect_rubygems_project,
    get_rubygems_dep_names,
    parse_gemfile,
)
from .utils import load_package_json

logger = logging.getLogger("picosentry.dep_confusion")

__all__ = ["detect_all_dep_confusion"]



def _looks_internal_base(name: str, config: DepConfusionConfig) -> bool:
    if name in config.known_safe_names:
        return False
    for prefix in config.known_public_prefixes:
        if name.startswith(prefix):
            return False
    for pattern in config.internal_patterns:
        if re.search(pattern, name, re.IGNORECASE):
            return True
    return config.check_single_segment and "." not in name and re.match(r"^[a-zA-Z][a-zA-Z0-9._-]*$", name) is not None



def _looks_internal_maven(group_id: str, artifact_id: str) -> bool:
    if artifact_id in _MAVEN_KNOWN_SAFE_ARTIFACTS:
        return False
    for pattern in _INTERNAL_ALL_PATTERNS:
        if re.search(pattern, artifact_id, re.IGNORECASE):
            return True

    if group_id and "." not in group_id and re.match(r"^[a-zA-Z][a-zA-Z0-9._-]*$", group_id):
        return True
    if group_id:
        for prefix in _MAVEN_PUBLIC_GROUP_PREFIXES:
            if group_id.startswith(prefix):
                return False
    return False


def _collect_npm_deps(target: Path) -> set[str]:
    deps: set[str] = set()
    root_pkg = target / "package.json"
    if not root_pkg.is_file():
        return deps
    pkg = load_package_json(root_pkg)
    if not pkg:
        return deps
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = pkg.get(key)
        if isinstance(section, dict):
            deps.update(section.keys())
    return deps


def _collect_go_deps(target: Path) -> set[str]:
    go_mod_data = parse_go_mod(target)
    if go_mod_data:
        return get_go_dep_names(go_mod_data)
    return set()


def _collect_cargo_deps(target: Path) -> set[str]:
    cargo_data = parse_cargo_toml(target)
    if cargo_data:
        return get_cargo_dep_names(cargo_data)
    return set()


def _collect_pypi_deps(target: Path) -> set[str]:
    deps: set[str] = set()
    project_data = load_pyproject_toml(target)
    if project_data:
        deps.update(get_python_dep_names(project_data.get("project", project_data)))
    for req_file in ("requirements.txt", "requirements-dev.txt"):
        req_path = target / req_file
        if req_path.is_file():
            for name, _version in parse_requirements_file(req_path):
                deps.add(name)
    return deps


def _collect_maven_deps(target: Path) -> list[tuple[str, str, str]]:
    deps: list[tuple[str, str, str]] = []
    pom_data = parse_pom_xml(target)
    if pom_data:
        deps.extend((dep[0], dep[1], dep[2]) for dep in pom_data.get("dependencies", []))
    gradle_data = parse_gradle_build(target)
    if gradle_data:
        deps.extend((dep[0], dep[1], dep[2]) for dep in gradle_data.get("dependencies", []))
    return deps


def _collect_nuget_deps_fn(target: Path) -> list[tuple[str, str, str]]:
    return collect_nuget_deps(target)


def _collect_rubygems_deps(target: Path) -> set[str]:
    gemfile_data = parse_gemfile(target)
    if gemfile_data:
        return get_rubygems_dep_names(gemfile_data)
    return set()


def _npm_has_private_registry(target: Path) -> bool:
    npmrc = target / ".npmrc"
    if npmrc.is_file():
        try:
            content = npmrc.read_text(encoding="utf-8", errors="replace")
            if "registry=" in content:
                return True
        except OSError:
            pass
    return False


def _pypi_has_private_index(target: Path) -> bool:

    for pip_conf in (target / "pip.conf", target / "pip.ini", target / ".pip" / "pip.conf"):
        if pip_conf.is_file():
            try:
                content = pip_conf.read_text(encoding="utf-8", errors="replace")
                if "index-url" in content:
                    for line in content.splitlines():
                        if "index-url" in line and "pypi.org" not in line:
                            return True
            except OSError:
                continue

    pypirc = target / ".pypirc"
    if pypirc.is_file():
        try:
            import configparser

            config = configparser.ConfigParser()
            config.read_string(pypirc.read_text(encoding="utf-8"))
            for section in config.sections():
                if (
                    section != "distutils"
                    and config.has_option(section, "repository")
                    and "pypi.org" not in config.get(section, "repository")
                ):
                    return True
        except (configparser.Error, OSError) as exc:
            logger.warning("Could not parse .pypirc at %s: %s", pypirc, exc)
            return False

    project_data = load_pyproject_toml(target)
    if project_data:
        sources = project_data.get("tool", {}).get("poetry", {}).get("source", [])
        if isinstance(sources, list):
            for source in sources:
                url = source.get("url", "")
                if url and "pypi.org" not in url:
                    return True
    return False


_NPMRC_REGISTRY_PATTERN = "registry="
_NPM_INTERNAL_SCOPES = frozenset({"@internal/", "@private/"})


def _get_go_pinned_deps(target: Path) -> set[str]:
    go_mod_data = parse_go_mod(target)
    if go_mod_data:
        return set(go_mod_data.get("replace", {}).keys())
    return set()


def _get_cargo_pinned_deps(target: Path) -> set[str]:
    cargo_data = parse_cargo_toml(target)
    if cargo_data:
        return set(cargo_data.get("patch", {}).keys()) | cargo_data.get("has_path_deps", set())
    return set()


def _get_rubygems_pinned_deps(target: Path) -> set[str]:
    gemfile_data = parse_gemfile(target)
    if gemfile_data:
        return set(gemfile_data.get("git_deps", set())) | set(gemfile_data.get("path_deps", set()))
    return set()


def _get_maven_finding_file(target: Path, has_pom: bool) -> Path:
    if has_pom:
        return target / "pom.xml"
    return target / "build.gradle"


def detect_all_dep_confusion(target: Path) -> list[Finding]:
    findings: list[Finding] = []

    pkg_path = target / "package.json"
    if pkg_path.is_file():
        pkg = load_package_json(pkg_path)
        if pkg:
            all_deps = _collect_npm_deps(target)
            if all_deps:
                has_private = _npm_has_private_registry(target)
                npm_internal_scopes = _get_npm_internal_scopes()

                for dep_name in sorted(all_deps):
                    is_internal = any(dep_name.startswith(p) for p in npm_internal_scopes)

                    if is_internal and not has_private:
                        findings.append(
                            Finding(
                                rule_id="L2-DEPC-001",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                package=dep_name,
                                file=str(pkg_path),
                                message=(
                                    f"Internal-scoped dependency '{dep_name}' declared "
                                    "without private registry configuration in .npmrc"
                                ),
                                evidence=f"dependency: {dep_name}",
                                remediation=(
                                    f"Add a registry override for '{dep_name}' in .npmrc "
                                    "to prevent npm from resolving it from the public registry."
                                ),
                                references=[
                                    "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                                    "https://docs.npmjs.com/cli/v10/configuring-npm/npmrc",
                                ],
                            )
                        )

                if has_private:
                    for dep_name in sorted(all_deps):
                        if dep_name.startswith("@"):
                            scope = dep_name.split("/")[0]
                            try:
                                npmrc_text = (target / ".npmrc").read_text(encoding="utf-8", errors="replace")
                            except OSError:
                                npmrc_text = ""
                            if f"{scope}:registry" not in npmrc_text:
                                findings.append(
                                    Finding(
                                        rule_id="L2-DEPC-001",
                                        severity=Severity.HIGH,
                                        confidence=Confidence.MEDIUM,
                                        package=dep_name,
                                        file=str(target / ".npmrc"),
                                        message=(
                                            f"Scoped dependency '{dep_name}' may resolve "
                                            "from public npm instead of private registry"
                                        ),
                                        evidence=f"dependency: {dep_name}, scope: {scope}",
                                        remediation=(
                                            f"Add '{scope}:registry=<your-private-registry>' "
                                            "to .npmrc to ensure correct resolution."
                                        ),
                                        references=[
                                            "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4"
                                        ],
                                    )
                                )

    if detect_go_project(target):
        go_deps = _collect_go_deps(target)
        if go_deps:
            has_private = detect_goproxy_private(target)
            pinned = _get_go_pinned_deps(target)
            go_config = _GO_CONFIG
            for dep_path in sorted(go_deps):
                if dep_path in pinned:
                    continue
                if _looks_internal_base(dep_path, go_config) and not has_private:
                    findings.append(_make_finding(go_config, dep_path, dep_path, target, "go.mod"))

    if detect_cargo_project(target):
        cargo_deps = _collect_cargo_deps(target)
        if cargo_deps:
            has_private = detect_private_cargo_registry(target)
            pinned = _get_cargo_pinned_deps(target)
            cargo_config = _CARGO_CONFIG
            for crate_name in sorted(cargo_deps):
                if crate_name in pinned:
                    continue
                if _looks_internal_base(crate_name, cargo_config) and not has_private:
                    findings.append(_make_finding(cargo_config, crate_name, crate_name, target, "Cargo.toml"))

    if detect_pypi_project(target):
        pypi_deps = _collect_pypi_deps(target)
        if pypi_deps:
            has_private = _pypi_has_private_index(target)
            pypi_config = _PYPI_CONFIG
            for dep_name in sorted(pypi_deps):
                if _looks_internal_base(dep_name, pypi_config) and not has_private:
                    manifest_file = "pyproject.toml" if (target / "pyproject.toml").exists() else str(target)
                    findings.append(_make_finding(pypi_config, dep_name, dep_name, target, manifest_file))

    maven_detected = detect_maven_project(target)
    if maven_detected:
        maven_deps = _collect_maven_deps(target)
        if maven_deps:
            has_private = detect_private_maven_repository(target)
            for group_id, artifact_id, _version in sorted(maven_deps):
                if not group_id or not artifact_id:
                    continue
                if _looks_internal_maven(group_id, artifact_id) and not has_private:
                    dep_ref = f"{group_id}:{artifact_id}"
                    finding_file = _get_maven_finding_file(target, bool(parse_pom_xml(target)))
                    findings.append(
                        Finding(
                            rule_id="L2-MAVEN-DEPC-001",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            package=dep_ref,
                            file=str(finding_file),
                            message=(
                                f"Internal-looking dependency '{dep_ref}' declared "
                                "without private Maven repository configuration"
                            ),
                            evidence=f"dependency: {dep_ref}",
                            remediation=(
                                f"Configure a private repository for '{dep_ref}' via "
                                "<repositories> in pom.xml, or add a custom repository "
                                "URL in build.gradle to prevent Maven from resolving it "
                                "from Maven Central."
                            ),
                            references=[
                                "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                                "https://maven.apache.org/settings.html#Servers",
                            ],
                            ecosystem="maven",
                        )
                    )

    if detect_nuget_project(target):
        nuget_deps = _collect_nuget_deps_fn(target)
        if nuget_deps:
            has_private = detect_private_nuget_source(target)
            nuget_config = _NUGET_CONFIG
            for pkg_id, _version, source in nuget_deps:
                if not pkg_id:
                    continue
                if _looks_internal_base(pkg_id, nuget_config) and not has_private:
                    findings.append(_make_finding(nuget_config, pkg_id, pkg_id, target, source or "nuget.config"))

    if detect_rubygems_project(target):
        gem_deps = _collect_rubygems_deps(target)
        if gem_deps:
            has_private = detect_private_rubygems_source(target)
            pinned = _get_rubygems_pinned_deps(target)
            rubygems_config = _RUBYGEMS_CONFIG
            for gem_name in sorted(gem_deps):
                if gem_name in pinned:
                    continue
                if _looks_internal_base(gem_name, rubygems_config) and not has_private:
                    findings.append(_make_finding(rubygems_config, gem_name, gem_name, target, "Gemfile"))

    return findings



def _make_finding(
    config: DepConfusionConfig,
    package_ref: str,
    dep_name: str,
    target: Path,
    manifest_file: str,
) -> Finding:
    return Finding(
        rule_id=config.rule_id,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        package=package_ref,
        file=str(target / manifest_file),
        message=(
            f"Internal-looking dependency '{dep_name}' declared "
            f"without private {config.ecosystem} registry configuration"
        ),
        evidence=f"dependency: {dep_name}",
        remediation=f"Configure a private registry for '{dep_name}' to prevent resolution from public sources.",
        references=[
            "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
        ],
        ecosystem=config.ecosystem,
    )


def _get_npm_internal_scopes() -> frozenset[str]:
    import os

    scopes = set(_NPM_INTERNAL_SCOPES)
    env = os.environ.get("PICOSENTRY_INTERNAL_SCOPES", "")
    if env:
        for raw_scope in env.split(","):
            s = raw_scope.strip()
            if s and s.startswith("@") and s.endswith("/"):
                scopes.add(s)
    return frozenset(scopes)
