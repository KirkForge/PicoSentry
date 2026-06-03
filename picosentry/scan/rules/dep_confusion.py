"""
L2-DEPC-001: Dependency confusion detection.

Flags packages that appear in both internal/private registries and
the public npm registry. Attackers squat internal package names on npm
to inject malicious code via install resolution order.

Pure function: (target_path, corpus_dir) → List[Finding]
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import load_package_json

logger = logging.getLogger("picosentry.dep_confusion")

__all__ = ["detect_dep_confusion"]
# Heuristic indicators in .npmrc that a private registry is configured.
NPMRC_REGISTRY_PATTERN = "registry="


# Well-known placeholder scopes that almost certainly indicate an
# internal/private package in a project that has not configured its
# registry.  This is intentionally conservative: only scopes that are
# obviously not real npm orgs are included.  Real orgs like @babel or
# @types should never appear here.
#
# For custom detection, set PICOSENTRY_INTERNAL_SCOPES (comma-separated
# scope prefixes, e.g. "@myorg/,@acme/").
_DEFAULT_PLACEHOLDER_SCOPES = frozenset(
    {
        "@internal/",
        "@private/",
    }
)


def _get_internal_scopes() -> frozenset[str]:
    import os

    scopes = set(_DEFAULT_PLACEHOLDER_SCOPES)
    env = os.environ.get("PICOSENTRY_INTERNAL_SCOPES", "")
    if env:
        for s in env.split(","):
            s = s.strip()
            if s and s.startswith("@") and s.endswith("/"):
                scopes.add(s)
    return frozenset(scopes)


def _get_all_deps(pkg: dict) -> set[str]:
    deps: set[str] = set()
    for key in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundledDependencies",
    ):
        section = pkg.get(key)
        if isinstance(section, dict):
            deps.update(section.keys())
    return deps


def _has_private_registry(target: Path) -> bool:
    npmrc = target / ".npmrc"
    if npmrc.is_file():
        try:
            content = npmrc.read_text(encoding="utf-8", errors="replace")
            if NPMRC_REGISTRY_PATTERN in content:
                return True
        except OSError:
            logger.debug("Failed to read .npmrc", exc_info=True)
    return False


def detect_dep_confusion(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect dependency confusion vectors.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    root_pkg = target / "package.json"
    if not root_pkg.is_file():
        return findings

    pkg = load_package_json(root_pkg)
    if not pkg:
        return findings

    all_deps = _get_all_deps(pkg)
    if not all_deps:
        return findings

    has_private = _has_private_registry(target)
    has_private = _has_private_registry(target)
    internal_scopes = _get_internal_scopes()

    for dep_name in sorted(all_deps):
        is_internal = any(dep_name.startswith(p) for p in internal_scopes)

        if is_internal and not has_private:
            findings.append(
                Finding(
                    rule_id="L2-DEPC-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=dep_name,
                    file=str(root_pkg),
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

    # If private registry is configured, warn about deps that could resolve from public npm.
    if has_private:
        for dep_name in sorted(all_deps):
            if dep_name.startswith("@"):
                scope = dep_name.split("/")[0]
                npmrc = target / ".npmrc"
                try:
                    npmrc_text = npmrc.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    npmrc_text = ""

                if f"{scope}:registry" not in npmrc_text:
                    findings.append(
                        Finding(
                            rule_id="L2-DEPC-001",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            package=dep_name,
                            file=str(npmrc),
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
                                "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                            ],
                        )
                    )

    return findings
