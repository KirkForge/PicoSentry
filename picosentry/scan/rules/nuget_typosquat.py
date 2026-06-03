"""
L2-NUGET-TYPO-001: NuGet package typosquatting detection.

Flags .NET package dependencies whose IDs are within edit distance <=2
of popular NuGet packages. Attackers register misspelled package IDs
on nuget.org to trick developers into importing malicious code.

Pure function: (target_path, corpus_dir) -> List[Finding]

NuGet package IDs are dot-separated (like ``Newtonsoft.Json``,
``Microsoft.Extensions.Logging``), compared as full ID strings against the corpus.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .nuget_utils import (
    detect_nuget_project,
    get_nuget_dep_names,
    parse_csproj_file,
    parse_packages_config,
)
from .typosquat_utils import (
    BUILTIN_NUGET_TOP_100,
    check_typosquat,
    load_corpus_for_ecosystem,
    typosquat_severity_confidence,
)

logger = logging.getLogger("picosentry.nuget_typosquat")

__all__ = ["detect_nuget_typosquat"]

# Known legitimate package ID patterns to skip (avoid false positives)
KNOWN_LEGITIMATE_NUGET: frozenset[str] = frozenset({
    "api", "client", "server", "core", "common", "extensions",
    "abstractions", "implementation", "interfaces", "models",
    "services", "data", "entity", "domain", "infrastructure",
    "provider", "contracts", "helpers", "logging", "configuration",
    "security", "serialization", "validation", "componentmodel",
    "component", "design", "runtime", "sdk",
})


def detect_nuget_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect NuGet package typosquatting — package IDs close to popular packages.
    No network calls. Pure filesystem + corpus scan.
    """
    findings: list[Finding] = []

    if not detect_nuget_project(target):
        return findings

    corpus = load_corpus_for_ecosystem(corpus_dir, "nuget", BUILTIN_NUGET_TOP_100)

    # Collect all package IDs from all NuGet sources
    all_deps: set[str] = set()

    csproj_data = parse_csproj_file(target)
    if csproj_data:
        all_deps.update(get_nuget_dep_names(csproj_data))

    config_packages = parse_packages_config(target)
    if config_packages:
        all_deps.update(get_nuget_dep_names(config_packages))

    for dep_name in sorted(all_deps):
        if not dep_name or dep_name in KNOWN_LEGITIMATE_NUGET:
            continue

        # Skip if the package ID is itself a known popular package — it's the real thing
        if dep_name in corpus:
            continue

        close_matches = check_typosquat(dep_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(dep_name, best_match, best_dist)
            findings.append(
                Finding(
                    rule_id="L2-NUGET-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=dep_name,
                    file=str(target / "test.csproj") if (target / "test.csproj").exists() else str(target),
                    message=(
                        f"Package '{dep_name}' may be a typosquat "
                        f"of popular package '{best_match}'"
                    ),
                    evidence=f"edit_distance({dep_name}, {best_match}) = {best_dist}",
                    remediation=(
                        f"Verify that '{dep_name}' is the intended package, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the package source and author before importing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks/",
                    ],
                    ecosystem="nuget",
                )
            )

    return findings