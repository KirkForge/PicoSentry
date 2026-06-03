"""
L2-TYPO-001: Typosquatting detection.

Flags packages whose names are within edit distance <=2 of popular
npm packages. Attackers register misspelled names to trick developers
into installing malicious code.

Pure function: (target_path, corpus_dir) -> List[Finding]

Corpus: npm_top_packages.json (327 packages, offline, versioned).
Falls back to built-in TOP_100 if corpus file is missing.

Refactored to use shared typosquat_utils for edit distance, corpus loading,
and severity/confidence heuristics.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .typosquat_utils import (
    BUILTIN_TOP_100,
    check_typosquat,
    load_corpus_for_ecosystem,
    typosquat_severity_confidence,
)
from .utils import get_dep_names, load_package_json

__all__ = ["detect_typosquat"]
logger = logging.getLogger("picosentry.typosquat")

# Packages that are themselves popular/legitimate despite being near another
# popular name. Never flag these as typosquats.
KNOWN_LEGITIMATE: frozenset[str] = frozenset({
    "preact", "remix", "vite", "vitest", "svelte", "solid-js",
    "pino", "ora", "got", "prettier", "knex", "mobx", "zod",
})


def detect_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect typosquatting — dependency names close to popular packages.
    No network calls. Pure filesystem + corpus scan.
    """
    findings: list[Finding] = []
    corpus = load_corpus_for_ecosystem(corpus_dir, "npm", BUILTIN_TOP_100)

    root_pkg = target / "package.json"
    if not root_pkg.is_file():
        return findings

    pkg = load_package_json(root_pkg)
    if not pkg:
        return findings

    # Check the package's own name first (malicious packages ARE the typosquat)
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
                        f"Package '{pkg_name}' may be a typosquat of popular package(s): {', '.join(m[0] for m in close_matches)}"
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

    # Also check node_modules packages
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

            # Scoped packages
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
        # Skip packages that ARE in the corpus — they're legitimate, not typosquats
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
                        f"Dependency '{dep_name}' may be a typosquat of popular package(s): {', '.join(m[0] for m in close_matches)}"
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