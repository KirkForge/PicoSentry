"""
L2-GO-TYPO-001: Go module typosquatting detection.

Flags Go module dependencies whose short names are within edit distance <=2
of popular Go packages. Attackers register misspelled module paths to trick
developers into importing malicious code.

Pure function: (target_path, corpus_dir) -> List[Finding]

Follows the same pattern as PyPI/npm typosquat but for the Go ecosystem.
Short-name matching: compares the last path segment (e.g. ``gin`` from
``github.com/gin-gonic/gin``) against the corpus of popular Go packages.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .go_utils import (
    detect_go_project,
    get_go_dep_names,
    get_module_short_name,
    parse_go_mod,
)
from .typosquat_utils import (
    BUILTIN_GO_TOP_100,
    check_typosquat,
    load_corpus_for_ecosystem,
    typosquat_severity_confidence,
)

logger = logging.getLogger("picosentry.go_typosquat")

__all__ = ["detect_go_typosquat"]

# Known legitimate module paths whose short names are near popular ones
KNOWN_LEGITIMATE_GO: frozenset[str] = frozenset({
    "x",        # golang.org/x/* sub-packages
    "v2",       # /v2 version suffixes
    "v3",
    "api",      # common sub-package name
    "client",   # common sub-package name
    "server",   # common sub-package name
    "internal", # Go internal packages
    "cmd",      # cmd sub-packages
    "pkg",      # pkg sub-packages
})


def detect_go_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect Go module typosquatting — module paths close to popular Go packages.
    No network calls. Pure filesystem + corpus scan.
    """
    findings: list[Finding] = []

    if not detect_go_project(target):
        return findings

    corpus = load_corpus_for_ecosystem(corpus_dir, "go", BUILTIN_GO_TOP_100)

    # Collect all dependency module paths
    all_deps: set[str] = set()
    all_module_paths: dict[str, str] = {}  # short_name -> full_module_path

    go_mod_data = parse_go_mod(target)
    if go_mod_data:
        # Module name itself (the project could be a typosquat)
        module_name = go_mod_data.get("module", "")
        if module_name:
            all_deps.add(module_name)

        # Direct and indirect dependencies
        for mod_path, _version in go_mod_data.get("require", []):
            if mod_path:
                all_deps.add(mod_path)
                short = get_module_short_name(mod_path)
                all_module_paths[short] = mod_path

        for mod_path, _version in go_mod_data.get("indirect", []):
            if mod_path:
                all_deps.add(mod_path)
                short = get_module_short_name(mod_path)
                all_module_paths[short] = mod_path

    for dep_path in sorted(all_deps):
        short_name = get_module_short_name(dep_path)
        if not short_name or short_name in KNOWN_LEGITIMATE_GO:
            continue

        # Skip if the short name is itself a known popular package — it's the real thing
        if short_name in corpus:
            continue

        close_matches = check_typosquat(short_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(short_name, best_match, best_dist)
            findings.append(
                Finding(
                    rule_id="L2-GO-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=dep_path,
                    file=str(target / "go.mod") if (target / "go.mod").exists() else str(target),
                    message=(
                        f"Go module '{dep_path}' (short name: {short_name}) "
                        f"may be a typosquat of popular package '{best_match}'"
                    ),
                    evidence=f"edit_distance({short_name}, {best_match}) = {best_dist}",
                    remediation=(
                        f"Verify that '{short_name}' is the intended module, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the module path and author before importing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks/",
                    ],
                    ecosystem="go",
                )
            )

    return findings