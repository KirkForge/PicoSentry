"""
L2-RUBYGEMS-TYPO-001: RubyGem typosquatting detection.

Flags gem dependencies whose names are within edit distance <=2
of popular RubyGems packages.

Pure function: (target_path, corpus_dir) -> List[Finding]

Gem names in Gemfile are simple identifiers (like ``rails``, ``devise``),
compared directly against the corpus.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .rubygems_utils import (
    detect_rubygems_project,
    get_rubygems_dep_names,
    parse_gemfile,
)
from .typosquat_utils import (
    BUILTIN_RUBYGEMS_TOP_100,
    check_typosquat,
    load_corpus_for_ecosystem,
    typosquat_severity_confidence,
)

logger = logging.getLogger("picosentry.rubygems_typosquat")

__all__ = ["detect_rubygems_typosquat"]

# Known legitimate gem name patterns to skip
KNOWN_LEGITIMATE_RUBYGEMS: frozenset[str] = frozenset({
    "api", "client", "server", "core", "ext", "base",
    "common", "mixins", "helpers", "utils", "engine",
    "rails", "active", "action", "rack", "middleware",
    "plugin", "adapter", "provider", "strategy",
})


def detect_rubygems_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect RubyGem typosquatting — gem names close to popular gems.
    No network calls. Pure filesystem + corpus scan.
    """
    findings: list[Finding] = []

    if not detect_rubygems_project(target):
        return findings

    corpus = load_corpus_for_ecosystem(corpus_dir, "rubygems", BUILTIN_RUBYGEMS_TOP_100)

    # Collect all dependency gem names
    all_deps: set[str] = set()

    gemfile_data = parse_gemfile(target)
    if gemfile_data:
        all_deps.update(get_rubygems_dep_names(gemfile_data))

    for dep_name in sorted(all_deps):
        if not dep_name or dep_name in KNOWN_LEGITIMATE_RUBYGEMS:
            continue

        # Skip if the gem name is itself a known popular gem
        if dep_name in corpus:
            continue

        close_matches = check_typosquat(dep_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(dep_name, best_match, best_dist)
            findings.append(
                Finding(
                    rule_id="L2-RUBYGEMS-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=dep_name,
                    file=str(target / "Gemfile") if (target / "Gemfile").exists() else str(target),
                    message=(
                        f"Gem '{dep_name}' may be a typosquat "
                        f"of popular gem '{best_match}'"
                    ),
                    evidence=f"edit_distance({dep_name}, {best_match}) = {best_dist}",
                    remediation=(
                        f"Verify that '{dep_name}' is the intended gem, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the gem source and author before importing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks/",
                    ],
                    ecosystem="rubygems",
                )
            )

    return findings