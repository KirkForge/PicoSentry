"""
L2-CARGO-TYPO-001: Cargo crate typosquatting detection.

Flags Rust crate dependencies whose names are within edit distance <=2
of popular crates. Attackers register misspelled crate names on crates.io
to trick developers into importing malicious code.

Pure function: (target_path, corpus_dir) -> List[Finding]

Crate names in Cargo.toml are simple identifiers (no path structure),
so the full name is compared directly against the corpus.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .cargo_utils import (
    detect_cargo_project,
    get_cargo_dep_names,
    parse_cargo_toml,
)
from .typosquat_utils import (
    BUILTIN_CARGO_TOP_100,
    check_typosquat,
    load_corpus_for_ecosystem,
    typosquat_severity_confidence,
)

logger = logging.getLogger("picosentry.cargo_typosquat")

__all__ = ["detect_cargo_typosquat"]

# Known legitimate crate name patterns to skip
KNOWN_LEGITIMATE_CARGO: frozenset[str] = frozenset({
    "x",      # common utility crate prefix
    "v2",     # version suffix
    "v3",
    "api",    # common name
    "client",
    "server",
    "core",   # common lib name
    "sys",    # system bindings
    "bindings",
    "ffi",
    "derive",
})


def detect_cargo_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect Cargo crate typosquatting — crate names close to popular crates.
    No network calls. Pure filesystem + corpus scan.
    """
    findings: list[Finding] = []

    if not detect_cargo_project(target):
        return findings

    corpus = load_corpus_for_ecosystem(corpus_dir, "cargo", BUILTIN_CARGO_TOP_100)

    # Collect all dependency crate names
    all_deps: set[str] = set()

    cargo_data = parse_cargo_toml(target)
    if cargo_data:
        all_deps.update(get_cargo_dep_names(cargo_data))

    for dep_name in sorted(all_deps):
        if not dep_name or dep_name in KNOWN_LEGITIMATE_CARGO:
            continue

        # Skip if the crate name is itself a known popular crate — it's the real thing
        if dep_name in corpus:
            continue

        close_matches = check_typosquat(dep_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = typosquat_severity_confidence(dep_name, best_match, best_dist)
            findings.append(
                Finding(
                    rule_id="L2-CARGO-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=dep_name,
                    file=str(target / "Cargo.toml") if (target / "Cargo.toml").exists() else str(target),
                    message=(
                        f"Crate '{dep_name}' may be a typosquat "
                        f"of popular crate '{best_match}'"
                    ),
                    evidence=f"edit_distance({dep_name}, {best_match}) = {best_dist}",
                    remediation=(
                        f"Verify that '{dep_name}' is the intended crate, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the crate source and author before importing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks/",
                    ],
                    ecosystem="cargo",
                )
            )

    return findings