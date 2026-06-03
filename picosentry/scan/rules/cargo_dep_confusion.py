"""
L2-CARGO-DEPC-001: Cargo crate dependency confusion detection.

Flags private/internal crate names that could be squatted on crates.io.
Attackers register internal-looking crate names on the public registry
to inject malicious code when ``cargo build`` resolves the crate.

Pure function: (target_path, corpus_dir) -> List[Finding]

Cargo-specific considerations:
- crates.io is the default public registry
- Private registries can be configured via ``[registries]`` in .cargo/config.toml
- ``[patch]`` sections in Cargo.toml override crate sources
- Path dependencies (``crate = {{ path = "..." }}``) indicate internal crates
- Internal crates often have generic or company-prefixed names
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .cargo_utils import (
    detect_cargo_project,
    detect_private_cargo_registry,
    get_cargo_dep_names,
    parse_cargo_toml,
)

logger = logging.getLogger("picosentry.cargo_dep_confusion")

__all__ = ["detect_cargo_dep_confusion"]

# Patterns indicating internal/private crate names
_DEFAULT_INTERNAL_PATTERNS = [
    r"^internal-",
    r"^private-",
    r"^my-",
    r"^acme-",
    r"^company-",
    r"^org-",
    r"^corp-",
    r"^test-",
    r"^example-",
    r"^local-",
    r"-internal$",
    r"-private$",
    r"-local$",
]

# Well-known crates that are common enough to NOT flag as internal.
# These are single-word names that appear internal but are real crates.
_KNOWN_SAFE_CRATES: frozenset[str] = frozenset({
    "core",
    "alloc",
    "std",
    "proc-macro2",
    "proc-macro-hack",
})


def _looks_internal(crate_name: str) -> bool:
    """Heuristic check if a crate name looks like an internal/private name.

    Checks:
    - Matches known internal prefixes/suffixes
    - Is NOT in the known-safe list of real crates
    """
    if crate_name in _KNOWN_SAFE_CRATES:
        return False

    for pattern in _DEFAULT_INTERNAL_PATTERNS:
        if re.search(pattern, crate_name, re.IGNORECASE):
            return True

    # Short, generic-sounding single-word names are sometimes internal
    # but also very common for false positives. Only flag very suspicious ones.
    if crate_name.startswith("_") or crate_name.endswith("_test"):
        return True

    return False


def detect_cargo_dep_confusion(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect Cargo crate dependency confusion vectors.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    if not detect_cargo_project(target):
        return findings

    # Collect all dependency crate names from Cargo.toml
    all_deps: set[str] = set()

    cargo_data = parse_cargo_toml(target)
    if cargo_data:
        all_deps.update(get_cargo_dep_names(cargo_data))

    if not all_deps:
        return findings

    has_private = detect_private_cargo_registry(target)

    # Path dependencies are deliberately pinned to local paths
    path_deps: set[str] = set()
    if cargo_data:
        path_deps = cargo_data.get("has_path_deps", set())

    # Patch overrides protect specific crates from confusion
    patched_crates: set[str] = set()
    if cargo_data:
        patched_crates = set(cargo_data.get("patch", {}).keys())

    for crate_name in sorted(all_deps):
        is_internal = _looks_internal(crate_name)
        is_path_dep = crate_name in path_deps
        is_patched = crate_name in patched_crates

        # If it has a path source or is patched, it's deliberately pinned
        if is_path_dep or is_patched:
            continue

        if is_internal and not has_private:
            findings.append(
                Finding(
                    rule_id="L2-CARGO-DEPC-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=crate_name,
                    file=str(target / "Cargo.toml") if (target / "Cargo.toml").exists() else str(target),
                    message=(
                        f"Internal-looking dependency '{crate_name}' declared "
                        "without private Cargo registry configuration"
                    ),
                    evidence=f"dependency: {crate_name}",
                    remediation=(
                        f"Configure a private registry for '{crate_name}' via "
                        "[registries] in .cargo/config.toml, or add a [patch] "
                        "section in Cargo.toml with a path/git override to "
                        "prevent cargo from resolving it from crates.io."
                    ),
                    references=[
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                        "https://doc.rust-lang.org/cargo/reference/registries.html",
                    ],
                    ecosystem="cargo",
                )
            )

    return findings