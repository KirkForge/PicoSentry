"""
L2-RUBYGEMS-DEPC-001: RubyGem dependency confusion detection.

Flags private/internal gem names that could be squatted on rubygems.org.
Attackers register internal-looking gem names on the public registry
to inject malicious code when ``bundle install`` resolves the gem.

Pure function: (target_path, corpus_dir) -> List[Finding]

RubyGems-specific considerations:
- rubygems.org is the default public registry
- Private gem servers can be configured via ``source`` blocks in Gemfile
- Git/path sources in Gemfile indicate private gems
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .rubygems_utils import (
    detect_rubygems_project,
    detect_private_rubygems_source,
    get_rubygems_dep_names,
    parse_gemfile,
)

logger = logging.getLogger("picosentry.rubygems_dep_confusion")

__all__ = ["detect_rubygems_dep_confusion"]

# Patterns indicating internal/private gem names
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

# Well-known gems that look "generic" but are real
_KNOWN_SAFE_GEMS: frozenset[str] = frozenset({
    "rails", "rack", "rake", "bundler", "json",
    "minitest", "test-unit", "psych", "io-console",
    "bigdecimal", "csv", "date", "stringio", "strscan",
    "base64", "digest", "securerandom",
})


def _looks_internal(gem_name: str) -> bool:
    """Heuristic check if a gem name looks like an internal/private name."""
    if gem_name in _KNOWN_SAFE_GEMS:
        return False

    for pattern in _DEFAULT_INTERNAL_PATTERNS:
        if re.search(pattern, gem_name, re.IGNORECASE):
            return True

    # Short single-word names that aren't known-safe are sometimes internal
    if gem_name.startswith("_") or gem_name.endswith("_test"):
        return True

    return False


def detect_rubygems_dep_confusion(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect RubyGems dependency confusion vectors.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    if not detect_rubygems_project(target):
        return findings

    # Collect all dependency gem names
    all_deps: set[str] = set()

    gemfile_data = parse_gemfile(target)
    if gemfile_data:
        all_deps.update(get_rubygems_dep_names(gemfile_data))

    if not all_deps:
        return findings

    has_private = detect_private_rubygems_source(target)

    # Track git/path deps that are deliberately pinned
    git_deps: set[str] = set()
    path_deps: set[str] = set()
    if gemfile_data:
        git_deps = gemfile_data.get("git_deps", set())
        path_deps = gemfile_data.get("path_deps", set())

    for gem_name in sorted(all_deps):
        is_internal = _looks_internal(gem_name)
        is_git_dep = gem_name in git_deps
        is_path_dep = gem_name in path_deps

        # If it has a git or path source, it's deliberately pinned
        if is_git_dep or is_path_dep:
            continue

        if is_internal and not has_private:
            findings.append(
                Finding(
                    rule_id="L2-RUBYGEMS-DEPC-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=gem_name,
                    file=str(target / "Gemfile") if (target / "Gemfile").exists() else str(target),
                    message=(
                        f"Internal-looking gem '{gem_name}' declared "
                        "without private gem server configuration"
                    ),
                    evidence=f"dependency: {gem_name}",
                    remediation=(
                        f"Configure a private gem server for '{gem_name}' via "
                        "a custom ``source`` block in Gemfile, or use git/path "
                        "sources to prevent bundler from resolving it from rubygems.org."
                    ),
                    references=[
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                        "https://bundler.io/man/gemfile.5.html",
                    ],
                    ecosystem="rubygems",
                )
            )

    return findings