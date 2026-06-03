"""
RubyGems-specific detection and parsing utilities for Ruby projects.

Analogues of ``cargo_utils.py`` but for the RubyGems ecosystem.

Provides:
- ``detect_rubygems_project()`` — check for RubyGems indicator files
- ``parse_gemfile()`` — parse Gemfile (Ruby DSL) for gem dependencies
- ``parse_gemfile_lock()`` — parse Gemfile.lock for pinned gem versions
- ``get_rubygems_dep_names()`` — extract gem names from parsed data
- ``detect_private_rubygems_source()`` — check for private gem source configuration
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.rubygems_utils")

# ── Ruby DSL patterns ─────────────────────────────────────────────────────

# Gemfile: gem "name", "~> 1.0"
_GEMFILE_GEM_RE = re.compile(
    r"^\s*gem\s+['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?\s*(?:,\s*(?:git|path|group|require|platforms)\s*:.*)?$"
)
# Gemfile: gem "name", git: "url"
_GEMFILE_GIT_RE = re.compile(
    r"^\s*gem\s+['\"]([^'\"]+)['\"].*,\s*git:\s*['\"]([^'\"]+)['\"]"
)
# Gemfile: gem "name", path: "path"
_GEMFILE_PATH_RE = re.compile(
    r"^\s*gem\s+['\"]([^'\"]+)['\"].*,\s*path:\s*['\"]([^'\"]+)['\"]"
)
# Gemfile source block
_GEMFILE_SOURCE_RE = re.compile(
    r"^\s*source\s+['\"]([^'\"]+)['\"]"
)
# Gemfile group block start
_GEMFILE_GROUP_START_RE = re.compile(
    r"^\s*group\s+:"
)
# Gemfile end keyword
_GEMFILE_END_RE = re.compile(r"^\s*end\s*$")

# Gemfile.lock patterns
_GEMFILE_LOCK_GEM_START = re.compile(r"^GEM$")
_GEMFILE_LOCK_GIT_START = re.compile(r"^GIT$")
_GEMFILE_LOCK_PATH_START = re.compile(r"^PATH$")
_GEMFILE_LOCK_SPEC_RE = re.compile(r"^\s{4}([a-zA-Z0-9_][a-zA-Z0-9_.-]*)\s+\(([^)]+)\)")
_GEMFILE_LOCK_REMOTE_RE = re.compile(r"^\s{2}remote:\s+(.+)")
_GEMFILE_LOCK_PLATFORMS_START = re.compile(r"^PLATFORMS$")
_GEMFILE_LOCK_DEPENDENCIES_START = re.compile(r"^DEPENDENCIES$")
_GEMFILE_LOCK_SPECS_START = re.compile(r"^\s*specs:\s*$")


# ── Package detection ──────────────────────────────────────────────────────


def detect_rubygems_project(target: Path) -> bool:
    """Check if the target directory contains a RubyGems project.

    Returns True if any of these indicator files exist:
    - Gemfile (primary indicator)
    - Gemfile.lock (lockfile)
    - *.gemspec (gem specification)
    """
    if not target.is_dir():
        return False

    if (target / "Gemfile").is_file():
        return True
    if (target / "Gemfile.lock").is_file():
        return True
    if list(target.glob("*.gemspec")):
        return True

    return False


# ── Gemfile parsing ────────────────────────────────────────────────────────


def parse_gemfile(target: Path) -> dict | None:
    """Parse ``Gemfile`` (Ruby DSL) for gem dependencies.

    Uses line-by-line regex — does NOT execute Ruby code.
    This covers the common patterns:
    - ``gem "name", "~> 1.0"`` — simple gem declaration
    - ``gem "name", git: "url"`` — git source
    - ``gem "name", path: "path"`` — local path
    - ``source "url"`` — custom source
    - ``group :development do ... end`` — group blocks

    Returns a dict with:
    - ``sources``: list of source URLs (default is rubygems.org)
    - ``dependencies``: list of (gem_name, version, source_type) tuples
    - ``git_deps``: set of gem names from git sources
    - ``path_deps``: set of gem names from path sources

    Returns None if Gemfile doesn't exist or is unparseable.
    """
    gemfile_path = target / "Gemfile"
    if not gemfile_path.is_file():
        return None

    try:
        lines = gemfile_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    result: dict = {
        "sources": ["https://rubygems.org"],  # default source
        "dependencies": [],
        "git_deps": set(),
        "path_deps": set(),
    }

    in_group = 0

    for line in lines:
        stripped = line.strip()

        # Skip comments and blank lines
        if not stripped or stripped.startswith("#"):
            continue

        # Handle group blocks
        if _GEMFILE_GROUP_START_RE.match(stripped):
            in_group += 1
            continue

        if _GEMFILE_END_RE.match(stripped):
            if in_group > 0:
                in_group -= 1
            continue

        # Source directive
        source_match = _GEMFILE_SOURCE_RE.match(stripped)
        if source_match:
            url = source_match.group(1)
            if url not in result["sources"]:
                result["sources"].append(url)
            continue

        # Gem declaration
        gem_match = _GEMFILE_GEM_RE.match(stripped)
        if gem_match:
            gem_name = gem_match.group(1)
            version = gem_match.group(2) if gem_match.group(2) else ""

            # Check for git/path sources
            git_match = _GEMFILE_GIT_RE.match(stripped)
            path_match = _GEMFILE_PATH_RE.match(stripped)

            if git_match:
                result["git_deps"].add(gem_name)
                result["dependencies"].append((gem_name, version, "git"))
            elif path_match:
                result["path_deps"].add(gem_name)
                result["dependencies"].append((gem_name, version, "path"))
            else:
                result["dependencies"].append((gem_name, version, "rubygems"))
            continue

    return result


# ── Gemfile.lock parsing ───────────────────────────────────────────────────


def parse_gemfile_lock(target: Path) -> list[dict] | None:
    """Parse ``Gemfile.lock`` for pinned gem versions.

    Gemfile.lock has sections like::

        GEM
          remote: https://rubygems.org/
          specs:
            actionpack (7.0.0)
              activesupport (= 7.0.0)
              rack (~> 2.2)

    Returns list of dicts with:
    - ``name``: gem name
    - ``version``: pinned version
    - ``source``: remote URL
    - ``source_type``: "gem", "git", or "path"

    Returns None if Gemfile.lock doesn't exist.
    """
    lock_path = target / "Gemfile.lock"
    if not lock_path.is_file():
        return None

    try:
        lines = lock_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    gems: list[dict] = []
    current_section = ""
    current_remote = ""
    current_source_type = "gem"
    current_gem: dict = {}

    for line in lines:
        stripped = line.strip()
        rline = line.rstrip()  # preserve leading whitespace for indentation-sensitive patterns

        if not stripped:
            continue

        # Section headers
        if _GEMFILE_LOCK_GEM_START.match(stripped):
            current_section = "GEM"
            current_source_type = "gem"
            current_remote = ""
            continue
        if _GEMFILE_LOCK_GIT_START.match(stripped):
            current_section = "GIT"
            current_source_type = "git"
            current_remote = ""
            continue
        if _GEMFILE_LOCK_PATH_START.match(stripped):
            current_section = "PATH"
            current_source_type = "path"
            current_remote = ""
            continue
        if _GEMFILE_LOCK_PLATFORMS_START.match(stripped):
            current_section = "PLATFORMS"
            continue
        if _GEMFILE_LOCK_DEPENDENCIES_START.match(stripped):
            current_section = "DEPENDENCIES"
            continue
        if _GEMFILE_LOCK_SPECS_START.match(stripped):
            continue

        # Remote URL line — match on raw line to preserve indentation
        remote_match = _GEMFILE_LOCK_REMOTE_RE.match(rline)
        if remote_match and current_section in ("GEM", "GIT", "PATH"):
            current_remote = remote_match.group(1)
            continue

        # Spec line (4-space indent with version in parens) — match on raw line
        spec_match = _GEMFILE_LOCK_SPEC_RE.match(rline)
        if spec_match and current_section in ("GEM", "GIT", "PATH"):
            # Save previous gem if exists
            if current_gem.get("name"):
                gems.append(current_gem)
            current_gem = {
                "name": spec_match.group(1),
                "version": spec_match.group(2),
                "source": current_remote,
                "source_type": current_source_type,
            }
            continue

    # Save last gem
    if current_gem.get("name"):
        gems.append(current_gem)

    return gems if gems else None


# ── Dependency name extraction ─────────────────────────────────────────────


def get_rubygems_dep_names(gemfile_data: dict) -> set[str]:
    """Extract dependency gem names from parsed Gemfile data.

    Returns a set of gem names (e.g. ``rails``, ``devise``).
    """
    names: set[str] = set()

    for gem_name, version, source_type in gemfile_data.get("dependencies", []):
        if gem_name:
            names.add(gem_name)

    return names


# ── Private gem server detection ───────────────────────────────────────────


def detect_private_rubygems_source(target: Path) -> bool:
    """Check if a private RubyGems source is configured.

    Looks for:
    - ``source`` blocks in Gemfile with non-public URLs
    - ``git`` or ``path`` sources in Gemfile
    - ``.gemrc`` file with custom sources
    - ``.bundle/config`` with custom sources

    Returns True if any private source configuration is found.
    """
    # Check Gemfile for custom sources
    gemfile_data = parse_gemfile(target)
    if gemfile_data:
        # Check for non-public source URLs
        for url in gemfile_data.get("sources", []):
            url_lower = url.lower().rstrip("/")
            if "rubygems.org" not in url_lower:
                return True

        # Git/path dependencies indicate private gems
        if gemfile_data.get("git_deps"):
            return True
        if gemfile_data.get("path_deps"):
            return True

    # Check .gemrc
    gemrc_path = target / ".gemrc"
    if gemrc_path.is_file():
        try:
            content = gemrc_path.read_text(encoding="utf-8", errors="replace")
            for url in re.findall(r"https?://[^\s'\"]+", content):
                if "rubygems" not in url.lower():
                    return True
        except OSError:
            pass

    # Check .bundle/config
    bundle_config = target / ".bundle" / "config"
    if bundle_config.is_file():
        try:
            content = bundle_config.read_text(encoding="utf-8", errors="replace")
            if "BUNDLE_SPECIFIC_SOURCE" in content or "BUNDLE_MIRROR" in content:
                return True
            for url in re.findall(r"https?://[^\s'\"]+", content):
                if "rubygems" not in url.lower():
                    return True
        except OSError:
            pass

    return False