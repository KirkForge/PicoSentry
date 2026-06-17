
from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.rubygems_utils")


_GEMFILE_GEM_RE = re.compile(
    r"^\s*gem\s+['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?\s*(?:,\s*(?:git|path|group|require|platforms)\s*:.*)?$"
)

_GEMFILE_GIT_RE = re.compile(
    r"^\s*gem\s+['\"]([^'\"]+)['\"].*,\s*git:\s*['\"]([^'\"]+)['\"]"
)

_GEMFILE_PATH_RE = re.compile(
    r"^\s*gem\s+['\"]([^'\"]+)['\"].*,\s*path:\s*['\"]([^'\"]+)['\"]"
)

_GEMFILE_SOURCE_RE = re.compile(
    r"^\s*source\s+['\"]([^'\"]+)['\"]"
)

_GEMFILE_GROUP_START_RE = re.compile(
    r"^\s*group\s+:"
)

_GEMFILE_END_RE = re.compile(r"^\s*end\s*$")


_GEMFILE_LOCK_GEM_START = re.compile(r"^GEM$")
_GEMFILE_LOCK_GIT_START = re.compile(r"^GIT$")
_GEMFILE_LOCK_PATH_START = re.compile(r"^PATH$")
_GEMFILE_LOCK_SPEC_RE = re.compile(r"^\s{4}([a-zA-Z0-9_][a-zA-Z0-9_.-]*)\s+\(([^)]+)\)")
_GEMFILE_LOCK_REMOTE_RE = re.compile(r"^\s{2}remote:\s+(.+)")
_GEMFILE_LOCK_PLATFORMS_START = re.compile(r"^PLATFORMS$")
_GEMFILE_LOCK_DEPENDENCIES_START = re.compile(r"^DEPENDENCIES$")
_GEMFILE_LOCK_SPECS_START = re.compile(r"^\s*specs:\s*$")


def detect_rubygems_project(target: Path) -> bool:
    if not target.is_dir():
        return False

    if (target / "Gemfile").is_file():
        return True
    if (target / "Gemfile.lock").is_file():
        return True
    return bool(list(target.glob("*.gemspec")))


def parse_gemfile(target: Path) -> dict | None:
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


        if not stripped or stripped.startswith("#"):
            continue


        if _GEMFILE_GROUP_START_RE.match(stripped):
            in_group += 1
            continue

        if _GEMFILE_END_RE.match(stripped):
            if in_group > 0:
                in_group -= 1
            continue


        source_match = _GEMFILE_SOURCE_RE.match(stripped)
        if source_match:
            url = source_match.group(1)
            if url not in result["sources"]:
                result["sources"].append(url)
            continue


        gem_match = _GEMFILE_GEM_RE.match(stripped)
        if gem_match:
            gem_name = gem_match.group(1)
            version = gem_match.group(2) if gem_match.group(2) else ""


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


def parse_gemfile_lock(target: Path) -> list[dict] | None:
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


        remote_match = _GEMFILE_LOCK_REMOTE_RE.match(rline)
        if remote_match and current_section in ("GEM", "GIT", "PATH"):
            current_remote = remote_match.group(1)
            continue


        spec_match = _GEMFILE_LOCK_SPEC_RE.match(rline)
        if spec_match and current_section in ("GEM", "GIT", "PATH"):

            if current_gem.get("name"):
                gems.append(current_gem)
            current_gem = {
                "name": spec_match.group(1),
                "version": spec_match.group(2),
                "source": current_remote,
                "source_type": current_source_type,
            }
            continue


    if current_gem.get("name"):
        gems.append(current_gem)

    return gems if gems else None


def get_rubygems_dep_names(gemfile_data: dict) -> set[str]:
    names: set[str] = set()

    for gem_name, _version, _source_type in gemfile_data.get("dependencies", []):
        if gem_name:
            names.add(gem_name)

    return names


def detect_private_rubygems_source(target: Path) -> bool:

    gemfile_data = parse_gemfile(target)
    if gemfile_data:

        for url in gemfile_data.get("sources", []):
            url_lower = url.lower().rstrip("/")
            if "rubygems.org" not in url_lower:
                return True


        if gemfile_data.get("git_deps"):
            return True
        if gemfile_data.get("path_deps"):
            return True


    gemrc_path = target / ".gemrc"
    if gemrc_path.is_file():
        try:
            content = gemrc_path.read_text(encoding="utf-8", errors="replace")
            for url in re.findall(r"https?://[^\s'\"]+", content):
                if "rubygems" not in url.lower():
                    return True
        except OSError:
            pass


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
