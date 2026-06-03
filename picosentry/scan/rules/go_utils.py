"""
Go-specific iteration and parsing utilities.

Analogues of ``iter_node_modules()`` and related functions from utils.py
but for the Go module ecosystem.

Provides:
- ``detect_go_project()`` — check for Go indicator files (go.mod, go.sum)
- ``parse_go_mod()`` — parse go.mod for module path, go version, direct dependencies
- ``parse_go_sum()`` — parse go.sum for pinned dependency hashes
- ``get_go_dep_names()`` — extract dependency module paths from parsed go.mod
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.go_utils")

# ── Go module patterns ──────────────────────────────────────────────────

_GO_MOD_REQUIRE_RE = re.compile(
    r'\trequire\s+(\S+)\s+(\S+)'  # tab-prefixed single require line
)
_GO_MOD_PAREN_REQUIRE_RE = re.compile(
    r'\t(\S+)\s+(\S+)'  # tab-indented line within require () block
)
_GO_MOD_REPLACE_RE = re.compile(
    r'^\t?replace\s+(\S+)\s*=>\s*(\S+)'  # replace directive with => separator
)
_GO_MOD_EXCLUDE_RE = re.compile(
    r'\texclude\s+(\S+)\s+(\S+)'
)

# ── Package detection ──────────────────────────────────────────────────


def detect_go_project(target: Path) -> bool:
    """Check if the target directory contains a Go project.

    Returns True if any of these indicator files exist:
    - go.mod
    - go.sum
    - vendor/ directory with modules.json
    """
    if not target.is_dir():
        return False

    if (target / "go.mod").is_file():
        return True
    if (target / "go.sum").is_file():
        return True

    return False


# ── go.mod parsing ──────────────────────────────────────────────────────


def parse_go_mod(target: Path) -> dict | None:
    """Parse ``go.mod`` file for module metadata and dependencies.

    Returns a dict with:
    - ``module``: the module path (e.g. ``github.com/user/project``)
    - ``go_version``: the Go version (e.g. ``1.21``)
    - ``require``: list of ``(module_path, version)`` direct dependencies
    - ``indirect``: list of ``(module_path, version)`` indirect dependencies
    - ``replace``: dict of ``{module_path: replacement_path}``
    - ``exclude``: list of ``(module_path, version)`` excluded versions

    Returns None if go.mod doesn't exist or is unparseable.
    """
    go_mod_path = target / "go.mod"
    if not go_mod_path.is_file():
        return None

    try:
        lines = go_mod_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    result: dict = {
        "module": "",
        "go_version": "",
        "require": [],
        "indirect": [],
        "replace": {},
        "exclude": [],
    }

    in_require_block = False
    require_indirect = False

    for line in lines:
        stripped = line.strip()

        # Module declaration
        if stripped.startswith("module "):
            result["module"] = stripped[7:].strip()

        # Go version
        elif stripped.startswith("go "):
            result["go_version"] = stripped[3:].strip()

        # Track require block state
        elif stripped == "require (":
            in_require_block = True
            require_indirect = False
            continue
        elif stripped == ")":
            if in_require_block:
                in_require_block = False
            continue

        # Single-line require (outside block)
        elif in_require_block is False and stripped.startswith("require "):
            m = _GO_MOD_REQUIRE_RE.match(line)
            if m:
                mod_path = m.group(1)
                version = m.group(2)
                if "// indirect" in line or "//indirect" in line:
                    result["indirect"].append((mod_path, version))
                else:
                    result["require"].append((mod_path, version))
            continue

        # Lines inside require ( ... ) block
        elif in_require_block and stripped:
            m = _GO_MOD_PAREN_REQUIRE_RE.match(line)
            if m:
                mod_path = m.group(1)
                version = m.group(2)
                if "// indirect" in line or "//indirect" in line:
                    result["indirect"].append((mod_path, version))
                else:
                    result["require"].append((mod_path, version))
            continue

        # Replace directives
        elif stripped.startswith("replace "):
            m = _GO_MOD_REPLACE_RE.match(line)
            if m:
                original = m.group(1)
                replacement = m.group(2) if m.group(2) else ""
                result["replace"][original] = replacement

        # Exclude directives
        elif stripped.startswith("exclude "):
            m = _GO_MOD_EXCLUDE_RE.match(line)
            if m:
                result["exclude"].append((m.group(1), m.group(2)))

    return result


# ── go.sum parsing ──────────────────────────────────────────────────────


def parse_go_sum(target: Path) -> list[tuple[str, str, str]]:
    """Parse ``go.sum`` for pinned dependency hashes.

    Returns list of ``(module_path, version, hash)`` tuples.
    Each go.sum line is: ``module version h1:hash``
    Entries can have multiple lines per module (one per version).

    Returns empty list if go.sum doesn't exist.
    """
    go_sum_path = target / "go.sum"
    if not go_sum_path.is_file():
        return []

    try:
        lines = go_sum_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    entries: list[tuple[str, str, str]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Format: module version h1:hash
        parts = line.split(" ")
        if len(parts) >= 3:
            mod_path = parts[0]
            version = parts[1]
            hash_val = parts[2]
            entries.append((mod_path, version, hash_val))

    return entries


# ── Dependency name extraction ──────────────────────────────────────────


def get_go_dep_names(go_mod_data: dict) -> set[str]:
    """Extract dependency module paths from parsed go.mod data.

    Returns a set of full module paths (e.g.
    ``github.com/gin-gonic/gin``).
    """
    names: set[str] = set()

    for mod_path, _version in go_mod_data.get("require", []):
        if mod_path:
            names.add(mod_path)

    for mod_path, _version in go_mod_data.get("indirect", []):
        if mod_path:
            names.add(mod_path)

    return names


def get_module_short_name(module_path: str) -> str:
    """Extract the short name from a Go module path.

    ``github.com/gin-gonic/gin`` → ``gin``
    ``golang.org/x/crypto`` → ``crypto``
    ``k8s.io/client-go`` → ``client-go``
    """
    # Last path segment after the final /
    if "/" in module_path:
        return module_path.rsplit("/", 1)[1]
    return module_path


def detect_goproxy_private(target: Path) -> bool:
    """Check if a private Go proxy is configured.

    Looks for:
    - ``GOPROXY`` in go.env with a private proxy URL
    - ``GONOSUMDB`` or ``GONOSUMCHECK`` entries for private modules
    - ``GOPRIVATE`` setting that indicates a private module path

    Also checks ``go.mod`` for ``replace`` directives pointing to
    local paths — a common pattern for private module development.
    """
    # Check go.env
    go_env = target / "go.env"
    if go_env.is_file():
        try:
            content = go_env.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("GOPROXY=") and "proxy.golang.org" not in line and "direct" not in line:
                    return True
                if line.startswith("GONOSUMDB=") or line.startswith("GONOSUMCHECK="):
                    return True
                if line.startswith("GOPRIVATE="):
                    return True
        except OSError:
            pass

    # Check go.mod for replace directives with local paths
    go_mod_data = parse_go_mod(target)
    if go_mod_data:
        for _original, replacement in go_mod_data.get("replace", {}).items():
            # Local path replacements (relative or absolute paths, not versions)
            if replacement and replacement.startswith((".", "/", "../")):
                return True

    return False