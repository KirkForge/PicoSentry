
from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("picosentry.go_utils")


_GO_MOD_REQUIRE_RE = re.compile(
    r'^require\s+(\S+)\s+(\S+)'  # column-0 single require line (real-world go.mod format)
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


def detect_go_project(target: Path) -> bool:
    if not target.is_dir():
        return False

    if (target / "go.mod").is_file():
        return True
    return bool((target / "go.sum").is_file())


def parse_go_mod(target: Path) -> dict | None:
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

    for line in lines:
        stripped = line.strip()


        if stripped.startswith("module "):
            result["module"] = stripped[7:].strip()


        elif stripped.startswith("go "):
            result["go_version"] = stripped[3:].strip()


        elif stripped == "require (":
            in_require_block = True
            continue
        elif stripped == ")":
            if in_require_block:
                in_require_block = False
            continue


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


        elif stripped.startswith("replace "):
            m = _GO_MOD_REPLACE_RE.match(line)
            if m:
                original = m.group(1)
                replacement = m.group(2) if m.group(2) else ""
                result["replace"][original] = replacement


        elif stripped.startswith("exclude "):
            m = _GO_MOD_EXCLUDE_RE.match(line)
            if m:
                result["exclude"].append((m.group(1), m.group(2)))

    return result


def parse_go_sum(target: Path) -> list[tuple[str, str, str]]:
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

        parts = line.split(" ")
        if len(parts) >= 3:
            mod_path = parts[0]
            version = parts[1]
            hash_val = parts[2]
            entries.append((mod_path, version, hash_val))

    return entries


def get_go_dep_names(go_mod_data: dict) -> set[str]:
    names: set[str] = set()

    for mod_path, _version in go_mod_data.get("require", []):
        if mod_path:
            names.add(mod_path)

    for mod_path, _version in go_mod_data.get("indirect", []):
        if mod_path:
            names.add(mod_path)

    return names


def get_module_short_name(module_path: str) -> str:

    if "/" in module_path:
        return module_path.rsplit("/", 1)[1]
    return module_path


def detect_goproxy_private(target: Path) -> bool:

    go_env = target / "go.env"
    if go_env.is_file():
        try:
            content = go_env.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("GOPROXY=") and "proxy.golang.org" not in line and "direct" not in line:
                    return True
                if line.startswith(("GONOSUMDB=", "GONOSUMCHECK=")):
                    return True
                if line.startswith("GOPRIVATE="):
                    return True
        except OSError:
            pass


    go_mod_data = parse_go_mod(target)
    if go_mod_data:
        for _original, replacement in go_mod_data.get("replace", {}).items():

            if replacement and replacement.startswith((".", "/", "../")):
                return True

    return False
