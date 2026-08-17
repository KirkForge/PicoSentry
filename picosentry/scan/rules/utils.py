from __future__ import annotations

import json
import threading
from collections import OrderedDict
from pathlib import Path


_INSTALL_SCRIPT_KEYS = frozenset({"install", "postinstall", "preinstall", "prepare"})


def detect_npm_project(target: Path) -> bool:
    return (target / "package.json").is_file() or (target / "node_modules").is_dir()


def has_execution_risk(pkg: dict, pkg_json_path: Path) -> bool:
    """True when a manifest carries a supply-chain risk signal.

    Informational npm metadata rules (engines/license/repository/maintainer)
    only report when the package can execute code on install (install hooks
    present) or is a *dependency* (lives under node_modules) — a clean root
    project with a sparse manifest is normal, not a finding.
    """
    scripts = pkg.get("scripts", {})
    if isinstance(scripts, dict) and _INSTALL_SCRIPT_KEYS & set(scripts.keys()):
        return True
    return "node_modules" in pkg_json_path.parts


def load_package_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(data, dict):
            return {}
        return data
    except (json.JSONDecodeError, OSError):
        return {}


def get_dep_names(pkg: dict) -> set[str]:
    names: set[str] = set()
    for key in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        section = pkg.get(key)
        if isinstance(section, dict):
            names.update(section.keys())
    return names


def get_dep_names_with_specs(pkg: dict) -> dict[str, str]:
    """Dependency name → raw version spec (e.g. ``{"lodash": "^4.17.15"}``)."""
    deps: dict[str, str] = {}
    for key in ("dependencies", "optionalDependencies"):
        section = pkg.get(key)
        if isinstance(section, dict):
            for name, spec in section.items():
                deps[name] = spec if isinstance(spec, str) else str(spec)
    return deps


def iter_node_modules(target: Path):
    nm = target / "node_modules"
    if not nm.is_dir():
        return

    def _walk_nm(nm_dir: Path, visited: set[Path] | None = None):
        if visited is None:
            visited = set()
        real = nm_dir.resolve()
        if real in visited:
            return  # prevent symlink cycles
        visited.add(real)

        for child in sorted(nm_dir.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue

            if child.name.startswith("@") and child.is_dir():
                for scoped_child in sorted(child.iterdir()):
                    if not scoped_child.is_dir():
                        continue
                    scoped_pkg = scoped_child / "package.json"
                    if scoped_pkg.is_file():
                        pkg = load_package_json(scoped_pkg)
                        if pkg:
                            yield scoped_pkg, pkg
                        else:
                            synth_name = f"{child.name}/{scoped_child.name}"
                            yield scoped_pkg, {"name": synth_name, "version": "0.0.0"}

                    nested_nm = scoped_child / "node_modules"
                    if nested_nm.is_dir():
                        yield from _walk_nm(nested_nm, visited)
                continue

            pkg_json = child / "package.json"
            if pkg_json.is_file():
                pkg = load_package_json(pkg_json)
                if pkg:
                    yield pkg_json, pkg

            nested_nm = child / "node_modules"
            if nested_nm.is_dir():
                yield from _walk_nm(nested_nm, visited)

    yield from _walk_nm(nm)


def iter_source_files(
    pkg_dir: Path,
    extensions: frozenset[str] | set[str],
    *,
    max_files: int,
    skip_dirs: frozenset[str] | set[str],
):
    """Yield up to ``max_files`` source files from ONE sorted walk of ``pkg_dir``.

    Replaces the former per-extension ``rglob(f"*{ext}")`` loops in the
    file-content rules (WO4.0.0-014): those re-walked the package directory
    once per extension, multiplying scandir/stat cost by len(extensions).
    Sorted order keeps file selection deterministic regardless of filesystem
    ordering.
    """
    count = 0
    for src_file in sorted(pkg_dir.rglob("*")):
        if count >= max_files:
            return
        if src_file.suffix not in extensions:
            continue
        if src_file.is_symlink():
            continue
        if not src_file.is_file():
            continue
        if any(part in skip_dirs for part in src_file.parts):
            continue
        yield src_file
        count += 1


# ponytail: per-process stat-keyed read cache shared by the file-content rules
# (campaigns + pattern rules + credential scanner). Ceiling: 64MB FIFO, entries
# ≤512KB. Invalidation is (mtime_ns, size) — same identity the corpus index
# cache uses. Upgrade path: drop the cache if a scan is ever single-rule.
_CACHEABLE_FILE_BYTES = 512_000
_FILE_CACHE_MAX_BYTES = 64 * 1024 * 1024
_file_cache: OrderedDict[tuple[str, int, int], bytes] = OrderedDict()
_file_cache_bytes = 0
_file_cache_lock = threading.Lock()
_CACHE_MISS = object()


def read_scannable_bytes(path: Path) -> bytes | None:
    """Read ``path`` once per process per (mtime_ns, size) identity (WO4.0.0-014).

    Returns None on read errors. Files larger than 512KB are read but not
    cached — every content rule already skips them, so they are one-shot reads
    at most. Callers keep their own symlink/size/skip-dir gating; the cache is
    keyed by absolute identity, so a rewritten fixture (new mtime) is re-read.
    """
    try:
        st = path.stat()
    except OSError:
        return None
    cacheable = st.st_size <= _CACHEABLE_FILE_BYTES
    key = (str(path), st.st_mtime_ns, st.st_size)
    if cacheable:
        with _file_cache_lock:
            hit: object = _file_cache.get(key, _CACHE_MISS)
            if hit is not _CACHE_MISS:
                _file_cache.move_to_end(key)
                return hit  # type: ignore[return-value]
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if cacheable and data:
        global _file_cache_bytes
        with _file_cache_lock:
            _file_cache[key] = data
            _file_cache_bytes += len(data)
            while _file_cache_bytes > _FILE_CACHE_MAX_BYTES:
                _, evicted = _file_cache.popitem(last=False)
                _file_cache_bytes -= len(evicted)
    return data
