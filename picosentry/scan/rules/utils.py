from __future__ import annotations

import json
from pathlib import Path


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
