
from __future__ import annotations

import re
from dataclasses import dataclass, field

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass(frozen=True)
class PnpmPackage:

    name: str
    version: str
    resolution: str = ""
    integrity: str = ""
    deps: tuple[str, ...] = ()
    is_aliased: bool = False


@dataclass
class PnpmLockfile:

    lockfile_version: str = ""
    importers: dict[str, dict[str, str]] = field(default_factory=dict)
    packages: dict[str, PnpmPackage] = field(default_factory=dict)
    checksums: dict[str, str] = field(default_factory=dict)


def parse_pnpm_lockfile(content: str) -> PnpmLockfile:
    if YAML_AVAILABLE:
        return _parse_with_yaml(content)
    return _parse_with_regex(content)


def _parse_with_yaml(content: str) -> PnpmLockfile:
    lockfile = PnpmLockfile()

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return lockfile

    if not isinstance(data, dict):
        return lockfile


    lockfile.lockfile_version = str(data.get("lockfileVersion", ""))


    importers = data.get("importers", {})
    if isinstance(importers, dict):
        for importer_path, importer_data in importers.items():
            if isinstance(importer_data, dict):
                deps = {}
                for dep_type in ("dependencies", "devDependencies", "optionalDependencies"):
                    section = importer_data.get(dep_type, {})
                    if isinstance(section, dict):
                        for name, version_info in section.items():
                            if isinstance(version_info, str):
                                deps[name] = version_info
                            elif isinstance(version_info, dict):
                                deps[name] = version_info.get("version", str(version_info))
                lockfile.importers[importer_path] = deps


    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for pkg_key, pkg_data in packages.items():
            if not isinstance(pkg_data, dict):
                continue
            name, version, is_aliased = _parse_pnpm_pkg_key(pkg_key)
            if not name:
                continue

            resolution = ""
            res = pkg_data.get("resolution", {})
            if isinstance(res, dict):
                resolution = res.get("integrity", "")
            elif isinstance(res, str):
                resolution = res

            integrity = pkg_data.get("resolution", {})
            integrity = integrity.get("integrity", "") if isinstance(integrity, dict) else ""


            pkg_deps: list[str] = []
            for dep_type in ("dependencies", "optionalDependencies"):
                dep_section = pkg_data.get(dep_type, {})
                if isinstance(dep_section, dict):
                    pkg_deps.extend(sorted(dep_section.keys()))

            lockfile.packages[pkg_key] = PnpmPackage(
                name=name,
                version=version or pkg_data.get("version", ""),
                resolution=resolution,
                integrity=integrity,
                deps=tuple(pkg_deps),
                is_aliased=is_aliased,
            )

    return lockfile


def _parse_pnpm_pkg_key(key: str) -> tuple[str, str, bool]:

    key = key.lstrip("/")


    is_aliased = "(" in key
    key = key.split("(")[0]


    if key.startswith("@"):

        at_idx = key.find("@", 1)
        if at_idx > 0:
            return key[:at_idx], key[at_idx + 1 :], is_aliased
        return key, "", is_aliased


    at_idx = key.find("@")
    if at_idx > 0:
        return key[:at_idx], key[at_idx + 1 :], is_aliased

    return key, "", is_aliased


def _parse_with_regex(content: str) -> PnpmLockfile:
    lockfile = PnpmLockfile()


    version_match = re.search(r"lockfileVersion:\s*['\"]?([\d.]+)", content)
    if version_match:
        lockfile.lockfile_version = version_match.group(1)


    for line in content.splitlines():
        stripped = line.strip()

        m = re.match(r"^['\"]?/([^@]+)@([\d.]+[^'\":]*)['\"]?:", stripped)
        if m:
            name = m.group(1)
            version = m.group(2).rstrip("'\"")
            key = f"/{name}@{version}"
            lockfile.packages[key] = PnpmPackage(
                name=name,
                version=version,
            )


    in_importers = False
    for line in content.splitlines():
        if line.strip() == "importers:":
            in_importers = True
            continue
        if in_importers:
            if line.startswith(("  ", "\t")):

                pass
            else:

                m = re.match(r"^\s+['\"]?([^'\":]+)['\"]?:", line)
                if m:
                    m.group(1)
                else:
                    in_importers = False

    return lockfile


def get_pnpm_importer_deps(lockfile: PnpmLockfile, importer: str = ".") -> dict[str, str]:
    return lockfile.importers.get(importer, {})


def get_pnpm_package(lockfile: PnpmLockfile, name: str, version: str | None = None) -> PnpmPackage | None:
    for pkg in lockfile.packages.values():
        if pkg.name == name and (version is None or pkg.version == version):
            return pkg
    return None


def find_missing_integrity(lockfile: PnpmLockfile) -> list[tuple[str, str]]:
    return [
        (pkg.name, pkg.version)
        for pkg in lockfile.packages.values()
        if not pkg.integrity and not pkg.resolution
    ]


def find_weak_integrity(lockfile: PnpmLockfile) -> list[tuple[str, str, str]]:


    truly_weak = ("sha1-", "md5-")
    weak = []
    for pkg in lockfile.packages.values():
        integrity = pkg.integrity or pkg.resolution
        if integrity:
            for algo in truly_weak:
                if algo in integrity:
                    weak.append((pkg.name, pkg.version, algo.rstrip("-")))
                    break
    return weak
