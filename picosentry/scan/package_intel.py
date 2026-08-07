from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SPDX_LICENSES = frozenset(
    {
        "0BSD",
        "AAL",
        "AFL-3.0",
        "AGPL-1.0",
        "AGPL-1.0-only",
        "AGPL-1.0-or-later",
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "Apache-1.0",
        "Apache-1.1",
        "Apache-2.0",
        "APSL-1.0",
        "APSL-2.0",
        "Artistic-1.0",
        "Artistic-2.0",
        "BSD-1-Clause",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "CAL-1.0",
        "CATOSL-1.1",
        "CC0-1.0",
        "CDDL-1.0",
        "CDDL-1.1",
        "CECILL-2.1",
        "CNRI-Python",
        "ECL-1.0",
        "ECL-2.0",
        "EFL-1.0",
        "EFL-2.0",
        "Entessa",
        "EPL-1.0",
        "EPL-2.0",
        "EUDatagrid",
        "EUPL-1.1",
        "EUPL-1.2",
        "Fair",
        "Frameworx-1.0",
        "GPL-1.0",
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "IPL-1.0",
        "ISC",
        "LGPL-2.0",
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "LiLiQ-P-1.1",
        "LiLiQ-R-1.1",
        "LiLiQ-Rplus-1.1",
        "LPL-1.0",
        "LPL-1.02",
        "LPPL-1.0",
        "LPPL-1.1",
        "LPPL-1.2",
        "LPPL-1.3c",
        "MIT",
        "MIT-0",
        "MPL-1.0",
        "MPL-1.1",
        "MPL-2.0",
        "MPL-2.0-no-copyleft-exception",
        "MS-PL",
        "MS-RL",
        "MirOS",
        "MulanPSL-2.0",
        "Multics",
        "NASA-1.3",
        "NCSA",
        "NGPL",
        "Nokia",
        "NPOSL-3.0",
        "NTP",
        "OCLC-2.0",
        "OFL-1.1",
        "OGTSL",
        "OSL-1.0",
        "OSL-2.0",
        "OSL-2.1",
        "OSL-3.0",
        "PHP-3.0",
        "PHP-3.01",
        "PostgreSQL",
        "PSF-2.0",
        "Python-2.0",
        "QPL-1.0",
        "RPL-1.1",
        "RPL-1.5",
        "RPSL-1.0",
        "RSCPL",
        "SimPL-2.0",
        "SISSL",
        "Sleepycat",
        "SPL-1.0",
        "UCL-1.0",
        "Unlicense",
        "UPL-1.0",
        "VSL-1.0",
        "W3C",
        "Watcom-1.0",
        "WTFPL",
        "Xnet",
        "Zlib",
        "ZPL-2.0",
        "ZPL-2.1",
    }
)

PRE_RELEASE_PATTERNS = (
    re.compile(r"[-.]?(?:alpha|a|beta|b|rc|dev|pre|preview|canary|nightly|snapshot|test)", re.IGNORECASE),
)

ZERO_MAJOR_RE = re.compile(r"^0\.\d+\.\d+")

INSTALL_SCRIPT_KEYS_NPM = frozenset({"install", "postinstall", "preinstall", "prepare", "prepack", "postpack"})

INSTALL_SCRIPT_KEYS_PYPI = frozenset({"install_scripts", "pre_install", "post_install"})

INSTALL_SCRIPT_KEYS_CARGO: frozenset[str] = frozenset()


@dataclass(frozen=True)
class PackageIntel:
    maintainer_count: int = 0
    anonymous_maintainer: bool = False
    maintainer_email_domains: tuple[str, ...] = ()
    has_repository_url: bool = False
    has_integrity_hash: bool = False
    has_signature: bool = False
    version_count: int = 0
    is_pre_release: bool = False
    is_zero_major: bool = False
    direct_dep_count: int = 0
    has_deps_with_install_scripts: bool = False
    has_install_scripts: bool = False
    has_postinstall_script: bool = False
    has_preinstall_script: bool = False
    has_license: bool = False
    license_spdx_compliant: bool = False
    risk_score: float = 0.0


def _extract_maintainer_count(data: dict[str, Any]) -> int:
    count = 0
    maintainers = data.get("maintainers")
    if isinstance(maintainers, list):
        count = len(maintainers)
    if count == 0:
        authors = data.get("authors")
        if isinstance(authors, list):
            count = len(authors)
    if count == 0:
        author = data.get("author")
        if author:
            count = 1
    return count


def _extract_anonymous_maintainer(data: dict[str, Any]) -> bool:
    for field_name in ("maintainers", "authors", "contributors"):
        people = data.get(field_name, [])
        if isinstance(people, list):
            for person in people:
                if isinstance(person, dict):
                    name = str(person.get("name", "")).strip()
                    email = str(person.get("email", "")).strip()
                    if not name and not email:
                        return True
                    if name.lower() in ("anonymous", "unknown", "n/a", ""):
                        return True
                elif isinstance(person, str):
                    if not person.strip() or person.strip().lower() in ("anonymous", "unknown"):
                        return True
    author = data.get("author")
    if isinstance(author, dict):
        name = str(author.get("name", "")).strip()
        if not name or name.lower() in ("anonymous", "unknown", "n/a"):
            return True
    elif isinstance(author, str):
        if not author.strip() or author.strip().lower() in ("anonymous", "unknown"):
            return True
    return False


def _extract_maintainer_domains(data: dict[str, Any]) -> tuple[str, ...]:
    domains: set[str] = set()
    for field_name in ("maintainers", "authors", "contributors"):
        people = data.get(field_name, [])
        if isinstance(people, list):
            for person in people:
                if isinstance(person, dict):
                    email = str(person.get("email", ""))
                    if "@" in email:
                        domains.add(email.rsplit("@", 1)[-1].lower().strip(">"))
                elif isinstance(person, str) and "@" in person:
                    domains.add(person.rsplit("@", 1)[-1].strip(">").lower())
    author = data.get("author")
    author_email = data.get("author_email", "")
    if isinstance(author_email, str) and "@" in author_email:
        domains.add(author_email.rsplit("@", 1)[-1].lower().strip(">"))
    if isinstance(author, dict):
        email = str(author.get("email", ""))
        if "@" in email:
            domains.add(email.rsplit("@", 1)[-1].lower().strip(">"))
    elif isinstance(author, str) and "@" in author:
        domains.add(author.rsplit("@", 1)[-1].strip(">").lower())
    return tuple(sorted(domains))


def _extract_has_repository(data: dict[str, Any]) -> bool:
    repo = data.get("repository")
    if not repo:
        homepage = data.get("homepage", "")
        return bool(homepage and "github.com" in homepage.lower())
    if isinstance(repo, str):
        return bool(repo.strip())
    if isinstance(repo, dict):
        return bool(repo.get("url", "").strip())
    return False


def _extract_has_integrity(data: dict[str, Any]) -> bool:
    for key in ("_integrity", "_shasum", "integrity"):
        val = data.get(key)
        if val and isinstance(val, str) and val.strip():
            return True
    return False


def _extract_has_signature(data: dict[str, Any]) -> bool:
    sigs = data.get("_signatures")
    if isinstance(sigs, list) and len(sigs) > 0:
        return True
    provenance = data.get("provenance")
    if isinstance(provenance, dict) and provenance.get("attestations"):
        return True
    attestations = data.get("attestations")
    return isinstance(attestations, dict) and len(attestations) > 0


def _extract_version_signals(data: dict[str, Any]) -> tuple[bool, bool]:
    version = str(data.get("version", ""))
    is_pre_release = False
    is_zero_major = False
    if version:
        for pat in PRE_RELEASE_PATTERNS:
            if pat.search(version):
                is_pre_release = True
                break
        if ZERO_MAJOR_RE.match(version):
            is_zero_major = True
    return is_pre_release, is_zero_major


def _extract_dep_counts_npm(data: dict[str, Any]) -> tuple[int, bool]:
    total = 0
    for section_name in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = data.get(section_name)
        if isinstance(section, dict):
            total += len(section)
    has_script_deps = False
    optional_deps = data.get("optionalDependencies", {})
    if isinstance(optional_deps, dict):
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict) and INSTALL_SCRIPT_KEYS_NPM & set(scripts.keys()):
            has_script_deps = bool(optional_deps)
    return total, has_script_deps


def _extract_dep_counts_pypi(data: dict[str, Any]) -> tuple[int, bool]:
    total = 0
    requires_dist = data.get("requires_dist") or data.get("Requires-Dist")
    if isinstance(requires_dist, list):
        total = len(requires_dist)
    deps = data.get("dependencies", [])
    if isinstance(deps, list):
        total += len(deps)
    return total, False


def _extract_dep_counts_cargo(data: dict[str, Any]) -> tuple[int, bool]:
    total = 0
    for section_name in ("dependencies", "dev-dependencies", "build-dependencies"):
        section = data.get(section_name)
        if isinstance(section, dict):
            total += len(section)
    return total, False


def _extract_dep_counts_go(data: dict[str, Any]) -> tuple[int, bool]:
    requires = data.get("require", [])
    if isinstance(requires, list):
        return len(requires), False
    return 0, False


def _extract_dep_counts_maven(data: dict[str, Any]) -> tuple[int, bool]:
    deps = data.get("dependencies", [])
    if isinstance(deps, list):
        return len(deps), False
    return 0, False


def _extract_dep_counts_rubygems(data: dict[str, Any]) -> tuple[int, bool]:
    deps = data.get("dependencies", {})
    if isinstance(deps, dict):
        total = sum(len(v) if isinstance(v, list) else 1 for v in deps.values())
        return total, False
    return 0, False


def _extract_dep_counts_nuget(data: dict[str, Any]) -> tuple[int, bool]:
    deps = data.get("dependencies", {})
    if isinstance(deps, dict):
        return len(deps), False
    return 0, False


def _extract_script_signals_npm(data: dict[str, Any]) -> tuple[bool, bool, bool]:
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return False, False, False
    has_install = bool(INSTALL_SCRIPT_KEYS_NPM & set(scripts.keys()))
    has_postinstall = "postinstall" in scripts
    has_preinstall = "preinstall" in scripts
    return has_install, has_postinstall, has_preinstall


def _extract_script_signals_pypi(data: dict[str, Any]) -> tuple[bool, bool, bool]:
    has_install = bool(data.get("has_setup_py") or data.get("has_setup_cfg_scripts"))
    has_postinstall = bool(data.get("has_post_install"))
    has_preinstall = bool(data.get("has_pre_install"))
    return has_install, has_postinstall, has_preinstall


def _extract_script_signals_cargo(data: dict[str, Any]) -> tuple[bool, bool, bool]:
    _ = data
    return False, False, False


def _extract_script_signals_go(data: dict[str, Any]) -> tuple[bool, bool, bool]:
    _ = data
    return False, False, False


def _extract_script_signals_maven(data: dict[str, Any]) -> tuple[bool, bool, bool]:
    plugins = data.get("build_plugins", [])
    if isinstance(plugins, list):
        for p in plugins:
            if isinstance(p, dict) and p.get("executions"):
                return True, False, False
    return False, False, False


def _extract_script_signals_rubygems(data: dict[str, Any]) -> tuple[bool, bool, bool]:
    extensions = data.get("extensions", [])
    if isinstance(extensions, list) and len(extensions) > 0:
        return True, False, False
    return False, False, False


def _extract_script_signals_nuget(data: dict[str, Any]) -> tuple[bool, bool, bool]:
    _ = data
    return False, False, False


def _extract_license_signals(data: dict[str, Any]) -> tuple[bool, bool]:
    license_field = data.get("license")
    if license_field is None:
        return False, False
    if isinstance(license_field, dict):
        license_str = str(license_field.get("type", ""))
    elif isinstance(license_field, str):
        license_str = license_field.strip()
    else:
        license_str = str(license_field).strip()
    if not license_str:
        return True, False
    if license_str.upper() == "UNLICENSED":
        return True, False
    is_spdx = license_str in SPDX_LICENSES
    if not is_spdx:
        for spdx_id in SPDX_LICENSES:
            if license_str.lower() == spdx_id.lower():
                is_spdx = True
                break
        if " OR " in license_str:
            for raw_segment in license_str.split(" OR "):
                stripped = raw_segment.strip().strip("()")
                if stripped in SPDX_LICENSES:
                    is_spdx = True
                    break
    return True, is_spdx


_ECOSYSTEM_EXTRACTORS = {
    "npm": {
        "dep_counts": _extract_dep_counts_npm,
        "script_signals": _extract_script_signals_npm,
    },
    "pypi": {
        "dep_counts": _extract_dep_counts_pypi,
        "script_signals": _extract_script_signals_pypi,
    },
    "cargo": {
        "dep_counts": _extract_dep_counts_cargo,
        "script_signals": _extract_script_signals_cargo,
    },
    "go": {
        "dep_counts": _extract_dep_counts_go,
        "script_signals": _extract_script_signals_go,
    },
    "golang": {
        "dep_counts": _extract_dep_counts_go,
        "script_signals": _extract_script_signals_go,
    },
    "maven": {
        "dep_counts": _extract_dep_counts_maven,
        "script_signals": _extract_script_signals_maven,
    },
    "rubygems": {
        "dep_counts": _extract_dep_counts_rubygems,
        "script_signals": _extract_script_signals_rubygems,
    },
    "nuget": {
        "dep_counts": _extract_dep_counts_nuget,
        "script_signals": _extract_script_signals_nuget,
    },
}


def _compute_risk_score(intel: PackageIntel) -> float:
    risk = 0.0
    if intel.maintainer_count == 0:
        risk += 0.20
    elif intel.maintainer_count == 1:
        risk += 0.10
    if intel.anonymous_maintainer:
        risk += 0.10
    if len(intel.maintainer_email_domains) == 0 and intel.maintainer_count > 0:
        risk += 0.05
    if not intel.has_repository_url:
        risk += 0.05
    if not intel.has_integrity_hash:
        risk += 0.05
    if not intel.has_signature:
        risk += 0.03
    if intel.is_pre_release:
        risk += 0.05
    if intel.is_zero_major:
        risk += 0.05
    if intel.direct_dep_count > 50:
        risk += 0.05
    elif intel.direct_dep_count > 20:
        risk += 0.03
    if intel.has_deps_with_install_scripts:
        risk += 0.10
    if intel.has_install_scripts:
        risk += 0.10
    if intel.has_postinstall_script:
        risk += 0.07
    if not intel.has_license:
        risk += 0.05
    elif not intel.license_spdx_compliant:
        risk += 0.02
    return min(round(risk, 2), 1.0)


class PackageIntelligence:
    def analyze(self, manifest_data: dict[str, Any], ecosystem: str = "npm") -> PackageIntel:
        extractors = _ECOSYSTEM_EXTRACTORS.get(ecosystem, _ECOSYSTEM_EXTRACTORS["npm"])
        maintainer_count = _extract_maintainer_count(manifest_data)
        anonymous_maintainer = _extract_anonymous_maintainer(manifest_data)
        maintainer_domains = _extract_maintainer_domains(manifest_data)
        has_repository_url = _extract_has_repository(manifest_data)
        has_integrity_hash = _extract_has_integrity(manifest_data)
        has_signature = _extract_has_signature(manifest_data)
        is_pre_release, is_zero_major = _extract_version_signals(manifest_data)
        direct_dep_count, has_deps_with_install_scripts = extractors["dep_counts"](manifest_data)
        has_install_scripts, has_postinstall, has_preinstall = extractors["script_signals"](manifest_data)
        has_license, license_spdx = _extract_license_signals(manifest_data)

        has_deps_with_install_scripts = bool(has_deps_with_install_scripts)
        has_install_scripts = bool(has_install_scripts)
        has_postinstall = bool(has_postinstall)
        has_preinstall = bool(has_preinstall)

        intel = PackageIntel(
            maintainer_count=maintainer_count,
            anonymous_maintainer=anonymous_maintainer,
            maintainer_email_domains=maintainer_domains,
            has_repository_url=has_repository_url,
            has_integrity_hash=has_integrity_hash,
            has_signature=has_signature,
            is_pre_release=is_pre_release,
            is_zero_major=is_zero_major,
            direct_dep_count=direct_dep_count,
            has_deps_with_install_scripts=has_deps_with_install_scripts,
            has_install_scripts=has_install_scripts,
            has_postinstall_script=has_postinstall,
            has_preinstall_script=has_preinstall,
            has_license=has_license,
            license_spdx_compliant=license_spdx,
        )
        risk = _compute_risk_score(intel)
        return PackageIntel(
            maintainer_count=maintainer_count,
            anonymous_maintainer=anonymous_maintainer,
            maintainer_email_domains=maintainer_domains,
            has_repository_url=has_repository_url,
            has_integrity_hash=has_integrity_hash,
            has_signature=has_signature,
            is_pre_release=is_pre_release,
            is_zero_major=is_zero_major,
            direct_dep_count=direct_dep_count,
            has_deps_with_install_scripts=has_deps_with_install_scripts,
            has_install_scripts=has_install_scripts,
            has_postinstall_script=has_postinstall,
            has_preinstall_script=has_preinstall,
            has_license=has_license,
            license_spdx_compliant=license_spdx,
            risk_score=risk,
        )
