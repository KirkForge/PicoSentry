from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

try:
    from defusedxml.ElementTree import fromstring as _safe_fromstring

    _HAS_DEFUSEDXML = True
except ImportError:
    _HAS_DEFUSEDXML = False

from xml.etree import ElementTree

logger = logging.getLogger("picosentry.sbom")

_PURL_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "golang": "golang",
    "cargo": "cargo",
    "maven": "maven",
    "gem": "rubygems",
    "nuget": "nuget",
}

_SPDX_PKG_MANAGER_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "golang": "golang",
    "cargo": "cargo",
    "maven": "maven",
    "rubygems": "rubygems",
    "nuget": "nuget",
    "gem": "rubygems",
}

_CYCLONEDX_TYPE_MAP: dict[str, str] = {
    "library": "library",
    "framework": "framework",
    "application": "application",
}

_MAX_XML_BYTES = 10 * 1024 * 1024  # ponytail: 10MB cap rejects billion-laughs amplification

# Registry hosts → ecosystem, for purl-less components whose download URL or
# sourceInfo names a known registry (WO5.0.0-016: purl is optional in
# CycloneDX; without a fallback these components vanished silently).
_REGISTRY_HOST_MAP: dict[str, str] = {
    "registry.npmjs.org": "npm",
    "www.npmjs.com": "npm",
    "npmjs.com": "npm",
    "pypi.org": "pypi",
    "files.pythonhosted.org": "pypi",
    "rubygems.org": "rubygems",
    "crates.io": "cargo",
    "static.crates.io": "cargo",
    "repo1.maven.org": "maven",
    "repo.maven.apache.org": "maven",
    "mvnrepository.com": "maven",
    "nuget.org": "nuget",
    "api.nuget.org": "nuget",
    "www.nuget.org": "nuget",
    "proxy.golang.org": "golang",
    "sum.golang.org": "golang",
}

# Go module paths start with a host ("github.com/owner/repo"); npm scoped
# names ("@scope/pkg") never contain a dot-host segment.
_GO_MODULE_PATH_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:/[^/\s]+){2,}$")
# Maven coordinates "org.apache.commons:commons-io" (reverse-domain group).
_MAVEN_COORDS_RE = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+:[^/\s:]+$")


def _purl_namespace(purl: str) -> str:
    """Namespace segment of a purl: pkg:maven/org.apache/commons-io@1.4 -> 'org.apache'."""
    if not purl.startswith("pkg:"):
        return ""
    body = purl[4:].split("@", 1)[0].split("?", 1)[0]
    segments = body.split("/")
    return "/".join(segments[1:-1]) if len(segments) >= 3 else ""


def _maven_display_name(name: str, group: str, purl: str) -> str:
    """Maven coordinates as 'group:artifact' (WO4.0.0-015).

    Maven SBOM components carry the artifact in ``name`` and the groupId in
    ``group`` (CycloneDX) or the purl namespace. Without the group the
    generated pom.xml cannot carry both <groupId> and <artifactId>, and the
    maven parsers drop the dependency entirely — silently zero findings.
    """
    if ":" in name:
        return name  # already coordinates (e.g. 'org.apache:commons-io')
    gid = group or _purl_namespace(purl)
    return f"{gid}:{name}" if gid else name


def _safe_xml_parse(data: bytes | str) -> ElementTree.Element | None:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > _MAX_XML_BYTES:
        return None
    if not _HAS_DEFUSEDXML:
        text = data.decode("utf-8", errors="replace").upper()
        if "<!ENTITY" in text or "<!DOCTYPE" in text:
            return None
    if _HAS_DEFUSEDXML:
        try:
            return _safe_fromstring(data)
        # INTENTIONAL BROAD CATCH: defusedxml raises DefusedXmlException on
        # unsafe constructs and ParseError on malformed XML; both mean "not
        # parseable", so we return None for either.
        except Exception:
            return None
    try:
        return ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return None


@dataclass
class PackageRef:
    name: str
    version: str
    ecosystem: str
    purl: str = ""


def _detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".xml":
        return "cyclonedx_xml"
    if suffix != ".json":
        return _probe_content(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return _probe_content(path)
    if not isinstance(data, dict):
        return _probe_content(path)
    schema = data.get("$schema", "")
    if isinstance(schema, str) and "cyclonedx" in schema.lower():
        return "cyclonedx_json"
    if isinstance(schema, str) and "spdx" in schema.lower():
        return "spdx_json"
    format_val = data.get("format", "")
    if isinstance(format_val, str) and "cyclonedx" in format_val.lower():
        return "cyclonedx_json"
    spec_version = data.get("specVersion", "")
    if spec_version:
        return "cyclonedx_json"
    spdx_id = data.get("SPDXID", "")
    if spdx_id:
        return "spdx_json"
    return _probe_content(path)


def _probe_content(path: Path) -> str:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return "unknown"
    stripped = raw.lstrip()
    if stripped.startswith("<"):
        root = _safe_xml_parse(path.read_bytes())
        if root is not None and "cyclonedx" in (root.tag or "").lower():
            return "cyclonedx_xml"
    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                return "unknown"
            schema = data.get("$schema", "")
            if isinstance(schema, str) and "cyclonedx" in schema.lower():
                return "cyclonedx_json"
            if isinstance(schema, str) and "spdx" in schema.lower():
                return "spdx_json"
            if data.get("specVersion"):
                return "cyclonedx_json"
            if data.get("SPDXID"):
                return "spdx_json"
        except json.JSONDecodeError:
            pass
    return "unknown"


def _ecosystem_from_purl(purl: str) -> str:
    if not purl or not purl.startswith("pkg:"):
        return "unknown"
    scheme_body = purl[4:]
    slash = scheme_body.find("/")
    if slash < 0:
        return "unknown"
    pkg_type = scheme_body[:slash]
    return _PURL_ECOSYSTEM_MAP.get(pkg_type, "unknown")


def _ecosystem_from_url(url: str) -> str:
    host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    return _REGISTRY_HOST_MAP.get(host, "unknown")


def _ecosystem_from_name(name: str) -> str:
    if name.startswith("@") and "/" in name:
        return "npm"
    if _GO_MODULE_PATH_RE.match(name):
        return "golang"
    if _MAVEN_COORDS_RE.match(name):
        return "maven"
    return "unknown"


def _parse_cyclonedx_json(data: dict) -> list[PackageRef]:
    components = data.get("components") or []
    refs: list[PackageRef] = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", "")
        ecosystem = _ecosystem_from_purl(purl) if purl else "unknown"
        if ecosystem == "unknown":
            ecosystem = _ecosystem_from_name(name)
        if ecosystem == "unknown":
            for ref in comp.get("externalReferences", []) or []:
                if isinstance(ref, dict):
                    ecosystem = _ecosystem_from_url(str(ref.get("url", "")))
                    if ecosystem != "unknown":
                        break
        if ecosystem == "maven":
            group = comp.get("group", "") if isinstance(comp.get("group", ""), str) else ""
            name = _maven_display_name(name, group, purl)
        refs.append(PackageRef(name=name, version=version, ecosystem=ecosystem, purl=purl))
    return refs


def _parse_cyclonedx_xml(data: bytes) -> list[PackageRef]:
    root = _safe_xml_parse(data)
    if root is None:
        return []
    # Derive the document's namespace from the root tag so CycloneDX 1.4/1.5/1.6
    # (and future revisions) all parse — the version is part of the namespace URI.
    tag = root.tag or ""
    ns = tag.split("}", 1)[0].lstrip("{") if tag.startswith("{") else ""

    def _find_child(element: ElementTree.Element, name: str) -> ElementTree.Element | None:
        if ns:
            el = element.find(f"{{{ns}}}{name}")
            if el is not None:
                return el
        return element.find(name)

    refs: list[PackageRef] = []
    for comp in root.iter():
        ctag = comp.tag.split("}")[-1] if "}" in comp.tag else comp.tag
        if ctag != "component":
            continue
        name = comp.get("name", "") or ""
        if not name:
            name_el = _find_child(comp, "name")
            if name_el is not None and name_el.text:
                name = name_el.text
        version_el = _find_child(comp, "version")
        version = (version_el.text if version_el is not None else comp.get("version", "")) or ""
        purl_el = _find_child(comp, "purl")
        purl = (purl_el.text if purl_el is not None else comp.get("purl", "")) or ""
        ecosystem = _ecosystem_from_purl(purl) if purl else "unknown"
        if ecosystem == "unknown":
            ecosystem = _ecosystem_from_name(name)
        if ecosystem == "unknown":
            for ref in comp.iter():
                rtag = ref.tag.split("}")[-1] if "}" in ref.tag else ref.tag
                if rtag == "reference":
                    url_el = _find_child(ref, "url")
                    url = (url_el.text if url_el is not None else ref.get("url", "")) or ""
                    ecosystem = _ecosystem_from_url(url)
                    if ecosystem != "unknown":
                        break
        if ecosystem == "maven":
            name = _maven_display_name(name, comp.get("group", "") or "", purl)
        refs.append(PackageRef(name=name, version=version, ecosystem=ecosystem, purl=purl))
    return refs


def _parse_spdx_json(data: dict) -> list[PackageRef]:
    packages = data.get("packages") or []
    refs: list[PackageRef] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        purl = ""
        ecosystem = "unknown"
        for ref in pkg.get("externalRefs", []) or []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                ecosystem = _ecosystem_from_purl(purl)
                break
        if ecosystem == "unknown":
            pkg_manager = pkg.get("packageManager", "")
            if isinstance(pkg_manager, str) and pkg_manager:
                ecosystem = _SPDX_PKG_MANAGER_MAP.get(pkg_manager.lower(), pkg_manager.lower())
        if ecosystem == "unknown":
            for field in ("downloadLocation", "sourceInfo"):
                ecosystem = _ecosystem_from_url(str(pkg.get(field, "") or ""))
                if ecosystem != "unknown":
                    break
        if ecosystem == "unknown":
            ecosystem = _ecosystem_from_name(name)
        if ecosystem == "maven":
            name = _maven_display_name(name, "", purl)
        refs.append(PackageRef(name=name, version=version, ecosystem=ecosystem, purl=purl))
    return refs


def parse_sbom(path: Path) -> list[PackageRef]:
    if path.stat().st_size > _MAX_XML_BYTES:
        raise ValueError(f"SBOM file exceeds {_MAX_XML_BYTES} bytes: {path}")
    fmt = _detect_format(path)
    if fmt == "unknown":
        raise ValueError(f"Cannot detect SBOM format for {path}")
    if fmt == "cyclonedx_json":
        data = json.loads(path.read_text(encoding="utf-8"))
        return _parse_cyclonedx_json(data)
    if fmt == "cyclonedx_xml":
        return _parse_cyclonedx_xml(path.read_bytes())
    if fmt == "spdx_json":
        data = json.loads(path.read_text(encoding="utf-8"))
        return _parse_spdx_json(data)
    raise ValueError(f"Unsupported SBOM format: {fmt}")
