from __future__ import annotations

import json
import logging
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

_CYCLONEDX_NS = "http://cyclonedx.org/schema/bom/1.5"

_MAX_XML_BYTES = 10 * 1024 * 1024  # ponytail: 10MB cap rejects billion-laughs amplification


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


def _parse_cyclonedx_json(data: dict) -> list[PackageRef]:
    components = data.get("components") or []
    refs: list[PackageRef] = []
    for comp in components:
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", "")
        ecosystem = _ecosystem_from_purl(purl) if purl else "unknown"
        refs.append(PackageRef(name=name, version=version, ecosystem=ecosystem, purl=purl))
    return refs


def _parse_cyclonedx_xml(data: bytes) -> list[PackageRef]:
    root = _safe_xml_parse(data)
    if root is None:
        return []
    refs: list[PackageRef] = []
    for comp in root.iter():
        tag = comp.tag.split("}")[-1] if "}" in comp.tag else comp.tag
        if tag != "component":
            continue
        name = comp.get("name", "") or ""
        if not name:
            name_el = comp.find(f"{{{_CYCLONEDX_NS}}}name")
            if name_el is None:
                name_el = comp.find("name")
            if name_el is not None and name_el.text:
                name = name_el.text
        version_el = comp.find(f"{{{_CYCLONEDX_NS}}}version")
        if version_el is None:
            version_el = comp.find("version")
        version = (version_el.text if version_el is not None else comp.get("version", "")) or ""
        purl_el = comp.find(f"{{{_CYCLONEDX_NS}}}purl")
        if purl_el is None:
            purl_el = comp.find("purl")
        purl = (purl_el.text if purl_el is not None else comp.get("purl", "")) or ""
        ecosystem = _ecosystem_from_purl(purl) if purl else "unknown"
        refs.append(PackageRef(name=name, version=version, ecosystem=ecosystem, purl=purl))
    return refs


def _parse_spdx_json(data: dict) -> list[PackageRef]:
    packages = data.get("packages") or []
    refs: list[PackageRef] = []
    for pkg in packages:
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        purl = ""
        ecosystem = "unknown"
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                ecosystem = _ecosystem_from_purl(purl)
                break
        if ecosystem == "unknown":
            pkg_manager = pkg.get("packageManager", "")
            if isinstance(pkg_manager, str) and pkg_manager:
                ecosystem = _SPDX_PKG_MANAGER_MAP.get(pkg_manager.lower(), pkg_manager.lower())
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
