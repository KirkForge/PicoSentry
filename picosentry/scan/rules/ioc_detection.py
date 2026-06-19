
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..ioc_registry import load_all_iocs
from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_custom_iocs"]

logger = logging.getLogger("picosentry.ioc_detection")


def _semver_matches(version: str, constraint: str) -> bool:
    version = version.strip().lstrip("v")
    constraint = constraint.strip()
    import re
    _SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:[-.]([a-zA-Z0-9._-]+))?(?:\+([a-zA-Z0-9._-]+))?")


    if version == constraint:
        return True


    def _parse_ver(v: str) -> tuple[list[int] | None, str]:
        m = _SEMVER_RE.search(v)
        if m:
            parts = [int(m.group(1)), int(m.group(2)), int(m.group(3))]
            pre = m.group(4) or ""
            return parts, pre

        nums = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
        if nums:
            parts = [int(nums.group(1) or 0), int(nums.group(2) or 0), int(nums.group(3) or 0)]
            return parts, ""
        return None, ""

    v_parts, v_pre = _parse_ver(version)
    if v_parts is None:
        return version in constraint or constraint in version


    def _parse_constraint(c: str) -> tuple[list[int] | None, str]:

        m = _SEMVER_RE.search(c)
        if m:
            parts = [int(m.group(1)), int(m.group(2)), int(m.group(3))]
            pre = m.group(4) or ""
            return parts, pre
        nums = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", c)
        if nums:
            parts = [int(nums.group(1) or 0), int(nums.group(2) or 0), int(nums.group(3) or 0)]
            return parts, ""
        return None, ""


    def _ver_cmp(a_parts: list[int], a_pre: str, b_parts: list[int], b_pre: str) -> int:
        if a_parts < b_parts:
            return -1
        if a_parts > b_parts:
            return 1


        if not a_pre and b_pre:
            return 1
        if a_pre and not b_pre:
            return -1
        if not a_pre and not b_pre:
            return 0

        a_idents = a_pre.split(".")
        b_idents = b_pre.split(".")
        for ai, bi in zip(a_idents, b_idents, strict=False):

            a_num = ai.isdigit()
            b_num = bi.isdigit()
            if a_num and b_num:
                if int(ai) < int(bi):
                    return -1
                if int(ai) > int(bi):
                    return 1
            elif a_num and not b_num:
                return -1
            elif not a_num and b_num:
                return 1
            else:
                if ai < bi:
                    return -1
                if ai > bi:
                    return 1
        if len(a_idents) < len(b_idents):
            return -1
        if len(a_idents) > len(b_idents):
            return 1
        return 0


    try:


        if constraint.startswith("^"):
            c = constraint[1:]
            c_parts, c_pre = _parse_constraint(c)
            if c_parts is None:
                return False
            cmp = _ver_cmp(v_parts, v_pre, c_parts, c_pre)
            if c_parts[0] == 0 and c_parts[1] == 0:


                return (v_parts[0] == 0 and v_parts[1] == 0 and v_parts[2] == c_parts[2])
            if c_parts[0] == 0:

                return (v_parts[0] == 0 and v_parts[1] == c_parts[1] and cmp >= 0
                        and v_parts[2] < 256)  # any patch within 0.y.*

            return cmp >= 0 and v_parts[0] == c_parts[0]


        if constraint.startswith("~"):
            c = constraint[1:]
            c_parts, c_pre = _parse_constraint(c)
            if c_parts is None:
                return False
            cmp = _ver_cmp(v_parts, v_pre, c_parts, c_pre)
            return v_parts[0] == c_parts[0] and v_parts[1] == c_parts[1] and cmp >= 0


        for op in (">=", "<=", ">", "<"):
            if constraint.startswith(op):
                c = constraint[len(op) :]
                c_parts, c_pre = _parse_constraint(c)
                if c_parts is None:
                    return False
                cmp = _ver_cmp(v_parts, v_pre, c_parts, c_pre)
                if op == ">=":
                    return cmp >= 0
                if op == "<=":
                    return cmp <= 0
                if op == ">":
                    return cmp > 0
                if op == "<":
                    return cmp < 0


        if " - " in constraint:
            lo, hi = constraint.split(" - ", 1)
            lo_parts, lo_pre = _parse_constraint(lo)
            hi_parts, hi_pre = _parse_constraint(hi)
            if lo_parts is None or hi_parts is None:
                return False
            lo_cmp = _ver_cmp(v_parts, v_pre, lo_parts, lo_pre)
            hi_cmp = _ver_cmp(v_parts, v_pre, hi_parts, hi_pre)
            return lo_cmp >= 0 and hi_cmp <= 0

    except (ValueError, IndexError):
        pass


    return version in constraint or constraint in version


def _check_package_against_iocs(
    pkg_name: str,
    pkg_version: str,
    pkg_label: str,
    pkg_json: Path,
    iocs: list[dict],
) -> list[Finding]:
    findings: list[Finding] = []

    for ioc in iocs:
        ioc_pkg = ioc.get("package_name", "")
        if not ioc_pkg or ioc_pkg != pkg_name:
            continue


        version_range = ioc.get("version_range", "*")
        if version_range != "*" and not _semver_matches(pkg_version, version_range):
            continue

        severity_str = ioc.get("severity", "HIGH").upper()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.HIGH

        findings.append(
            Finding(
                rule_id="L2-IOC-001",
                severity=severity,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=(
                    f"Package '{pkg_name}' matches custom IoC '{ioc.get('name', ioc.get('id', 'unknown'))}': "
                    f"{ioc.get('description', 'No description')}"
                ),
                evidence=f"IoC id={ioc.get('id', '?')}, type={ioc.get('ioc_type', 'custom')}, "
                f"attack_vector={ioc.get('attack_vector', 'unspecified')}",
                remediation=(
                    "This package matches a custom IoC indicator. "
                    f"Source: {ioc.get('source', 'custom')}. "
                    "Review the IoC details and assess whether this package is safe to use."
                ),
                references=ioc.get("references", []),
            )
        )

    return findings


def detect_custom_iocs(target: Path) -> list[Finding]:
    findings: list[Finding] = []


    try:
        iocs = load_all_iocs()
    except (OSError, json.JSONDecodeError, ValueError):
        logger.exception("Failed to load IoCs — IoC detection rule cannot run")
        return findings
    except Exception as e:
        logger.critical("Unexpected error loading IoCs — this may indicate a corrupted corpus: %s", e)
        return findings

    if not iocs:
        return findings


    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            pkg_name = pkg.get("name", "root")
            pkg_version = pkg.get("version", "unknown")
            pkg_label = f"{pkg_name}@{pkg_version}"
            findings.extend(_check_package_against_iocs(pkg_name, pkg_version, pkg_label, root_pkg, iocs))


    for pkg_json, pkg in iter_node_modules(target):
        pkg_name = pkg.get("name", pkg_json.parent.name)
        pkg_version = pkg.get("version", "unknown")
        pkg_label = f"{pkg_name}@{pkg_version}"

        findings.extend(_check_package_against_iocs(pkg_name, pkg_version, pkg_label, pkg_json, iocs))

    return findings
