from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from picosentry._core.models import Severity


class DiffVerdict(str, Enum):
    CLEAN = "CLEAN"
    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ScriptChange:
    name: str
    old_content: str = ""
    new_content: str = ""

    def as_tuple(self) -> tuple:
        return (self.name, self.old_content, self.new_content)


@dataclass(frozen=True)
class DependencyChange:
    name: str
    old_version: str = ""
    new_version: str = ""

    def as_tuple(self) -> tuple:
        return (self.name, self.old_version, self.new_version)


@dataclass(frozen=True)
class PatternMatch:
    pattern: str
    location: str

    def as_tuple(self) -> tuple:
        return (self.pattern, self.location)


@dataclass(frozen=True)
class VersionDelta:
    added_scripts: tuple[ScriptChange, ...] = ()
    removed_scripts: tuple[ScriptChange, ...] = ()
    changed_scripts: tuple[ScriptChange, ...] = ()
    added_dependencies: tuple[DependencyChange, ...] = ()
    removed_dependencies: tuple[DependencyChange, ...] = ()
    changed_dependencies: tuple[DependencyChange, ...] = ()
    added_network_patterns: tuple[PatternMatch, ...] = ()
    added_obfuscation: tuple[PatternMatch, ...] = ()
    added_credential_access: tuple[PatternMatch, ...] = ()
    risk_delta: float = 0.0
    verdict: DiffVerdict = DiffVerdict.CLEAN

    def to_dict(self) -> dict[str, Any]:
        return {
            "added_scripts": [sc.as_tuple() for sc in self.added_scripts],
            "removed_scripts": [sc.as_tuple() for sc in self.removed_scripts],
            "changed_scripts": [sc.as_tuple() for sc in self.changed_scripts],
            "added_dependencies": [dc.as_tuple() for dc in self.added_dependencies],
            "removed_dependencies": [dc.as_tuple() for dc in self.removed_dependencies],
            "changed_dependencies": [dc.as_tuple() for dc in self.changed_dependencies],
            "added_network_patterns": [pm.as_tuple() for pm in self.added_network_patterns],
            "added_obfuscation": [pm.as_tuple() for pm in self.added_obfuscation],
            "added_credential_access": [pm.as_tuple() for pm in self.added_credential_access],
            "risk_delta": self.risk_delta,
            "verdict": self.verdict.value,
        }


LIFECYCLE_SCRIPT_KEYS = frozenset({"install", "postinstall", "preinstall", "prepare", "prepack", "postpack"})

NETWORK_PATTERNS = (
    "http://",
    "https://",
    "ftp://",
    "curl ",
    "wget ",
    "fetch(",
    "ncat",
    "socat",
    "nc -",
    "ssh ",
    "scp ",
)

OBFUSCATION_PATTERNS = (
    "eval(",
    "Function(",
    "exec(",
    "__import__(",
    "atob(",
    "Buffer.from(",
    "\\x",
    "\\u00",
    "child_process",
    "subprocess.",
    "os.system(",
    "os.popen(",
    "compile(",
)

CREDENTIAL_PATTERNS = (
    ".env",
    ".ssh/",
    ".aws/",
    ".npmrc",
    "process.env",
    "os.environ",
    ".pypirc",
    ".netrc",
    "AWS_",
    "GITHUB_TOKEN",
    "NPM_TOKEN",
)

_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.4,
    Severity.LOW: 0.2,
    Severity.INFO: 0.1,
}


def _extract_scripts(manifest: dict[str, Any]) -> dict[str, str]:
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        return {}
    return {k: str(v) for k, v in scripts.items() if isinstance(v, (str, int, float))}


def _extract_deps(manifest: dict[str, Any]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section_data = manifest.get(section)
        if isinstance(section_data, dict):
            for name, version in section_data.items():
                deps[name] = str(version)
    requires_dist = manifest.get("requires_dist") or manifest.get("Requires-Dist")
    if isinstance(requires_dist, list):
        for entry in requires_dist:
            if isinstance(entry, str):
                parts = entry.split(";")[0].strip()
                for op in (">=", "<=", "!=", "==", "~=", ">=", "<="):
                    if op in parts:
                        name, _, version = parts.partition(op)
                        deps[name.strip()] = parts
                        break
                else:
                    deps[parts] = "*"
    return dict(sorted(deps.items()))


def _scan_text_for_patterns(text: str, patterns: tuple[str, ...], label: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    text_lower = text.lower()
    for pat in patterns:
        if pat.lower() in text_lower:
            matches.append(PatternMatch(pattern=pat, location=label))
    return matches


def _compute_risk_delta(delta: VersionDelta) -> float:
    risk = 0.0
    risk += 0.15 * len(delta.added_scripts)
    risk += 0.10 * len(delta.changed_scripts)
    risk += 0.20 * len(delta.added_network_patterns)
    risk += 0.25 * len(delta.added_obfuscation)
    risk += 0.30 * len(delta.added_credential_access)
    risk += 0.05 * len(delta.added_dependencies)
    risk += 0.03 * len(delta.changed_dependencies)
    return round(max(risk, 0.0), 2)


def _verdict_from_risk(risk_delta: float, delta: VersionDelta) -> DiffVerdict:
    has_critical_pattern = bool(delta.added_obfuscation) or bool(delta.added_credential_access)
    if risk_delta >= 1.0 or has_critical_pattern:
        return DiffVerdict.CRITICAL
    if risk_delta >= 0.5:
        return DiffVerdict.HIGH_RISK
    if risk_delta >= 0.2:
        return DiffVerdict.MEDIUM_RISK
    if risk_delta > 0.0:
        return DiffVerdict.LOW_RISK
    return DiffVerdict.CLEAN


def _collect_new_pattern_matches(
    old_scripts: dict[str, str],
    new_scripts: dict[str, str],
    patterns: tuple[str, ...],
    existing: list[PatternMatch],
) -> list[PatternMatch]:
    existing_set = set(existing)
    old_text = " ".join(old_scripts.get(k, "") for k in sorted(old_scripts)).lower()
    new_text = " ".join(new_scripts.get(k, "") for k in sorted(new_scripts)).lower()
    results: list[PatternMatch] = list(existing)
    for pat in patterns:
        pat_lower = pat.lower()
        if pat_lower not in new_text:
            continue
        if pat_lower in old_text:
            continue
        for key in sorted(new_scripts):
            if pat_lower in new_scripts[key].lower() and (
                key not in old_scripts or pat_lower not in old_scripts.get(key, "").lower()
            ):
                pm = PatternMatch(pattern=pat, location=f"scripts.{key}")
                if pm not in existing_set and pm not in results:
                    results.append(pm)
    return results


class VersionDiff:
    def diff_manifests(
        self,
        old_manifest: dict[str, Any],
        new_manifest: dict[str, Any],
    ) -> VersionDelta:
        old_scripts = _extract_scripts(old_manifest)
        new_scripts = _extract_scripts(new_manifest)
        old_deps = _extract_deps(old_manifest)
        new_deps = _extract_deps(new_manifest)

        added_scripts: list[ScriptChange] = []
        removed_scripts: list[ScriptChange] = []
        changed_scripts: list[ScriptChange] = []

        for name in sorted(set(old_scripts) | set(new_scripts)):
            old_val = old_scripts.get(name, "")
            new_val = new_scripts.get(name, "")
            if name not in old_scripts:
                added_scripts.append(ScriptChange(name=name, new_content=new_val))
            elif name not in new_scripts:
                removed_scripts.append(ScriptChange(name=name, old_content=old_val))
            elif old_val != new_val:
                changed_scripts.append(ScriptChange(name=name, old_content=old_val, new_content=new_val))

        added_deps: list[DependencyChange] = []
        removed_deps: list[DependencyChange] = []
        changed_deps: list[DependencyChange] = []

        for dep_name in sorted(set(old_deps) | set(new_deps)):
            old_ver = old_deps.get(dep_name, "")
            new_ver = new_deps.get(dep_name, "")
            if dep_name not in old_deps:
                added_deps.append(DependencyChange(name=dep_name, new_version=new_ver))
            elif dep_name not in new_deps:
                removed_deps.append(DependencyChange(name=dep_name, old_version=old_ver))
            elif old_ver != new_ver:
                changed_deps.append(DependencyChange(name=dep_name, old_version=old_ver, new_version=new_ver))

        added_net: list[PatternMatch] = []
        added_obf: list[PatternMatch] = []
        added_cred: list[PatternMatch] = []

        for key in sorted(new_scripts):
            if key not in old_scripts or old_scripts.get(key, "") != new_scripts[key]:
                text = new_scripts[key]
                added_net.extend(_scan_text_for_patterns(text, NETWORK_PATTERNS, f"scripts.{key}"))
                added_obf.extend(_scan_text_for_patterns(text, OBFUSCATION_PATTERNS, f"scripts.{key}"))
                added_cred.extend(_scan_text_for_patterns(text, CREDENTIAL_PATTERNS, f"scripts.{key}"))

        added_net = _collect_new_pattern_matches(old_scripts, new_scripts, NETWORK_PATTERNS, added_net)
        added_obf = _collect_new_pattern_matches(old_scripts, new_scripts, OBFUSCATION_PATTERNS, added_obf)
        added_cred = _collect_new_pattern_matches(old_scripts, new_scripts, CREDENTIAL_PATTERNS, added_cred)

        added_net = sorted(set(added_net), key=lambda p: (p.pattern, p.location))
        added_obf = sorted(set(added_obf), key=lambda p: (p.pattern, p.location))
        added_cred = sorted(set(added_cred), key=lambda p: (p.pattern, p.location))

        delta = VersionDelta(
            added_scripts=tuple(added_scripts),
            removed_scripts=tuple(removed_scripts),
            changed_scripts=tuple(changed_scripts),
            added_dependencies=tuple(added_deps),
            removed_dependencies=tuple(removed_deps),
            changed_dependencies=tuple(changed_deps),
            added_network_patterns=tuple(added_net),
            added_obfuscation=tuple(added_obf),
            added_credential_access=tuple(added_cred),
        )
        risk_delta = _compute_risk_delta(delta)
        verdict = _verdict_from_risk(risk_delta, delta)
        return VersionDelta(
            added_scripts=delta.added_scripts,
            removed_scripts=delta.removed_scripts,
            changed_scripts=delta.changed_scripts,
            added_dependencies=delta.added_dependencies,
            removed_dependencies=delta.removed_dependencies,
            changed_dependencies=delta.changed_dependencies,
            added_network_patterns=delta.added_network_patterns,
            added_obfuscation=delta.added_obfuscation,
            added_credential_access=delta.added_credential_access,
            risk_delta=risk_delta,
            verdict=verdict,
        )

    def diff_files(self, old_path: Path, new_path: Path) -> VersionDelta:
        old_manifest = json.loads(old_path.read_text(encoding="utf-8"))
        new_manifest = json.loads(new_path.read_text(encoding="utf-8"))
        return self.diff_manifests(old_manifest, new_manifest)

    def diff_scan_results(
        self,
        old_result: dict[str, Any],
        new_result: dict[str, Any],
    ) -> VersionDelta:
        old_manifest = self._manifest_from_scan(old_result)
        new_manifest = self._manifest_from_scan(new_result)
        return self.diff_manifests(old_manifest, new_manifest)

    @staticmethod
    def _manifest_from_scan(result: dict[str, Any]) -> dict[str, Any]:
        manifest: dict[str, Any] = {}
        scripts: dict[str, str] = {}
        deps: dict[str, str] = {}

        findings = result.get("findings", [])
        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                rule_id = f.get("rule_id", "")
                evidence = str(f.get("evidence", ""))
                message = str(f.get("message", ""))

                if rule_id.startswith(("L2-POST", "L2-PYPI-POST")):
                    script_match = re.search(r"scripts\.(\w+)\s*=", evidence)
                    if script_match:
                        script_name = script_match.group(1)
                        content_match = re.search(r"=\s*(.+?)$", evidence)
                        content = content_match.group(1).strip().strip("'\"") if content_match else ""
                        scripts[script_name] = content

                if rule_id.startswith("L2-MANI"):
                    dep_match = re.search(r"Dependency\s+'(\S+)'.*range\s+'([^']+)'", message)
                    if dep_match:
                        deps[dep_match.group(1)] = dep_match.group(2)

        if scripts:
            manifest["scripts"] = dict(sorted(scripts.items()))
        if deps:
            manifest["dependencies"] = dict(sorted(deps.items()))
        return manifest


def format_delta(delta: VersionDelta, indent: int = 0) -> str:
    prefix = " " * indent
    lines: list[str] = []
    lines.append(f"{prefix}Verdict: {delta.verdict.value}")
    lines.append(f"{prefix}Risk delta: {delta.risk_delta:+.2f}")

    if delta.added_scripts:
        lines.append(f"{prefix}Added scripts:")
        for sc in delta.added_scripts:
            content_preview = sc.new_content[:80] + "..." if len(sc.new_content) > 80 else sc.new_content
            lines.append(f"{prefix}  + {sc.name}: {content_preview}")

    if delta.removed_scripts:
        lines.append(f"{prefix}Removed scripts:")
        for sc in delta.removed_scripts:
            lines.append(f"{prefix}  - {sc.name}")

    if delta.changed_scripts:
        lines.append(f"{prefix}Changed scripts:")
        for sc in delta.changed_scripts:
            old_preview = sc.old_content[:60] + "..." if len(sc.old_content) > 60 else sc.old_content
            new_preview = sc.new_content[:60] + "..." if len(sc.new_content) > 60 else sc.new_content
            lines.append(f"{prefix}  ~ {sc.name}:")
            lines.append(f"{prefix}      old: {old_preview}")
            lines.append(f"{prefix}      new: {new_preview}")

    if delta.added_dependencies:
        lines.append(f"{prefix}Added dependencies:")
        for dc in delta.added_dependencies:
            lines.append(f"{prefix}  + {dc.name}: {dc.new_version}")

    if delta.removed_dependencies:
        lines.append(f"{prefix}Removed dependencies:")
        for dc in delta.removed_dependencies:
            lines.append(f"{prefix}  - {dc.name}: {dc.old_version}")

    if delta.changed_dependencies:
        lines.append(f"{prefix}Changed dependencies:")
        for dc in delta.changed_dependencies:
            lines.append(f"{prefix}  ~ {dc.name}: {dc.old_version} -> {dc.new_version}")

    if delta.added_network_patterns:
        lines.append(f"{prefix}Added network patterns:")
        for pm in delta.added_network_patterns:
            lines.append(f"{prefix}  ! {pm.pattern} in {pm.location}")

    if delta.added_obfuscation:
        lines.append(f"{prefix}Added obfuscation patterns:")
        for pm in delta.added_obfuscation:
            lines.append(f"{prefix}  ! {pm.pattern} in {pm.location}")

    if delta.added_credential_access:
        lines.append(f"{prefix}Added credential access:")
        for pm in delta.added_credential_access:
            lines.append(f"{prefix}  ! {pm.pattern} in {pm.location}")

    if delta.verdict == DiffVerdict.CLEAN:
        lines.append(f"{prefix}No risky changes detected.")

    return "\n".join(lines)
