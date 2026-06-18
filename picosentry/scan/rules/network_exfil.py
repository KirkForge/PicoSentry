
from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_network_exfiltration"]


INSTALL_SCRIPT_KEYS = (
    "install",
    "postinstall",
    "preinstall",
    "prepare",
    "prepack",
)


JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx"}


MAX_FILE_BYTES = 512_000


MAX_FILES_PER_PACKAGE = 200


SKIP_DIRS = frozenset(
    {"dist", "build", "out", ".cache", "__pycache__", ".git", ".hg", ".svn"}
)

SKIP_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".lock",
    }
)


C2_DOMAINS: list[tuple[str, str, Severity, str]] = [

    (r"\bshai-hulud\.cc\b", "Shai-Hulud C2", Severity.CRITICAL, "Shai-Hulud worm C2 domain"),
    (r"\bfirebase\.su\b", "Scavenger C2", Severity.CRITICAL, "CVE-2025-54313 Scavenger C2 domain"),
    (r"\bdieorsuffer\.com\b", "Scavenger C2", Severity.CRITICAL, "CVE-2025-54313 Scavenger C2 domain"),
    (r"\bsmartscreen-api\.com\b", "Scavenger C2", Severity.CRITICAL, "CVE-2025-54313 Scavenger C2 phishing domain"),
    (r"\bwebhook\.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7", "Shai-Hulud exfil", Severity.CRITICAL, "Known Shai-Hulud exfiltration webhook"),
]


PHISHING_DOMAINS: list[tuple[str, str, Severity, str]] = [
    (r"\bnpmjs\.(?:help|support|security)\b", "npm phishing", Severity.HIGH, "Phishing domain impersonating npmjs.com"),
    (r"\bnpnjs\.com\b", "npm typosquat", Severity.HIGH, "Typosquat domain mimicking npmjs.com"),
    (r"\bnprnjs\.\b", "npm typosquat", Severity.MEDIUM, "Typosquat domain mimicking npmjs.com"),
    (r"\bnpmj5\.\b", "npm typosquat", Severity.MEDIUM, "Typosquat domain mimicking npmjs.com"),
    (r"\bnpn-js\.\b", "npm typosquat", Severity.MEDIUM, "Typosquat domain mimicking npmjs.com"),
]


CLOUD_METADATA: list[tuple[str, str, Severity, str]] = [
    (r"169\.254\.169\.254", "AWS IMDS", Severity.CRITICAL, "AWS Instance Metadata Service endpoint — credential exfiltration risk"),
    (r"fd00:ec2::254", "AWS IMDS IPv6", Severity.CRITICAL, "AWS Instance Metadata Service IPv6 endpoint"),
    (r"\[fd00:ec2::254\]", "AWS IMDS IPv6 brackets", Severity.CRITICAL, "AWS Instance Metadata Service IPv6 bracket notation"),
    (r"metadata\.google\.internal", "GCP metadata", Severity.CRITICAL, "GCP Compute Engine metadata endpoint"),
    (r"metadata\.azure\.com", "Azure metadata", Severity.CRITICAL, "Azure Instance Metadata Service endpoint"),
    (r"/latest/meta-data/", "AWS IMDS path", Severity.CRITICAL, "AWS IMDS metadata path pattern"),
    (r"/computeMetadata/v1/", "GCP metadata path", Severity.CRITICAL, "GCP metadata path pattern"),
]


ALL_PATTERNS: list[tuple[str, re.Pattern, Severity, str, str]] = []

for pattern_str, name, severity, desc in C2_DOMAINS:
    ALL_PATTERNS.append((name, re.compile(pattern_str, re.IGNORECASE), severity, desc, name))
for pattern_str, name, severity, desc in PHISHING_DOMAINS:
    ALL_PATTERNS.append((name, re.compile(pattern_str, re.IGNORECASE), severity, desc, name))
for pattern_str, name, severity, desc in CLOUD_METADATA:
    ALL_PATTERNS.append((name, re.compile(pattern_str), severity, desc, name))


ENV_EXFIL_PATTERNS: list[tuple[str, re.Pattern, Severity, str, str]] = [
    (
        "env_exfil_fetch",
        re.compile(r"(?:fetch|axios|http\.request|https\.request|got|request)\s*.*process\.env", re.IGNORECASE),
        Severity.CRITICAL,
        "Environment variable exfiltration via network request",
        "Network requests that include process.env data are exfiltrating credentials.",
    ),
    (
        "env_exfil_curl",
        re.compile(r"(?:curl|wget)\s+.*\$(?:AWS_|NPM_TOKEN|GITHUB_TOKEN|NODE_AUTH_TOKEN|GITLAB_TOKEN)", re.IGNORECASE),
        Severity.CRITICAL,
        "Environment variable exfiltration via curl/wget",
        "Shell commands that send credential environment variables over the network.",
    ),
    (
        "metadata_header",
        re.compile(r"Metadata:\s*true", re.IGNORECASE),
        Severity.HIGH,
        "Azure metadata header pattern detected",
        "The 'Metadata: true' header is used to query Azure Instance Metadata Service.",
    ),
    (
        "scavenger_dll",
        re.compile(r"\b(?:node-gyp\.(?:dll|so)|loader\.(?:dll|so)|version\.(?:dll|so)|umpdc\.(?:dll|so)|profapi\.(?:dll|so)|libumpdc\.so|libprofapi\.so)\b"),
        Severity.CRITICAL,
        "Scavenger malware DLL/SO file reference detected",
        "Known Scavenger malware native library files (CVE-2025-54313).",
    ),
]


def _scan_text_for_exfil(text: str, source_label: str, is_script: bool = False) -> list[Finding]:
    findings: list[Finding] = []

    patterns = ALL_PATTERNS + ENV_EXFIL_PATTERNS if is_script else ALL_PATTERNS

    for name, pattern, severity, desc, _remediation_key in patterns:
        for match in pattern.finditer(text):
            matched_text = match.group(0)[:120]


            if "C2" in name or name in ("Shai-Hulud exfil", "Scavenger C2"):
                remediation = (
                    "Known supply chain attack C2 domain detected. Remove this dependency immediately. "
                    "Rotate any credentials that may have been exposed. "
                    "See: https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/"
                )
            elif "metadata" in name.lower() or "IMDS" in name or name == "metadata_header":
                remediation = (
                    "Cloud metadata endpoint access detected. This can exfiltrate IAM credentials. "
                    "Ensure your environment blocks IMDS access from npm install. "
                    "See: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                )
            elif "phishing" in name.lower() or "typosquat" in name.lower():
                remediation = (
                    "Phishing/typosquat domain detected. This domain mimics npmjs.com to steal credentials. "
                    "Remove this dependency and verify all npm credentials."
                )
            elif "env_exfil" in name:
                remediation = (
                    "Environment variables are being sent over the network. "
                    "This is a credential exfiltration pattern. Remove this dependency and rotate exposed credentials."
                )
            elif "Scavenger" in name or "scavenger" in name:
                remediation = (
                    "Scavenger malware indicator detected (CVE-2025-54313). "
                    "Remove this dependency immediately and audit all systems."
                )
            else:
                remediation = (
                    "Suspicious network pattern detected. Review this dependency carefully."
                )

            findings.append(
                Finding(
                    rule_id="L2-NETEX-001",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    package=source_label,
                    file="",
                    message=desc,
                    evidence=matched_text,
                    remediation=remediation,
                    references=[
                        "https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/",
                        "https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/",
                        "https://unit42.paloaltonetworks.com/npm-supply-chain-attack-shai-hulud-2-0/",
                    ],
                )
            )

    return findings


def _scan_source_for_exfil(file_path: Path, pkg_label: str) -> list[Finding]:
    findings: list[Finding] = []

    if file_path.suffix in SKIP_EXTENSIONS:
        return findings

    try:
        size = file_path.stat().st_size
    except OSError:
        return findings

    if size > MAX_FILE_BYTES:
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    all_patterns = ALL_PATTERNS + ENV_EXFIL_PATTERNS

    for name, pattern, severity, desc, _remediation_key in all_patterns:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            matched_text = match.group(0)[:120]


            if "C2" in name or name == "Shai-Hulud exfil":
                remediation = (
                    "Known supply chain attack C2 domain detected in source. "
                    "Remove this dependency and rotate any exposed credentials."
                )
            elif "IMDS" in name or "metadata" in name.lower():
                remediation = (
                    "Cloud metadata endpoint access in source. "
                    "This can exfiltrate IAM credentials. Block IMDS access."
                )
            elif "phishing" in name.lower() or "typosquat" in name.lower():
                remediation = "Phishing/typosquat domain in source. Remove this dependency."
            elif "env_exfil" in name:
                remediation = (
                    "Environment variable exfiltration via network in source. "
                    "Remove this dependency and rotate exposed credentials."
                )
            elif "Scavenger" in name or "scavenger" in name:
                remediation = (
                    "Scavenger malware indicator in source (CVE-2025-54313). "
                    "Remove this dependency immediately."
                )
            else:
                remediation = "Suspicious network pattern in source. Review carefully."

            findings.append(
                Finding(
                    rule_id="L2-NETEX-001",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    package=pkg_label,
                    file=str(file_path),
                    line=line_num,
                    message=desc,
                    evidence=matched_text,
                    remediation=remediation,
                    references=[
                        "https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/",
                        "https://unit42.paloaltonetworks.com/npm-supply-chain-attack-shai-hulud-2-0/",
                    ],
                )
            )

    return findings


def _scan_package_sources(pkg_dir: Path, pkg_label: str, findings: list[Finding]) -> None:
    file_count = 0
    for ext in JS_EXTENSIONS:
        for src_file in pkg_dir.rglob(f"*{ext}"):
            if file_count >= MAX_FILES_PER_PACKAGE:
                return
            if src_file.is_symlink():
                continue
            if any(part in SKIP_DIRS for part in src_file.parts):
                continue
            findings.extend(_scan_source_for_exfil(src_file, pkg_label))
            file_count += 1


def detect_network_exfiltration(target: Path) -> list[Finding]:
    findings: list[Finding] = []


    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            pkg_name = pkg.get("name", "root")
            pkg_version = pkg.get("version", "unknown")
            pkg_label = f"{pkg_name}@{pkg_version}"


            scripts = pkg.get("scripts", {})
            if isinstance(scripts, dict):
                for script_key in INSTALL_SCRIPT_KEYS:
                    if script_key in scripts:
                        script_value = str(scripts[script_key])
                        script_findings = _scan_text_for_exfil(
                            script_value, pkg_label, is_script=True
                        )
                        findings.extend(
                            Finding(
                                rule_id=f.rule_id,
                                severity=f.severity,
                                confidence=f.confidence,
                                package=f.package,
                                file=str(root_pkg),
                                message=f.message,
                                evidence=f"scripts.{script_key}: {f.evidence}",
                                remediation=f.remediation,
                                references=f.references,
                            )
                            for f in script_findings
                        )

            _scan_package_sources(target, pkg_label, findings)


    for pkg_json, pkg in iter_node_modules(target):
        pkg_name = pkg.get("name", pkg_json.parent.name)
        pkg_version = pkg.get("version", "unknown")
        pkg_label = f"{pkg_name}@{pkg_version}"


        scripts = pkg.get("scripts", {})
        if isinstance(scripts, dict):
            for script_key in INSTALL_SCRIPT_KEYS:
                if script_key in scripts:
                    script_value = str(scripts[script_key])
                    script_findings = _scan_text_for_exfil(
                        script_value, pkg_label, is_script=True
                    )
                    findings.extend(
                        Finding(
                            rule_id=f.rule_id,
                            severity=f.severity,
                            confidence=f.confidence,
                            package=f.package,
                            file=str(pkg_json),
                            message=f.message,
                            evidence=f"scripts.{script_key}: {f.evidence}",
                            remediation=f.remediation,
                            references=f.references,
                        )
                        for f in script_findings
                    )


        pkg_dir = pkg_json.parent
        _scan_package_sources(pkg_dir, pkg_label, findings)

    return findings
