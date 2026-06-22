from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .pattern_scanner import PatternScanner, TokenPattern
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


SKIP_DIRS = frozenset({"dist", "build", "out", ".cache", "__pycache__", ".git", ".hg", ".svn"})

SKIP_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".map",
        ".lock",
    }
)


_SCRIPT_REFERENCES = [
    "https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/",
    "https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/",
    "https://unit42.paloaltonetworks.com/npm-supply-chain-attack-shai-hulud-2-0/",
]

_SOURCE_REFERENCES = [
    "https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/",
    "https://unit42.paloaltonetworks.com/npm-supply-chain-attack-shai-hulud-2-0/",
]


def _remediation(name: str, in_source: bool) -> str:
    where = " in source" if in_source else ""

    if "C2" in name or name in ("Shai-Hulud exfil", "Scavenger C2"):
        return (
            f"Known supply chain attack C2 domain detected{where}. Remove this dependency immediately. "
            "Rotate any credentials that may have been exposed. "
            "See: https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/"
        )
    if "metadata" in name.lower() or "IMDS" in name or name == "metadata_header":
        return (
            f"Cloud metadata endpoint access detected{where}. This can exfiltrate IAM credentials. "
            "Ensure your environment blocks IMDS access from npm install. "
            "See: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
        )
    if "phishing" in name.lower() or "typosquat" in name.lower():
        return (
            f"Phishing/typosquat domain detected{where}. This domain mimics npmjs.com to steal credentials. "
            "Remove this dependency and verify all npm credentials."
        )
    if "env_exfil" in name:
        return (
            f"Environment variables are being sent over the network{where}. "
            "This is a credential exfiltration pattern. Remove this dependency and rotate exposed credentials."
        )
    if "Scavenger" in name or "scavenger" in name:
        return (
            f"Scavenger malware indicator detected{where} (CVE-2025-54313). "
            "Remove this dependency immediately and audit all systems."
        )
    return f"Suspicious network pattern detected{where}. Review this dependency carefully."


def _tp(
    name: str,
    pattern: re.Pattern[str],
    severity: Severity,
    desc: str,
    required_tokens: frozenset[str],
    in_source: bool,
) -> TokenPattern:
    return TokenPattern(
        rule_id="L2-NETEX-001",
        pattern=pattern,
        severity=severity,
        message=desc,
        remediation=_remediation(name, in_source),
        required_tokens=required_tokens,
        confidence=Confidence.MEDIUM if in_source else Confidence.HIGH,
        references=_SOURCE_REFERENCES if in_source else _SCRIPT_REFERENCES,
    )


def _build_patterns(in_source: bool) -> list[TokenPattern]:
    patterns: list[TokenPattern] = []

    # C2 domains.
    c2_domains: list[tuple[str, str, Severity, str, frozenset[str]]] = [
        (
            r"\bshai-hulud\.cc\b",
            "Shai-Hulud C2",
            Severity.CRITICAL,
            "Shai-Hulud worm C2 domain",
            frozenset({"shai-hulud.cc"}),
        ),
        (
            r"\bfirebase\.su\b",
            "Scavenger C2",
            Severity.CRITICAL,
            "CVE-2025-54313 Scavenger C2 domain",
            frozenset({"firebase.su"}),
        ),
        (
            r"\bdieorsuffer\.com\b",
            "Scavenger C2",
            Severity.CRITICAL,
            "CVE-2025-54313 Scavenger C2 domain",
            frozenset({"dieorsuffer.com"}),
        ),
        (
            r"\bsmartscreen-api\.com\b",
            "Scavenger C2",
            Severity.CRITICAL,
            "CVE-2025-54313 Scavenger C2 phishing domain",
            frozenset({"smartscreen-api.com"}),
        ),
        (
            r"\bwebhook\.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
            "Shai-Hulud exfil",
            Severity.CRITICAL,
            "Known Shai-Hulud exfiltration webhook",
            frozenset({"webhook.site"}),
        ),
    ]
    for pattern_str, name, severity, desc, tokens in c2_domains:
        patterns.append(_tp(name, re.compile(pattern_str, re.IGNORECASE), severity, desc, tokens, in_source))

    # Phishing domains.
    phishing_domains: list[tuple[str, str, Severity, str, frozenset[str]]] = [
        (
            r"\bnpmjs\.(?:help|support|security)\b",
            "npm phishing",
            Severity.HIGH,
            "Phishing domain impersonating npmjs.com",
            frozenset({"npmjs."}),
        ),
        (
            r"\bnpnjs\.com\b",
            "npm typosquat",
            Severity.HIGH,
            "Typosquat domain mimicking npmjs.com",
            frozenset({"npnjs.com"}),
        ),
        (
            r"\bnprnjs\.\b",
            "npm typosquat",
            Severity.MEDIUM,
            "Typosquat domain mimicking npmjs.com",
            frozenset({"nprnjs."}),
        ),
        (
            r"\bnpmj5\.\b",
            "npm typosquat",
            Severity.MEDIUM,
            "Typosquat domain mimicking npmjs.com",
            frozenset({"npmj5."}),
        ),
        (
            r"\bnpn-js\.\b",
            "npm typosquat",
            Severity.MEDIUM,
            "Typosquat domain mimicking npmjs.com",
            frozenset({"npn-js."}),
        ),
    ]
    for pattern_str, name, severity, desc, tokens in phishing_domains:
        patterns.append(_tp(name, re.compile(pattern_str, re.IGNORECASE), severity, desc, tokens, in_source))

    # Cloud metadata.
    cloud_metadata: list[tuple[str, str, Severity, str, frozenset[str]]] = [
        (
            r"169\.254\.169\.254",
            "AWS IMDS",
            Severity.CRITICAL,
            "AWS Instance Metadata Service endpoint",
            frozenset({"169.254.169.254"}),
        ),
        (
            r"fd00:ec2::254",
            "AWS IMDS IPv6",
            Severity.CRITICAL,
            "AWS Instance Metadata Service IPv6 endpoint",
            frozenset({"fd00:ec2::254"}),
        ),
        (
            r"\[fd00:ec2::254\]",
            "AWS IMDS IPv6 brackets",
            Severity.CRITICAL,
            "AWS IMDS IPv6 bracket notation",
            frozenset({"[fd00:ec2::254]"}),
        ),
        (
            r"metadata\.google\.internal",
            "GCP metadata",
            Severity.CRITICAL,
            "GCP Compute Engine metadata endpoint",
            frozenset({"metadata.google.internal"}),
        ),
        (
            r"metadata\.azure\.com",
            "Azure metadata",
            Severity.CRITICAL,
            "Azure Instance Metadata Service endpoint",
            frozenset({"metadata.azure.com"}),
        ),
        (
            r"/latest/meta-data/",
            "AWS IMDS path",
            Severity.CRITICAL,
            "AWS IMDS metadata path pattern",
            frozenset({"/latest/meta-data/"}),
        ),
        (
            r"/computeMetadata/v1/",
            "GCP metadata path",
            Severity.CRITICAL,
            "GCP metadata path pattern",
            frozenset({"/computemetadata/v1/"}),
        ),
    ]
    for pattern_str, name, severity, desc, tokens in cloud_metadata:
        patterns.append(_tp(name, re.compile(pattern_str), severity, desc, tokens, in_source))

    return patterns


def _build_env_exfil_patterns(in_source: bool) -> list[TokenPattern]:
    patterns: list[TokenPattern] = []

    # Network requests that include process.env.
    http_libs: list[tuple[str, str]] = [
        (r"fetch", "fetch"),
        (r"axios", "axios"),
        (r"http\.request", "http.request"),
        (r"https\.request", "https.request"),
        (r"got", "got"),
        (r"request", "request"),
    ]
    for lib, token in http_libs:
        patterns.append(
            _tp(
                "env_exfil_fetch",
                re.compile(rf"\b{lib}\s*.*process\.env", re.IGNORECASE),
                Severity.CRITICAL,
                "Environment variable exfiltration via network request",
                frozenset({token, "process.env"}),
                in_source,
            )
        )

    # curl/wget sending credential env vars.
    for tool, tool_token in ((r"curl", "curl"), (r"wget", "wget")):
        patterns.append(
            _tp(
                "env_exfil_curl",
                re.compile(
                    rf"\b{tool}\s+.*\$(?:AWS_|NPM_TOKEN|GITHUB_TOKEN|NODE_AUTH_TOKEN|GITLAB_TOKEN)",
                    re.IGNORECASE,
                ),
                Severity.CRITICAL,
                "Environment variable exfiltration via curl/wget",
                frozenset({tool_token}),
                in_source,
            )
        )

    # Azure metadata header.
    patterns.append(
        _tp(
            "metadata_header",
            re.compile(r"Metadata:\s*true", re.IGNORECASE),
            Severity.HIGH,
            "Azure metadata header pattern detected",
            frozenset({"metadata:"}),
            in_source,
        )
    )

    # Scavenger malware native libraries.
    scavenger_files: list[tuple[str, str, str]] = [
        (r"\bnode-gyp\.(?:dll|so)\b", "node-gyp", "node-gyp"),
        (r"\bloader\.(?:dll|so)\b", "loader", "loader."),
        (r"\bversion\.(?:dll|so)\b", "version", "version."),
        (r"\b(?:umpdc\.(?:dll|so)|libumpdc\.so)\b", "umpdc", "umpdc"),
        (r"\b(?:profapi\.(?:dll|so)|libprofapi\.so)\b", "profapi", "profapi"),
    ]
    for regex, _label, token in scavenger_files:
        patterns.append(
            _tp(
                "scavenger_dll",
                re.compile(regex),
                Severity.CRITICAL,
                "Scavenger malware DLL/SO file reference detected",
                frozenset({token}),
                in_source,
            )
        )

    return patterns


_SCRIPT_SCANNER = PatternScanner(_build_patterns(in_source=False) + _build_env_exfil_patterns(in_source=False))
_TEXT_SCANNER = PatternScanner(_build_patterns(in_source=False))  # no env-exfil for non-script text
_SOURCE_SCANNER = PatternScanner(_build_patterns(in_source=True) + _build_env_exfil_patterns(in_source=True))


def _scan_text_for_exfil(text: str, source_label: str, is_script: bool = False) -> list[Finding]:
    scanner = _SCRIPT_SCANNER if is_script else _TEXT_SCANNER
    return scanner.scan_text(text, source_label, "")


def _scan_source_for_exfil(file_path: Path, pkg_label: str) -> list[Finding]:
    return _SOURCE_SCANNER.scan_file(
        file_path,
        pkg_label,
        max_bytes=MAX_FILE_BYTES,
        skip_extensions=SKIP_EXTENSIONS,
        skip_dirs=SKIP_DIRS,
    )


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
                        script_findings = _scan_text_for_exfil(script_value, pkg_label, is_script=True)
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
                    script_findings = _scan_text_for_exfil(script_value, pkg_label, is_script=True)
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
