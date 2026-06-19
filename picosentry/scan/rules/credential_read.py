from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import load_package_json

__all__ = ["detect_credential_reading"]

CREDENTIAL_PATTERNS = (
    re.compile(r"process\.env\.(?:AWS_|GITHUB_|NPM_|TOKEN|SECRET|KEY|PASS|AUTH|CREDENTIAL)", re.IGNORECASE),
    re.compile(
        r"""(?:readFileSync|readFile|fs\.read|cat\s+|type\s+)['"].*?(?:\.npmrc|\.env|\.aws|\.ssh|\.gitconfig|id_rsa|id_ed25519)""",
        re.IGNORECASE,
    ),
    re.compile(r"""['"/](?:\.npmrc|\.env|\.aws[/\\]|\.ssh[/\\])['"/]""", re.IGNORECASE),
    re.compile(
        r"(?:password|passwd|secret|token|api_key|apikey|access_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE
    ),
    re.compile(r"process\.env(?!\.\w)", re.IGNORECASE),
    re.compile(r"(?:curl|wget|fetch|http\.get|http\.post|request|axios|got)\s*.*process\.env", re.IGNORECASE),
)


JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx"}


MAX_FILE_BYTES = 512_000


MAX_FILES_PER_PACKAGE = 200


SKIP_DIRS = frozenset(
    {
        "dist",
        "build",
        "out",
        ".cache",
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
    }
)

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


def redact_secret_evidence(text: str) -> str:
    if not text:
        return text

    redacted = re.sub(
        r"""(['\"])([A-Za-z0-9_\-+/=]{8,})(['\"])""",
        r"\1<REDACTED>\3",
        text,
    )

    redacted = re.sub(
        r"\b([A-Za-z0-9_\-+/]{32,})\b",
        lambda m: m.group(0)[:8] + "…<REDACTED>",
        redacted,
    )

    return re.sub(
        r"(_authToken\s*=\s*)\S+",
        r"\1<REDACTED>",
        redacted,
    )


def _should_skip_path(file_path: Path) -> bool:

    if any(part in SKIP_DIRS for part in file_path.parts):
        return True

    if file_path.suffix.lower() in SKIP_EXTENSIONS:
        return True

    return ".min." in file_path.name


def _scan_scripts_for_creds(pkg: dict, pkg_json: Path) -> list[Finding]:
    findings: list[Finding] = []
    scripts = pkg.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    for script_key, script_value in sorted(scripts.items()):
        script_str = str(script_value)

        has_env_read = "process.env" in script_str or "$" in script_str
        has_network = any(p in script_str for p in ("curl", "wget", "fetch", "http://", "https://", "nc ", "ncat"))

        if has_env_read and has_network:
            findings.append(
                Finding(
                    rule_id="L2-CRED-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=(
                        f"Install script '{script_key}' reads environment variables "
                        "and makes network requests — potential credential exfiltration"
                    ),
                    evidence=f"scripts.{script_key} = {script_str[:200]}",
                    remediation=(
                        f"Remove or audit the '{script_key}' script. "
                        "Use --ignore-scripts during install. "
                        "Never allow install scripts to read env vars and make network calls."
                    ),
                    references=[
                        "https://blog.vlt.sh/blog/postinstall-harm",
                        "https://github.com/npm/npm/issues/17152",
                    ],
                )
            )
        elif has_env_read:
            env_vars = re.findall(r"process\.env\.\w+", script_str)
            shell_vars = re.findall(r"\$\{?\w+\}?", script_str)
            all_vars = env_vars + shell_vars
            sensitive = any(
                kw in " ".join(all_vars).upper()
                for kw in ("TOKEN", "SECRET", "KEY", "PASS", "AUTH", "CREDENTIAL", "AWS", "NPM", "GITHUB")
            )
            if sensitive:
                findings.append(
                    Finding(
                        rule_id="L2-CRED-001",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        package=pkg_label,
                        file=str(pkg_json),
                        message=(f"Install script '{script_key}' reads sensitive environment variables"),
                        evidence=f"scripts.{script_key} = {script_str[:200]}",
                        remediation=(
                            f"Review the '{script_key}' script for credential access. "
                            "Consider --ignore-scripts during install."
                        ),
                        references=[
                            "https://blog.vlt.sh/blog/postinstall-harm",
                        ],
                    )
                )

    return findings


def _scan_source_for_creds(file_path: Path, pkg_label: str) -> list[Finding]:
    findings: list[Finding] = []

    if _should_skip_path(file_path):
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

    for pattern in CREDENTIAL_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            matched_text = match.group(0)[:120]

            severity = Severity.MEDIUM
            confidence = Confidence.MEDIUM

            if "process.env" in matched_text and any(p in matched_text for p in ("curl", "wget", "fetch", "http")):
                severity = Severity.CRITICAL
                confidence = Confidence.HIGH
            elif any(kw in matched_text.upper() for kw in ("TOKEN", "SECRET", "KEY", "PASS", "AWS", "NPM_")):
                severity = Severity.HIGH
                confidence = Confidence.HIGH

            redacted_text = redact_secret_evidence(matched_text)
            findings.append(
                Finding(
                    rule_id="L2-CRED-001",
                    severity=severity,
                    confidence=confidence,
                    package=pkg_label,
                    file=str(file_path),
                    line=line_num,
                    message=f"Credential-reading pattern detected: {redacted_text[:60]}",
                    evidence=redacted_text,
                    remediation=(
                        "Review this code path. If it reads credentials unnecessarily, "
                        "remove it. If legitimate, ensure credentials are not logged or transmitted."
                    ),
                    references=[
                        "https://blog.vlt.sh/blog/postinstall-harm",
                        "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_variables_in_url",
                    ],
                )
            )

    return findings


def detect_credential_reading(target: Path) -> list[Finding]:
    findings: list[Finding] = []

    root_pkg = target / "package.json"
    root_pkg_label = "root"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            root_pkg_label = f"{pkg.get('name', 'root')}@{pkg.get('version', 'unknown')}"
            findings.extend(_scan_scripts_for_creds(pkg, root_pkg))

    _scan_package_sources(target, root_pkg_label, findings)

    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue

            pkg_json = child / "package.json"
            if pkg_json.is_file():
                pkg = load_package_json(pkg_json)
                if pkg:
                    pkg_label = f"{pkg.get('name', child.name)}@{pkg.get('version', 'unknown')}"
                    findings.extend(_scan_scripts_for_creds(pkg, pkg_json))

                    _scan_package_sources(child, pkg_label, findings)

            if child.name.startswith("@") and child.is_dir():
                for scoped_child in sorted(child.iterdir()):
                    if not scoped_child.is_dir():
                        continue
                    scoped_pkg = scoped_child / "package.json"
                    if scoped_pkg.is_file():
                        pkg = load_package_json(scoped_pkg)
                        if pkg:
                            pkg_label = f"{pkg.get('name', scoped_child.name)}@{pkg.get('version', 'unknown')}"
                            findings.extend(_scan_scripts_for_creds(pkg, scoped_pkg))

                            _scan_package_sources(scoped_child, pkg_label, findings)

    return findings


def _scan_package_sources(pkg_dir: Path, pkg_label: str, findings: list[Finding]) -> None:
    file_count = 0
    for ext in JS_EXTENSIONS:
        for src_file in pkg_dir.rglob(f"*{ext}"):
            if file_count >= MAX_FILES_PER_PACKAGE:
                return  # exit both loops
            if not src_file.is_symlink():
                findings.extend(_scan_source_for_creds(src_file, pkg_label))
                file_count += 1
