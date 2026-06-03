"""
L2-POST-001: Post-install script detection.

Flags packages that declare install, postinstall, or preinstall scripts
in their package.json. These are the #1 vector for supply chain attacks.

Pure function: (target_path, corpus_dir) → List[Finding]
"""

from __future__ import annotations

from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_post_install_scripts"]
# Scripts that execute code at install time — the primary attack vector.
DANGEROUS_SCRIPT_KEYS = (
    "install",
    "postinstall",
    "preinstall",
    "prepare",
    "prepack",
)

# Commands that indicate network access or code execution capability.
NETWORK_PATTERNS = (
    "curl",
    "wget",
    "fetch",
    "http://",
    "https://",
    "nc ",
    "ncat",
    "socat",
    "ssh",
    "scp",
)

# Patterns indicating code execution capability (child_process, etc.)
EXEC_PATTERNS = (
    "child_process",
    "require('child_process')",
    'require("child_process")',
    ".exec(",
    ".execSync(",
    ".spawn(",
    ".spawnSync(",
    ".execFile(",
    ".execFileSync(",
    ".fork(",
)

# Commands that read credentials or sensitive files.
CREDENTIAL_PATTERNS = (
    ".npmrc",
    ".aws/",
    ".ssh/",
    ".env",
    "AWS_",
    "process.env",
    "process.stdout.write",
)


def _scan_package_json(pkg_json: Path) -> list[Finding]:
    """Scan a single package.json for dangerous install scripts."""
    findings: list[Finding] = []
    data = load_package_json(pkg_json)
    if not data:
        return findings

    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    pkg_name = data.get("name", pkg_json.parent.name)
    pkg_version = data.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    for key in DANGEROUS_SCRIPT_KEYS:
        if key in scripts:
            script_value = scripts[key]
            severity = Severity.HIGH

            # Escalate to CRITICAL if script does network access or reads creds
            script_lower = str(script_value).lower()
            has_network = any(p in script_lower for p in NETWORK_PATTERNS)
            has_creds = any(p in script_lower for p in CREDENTIAL_PATTERNS)
            has_exec = any(p in script_value for p in EXEC_PATTERNS)

            if has_network or has_creds or has_exec:
                severity = Severity.CRITICAL

            # Build remediation message based on what was detected
            risk_tags = []
            if has_network:
                risk_tags.append("network access")
            if has_creds:
                risk_tags.append("credential reading")
            if has_exec:
                risk_tags.append("child_process execution")

            if risk_tags:
                remediation = (
                    f"CRITICAL: {pkg_label} '{key}' script has "
                    + ", ".join(risk_tags)
                    + ". Audit before installing. Use --ignore-scripts."
                )
            else:
                remediation = (
                    f"Review the '{key}' script in {pkg_label}. "
                    "If not essential, remove it. Consider using "
                    "--ignore-scripts during install."
                )

            findings.append(
                Finding(
                    rule_id="L2-POST-001",
                    severity=severity,
                    confidence=Confidence.EXACT,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=f"Package declares '{key}' lifecycle script",
                    evidence=f"scripts.{key} = {script_value!r}",
                    remediation=remediation,
                    references=[
                        "https://github.com/npm/npm/issues/17152",
                        "https://blog.vlt.sh/blog/postinstall-harm",
                    ],
                )
            )

    return findings


def detect_post_install_scripts(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect packages with install/postinstall/preinstall scripts.

    Scans root package.json and every node_modules/*/package.json.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        findings.extend(_scan_package_json(root_pkg))

    # node_modules packages
    for pkg_json, _pkg in iter_node_modules(target):
        findings.extend(_scan_package_json(pkg_json))

    return findings
