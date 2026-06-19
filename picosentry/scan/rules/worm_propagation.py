from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import load_package_json

__all__ = ["detect_worm_propagation"]


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


WORM_NPM_PUBLISH = re.compile(
    r"\bnpm\s+(?:whoami|publish|token\s+list)\b",
    re.IGNORECASE,
)


REMOTE_PIPE_SHELL = re.compile(
    r"""(?:curl|wget|fetch)\s+.*[|\s]*(?:bash|sh|node)\b""",
    re.IGNORECASE,
)


NODE_EVAL_ONELINER = re.compile(
    r"""\bnode\s+-e\s+['"]""",
)


BUN_PAYLOAD = re.compile(
    r"\b(?:setup_bun|bun_environment)\.js\b",
)


GITHUB_REPO_CREATION = re.compile(
    r"\bmakeRepo\b.*\bShai-Hulud\b|\bShai-Hulud\b",
    re.IGNORECASE,
)


GIT_CONFIG_MANIPULATION = re.compile(
    r"""\bgit\s+config\s+--unset\s+core\.bare\b""",
)


WORKFLOW_INJECTION = re.compile(
    r"""\brm\s+-rf\s+.*\.github/workflows\b""",
)


DESTRUCTIVE_FALLBACK = re.compile(
    r"""\brm\s+-rf\s+[~$]""",
)


SELF_MODIFY_PACKAGE = re.compile(
    r"""writeFileSync\s*\(.*package\.json""",
)


GLOB_SCAN_NODE_MODULES = re.compile(
    r"""glob.*node_modules.*package\.json""",
)


BUN_RUN_EXEC = re.compile(
    r"""\bbun\s+(?:run|x|exec)\b""",
    re.IGNORECASE,
)


SILENT_FAIL_AFTER_EXEC = re.compile(
    r"""(?:&&|\|\||;)\s*exit\s+\d""",
)


GIT_URL_DEP = re.compile(
    r"""(?:^github:|^git\+|^git://|^https?://[^\s]+\.git|^[\w.-]+/[\w.-]+#)""",
    re.IGNORECASE,
)


CAMPAIGN_IDENTIFIERS = re.compile(
    r"""MUT-8694|mut-8964|s1ngularity.*Nx|Shai-Hulud|Sha1-Hulud|firedalazer""",
    re.IGNORECASE,
)


CI_SECRETS_EXFIL = re.compile(
    r"""toJSON\s*\(\s*secrets\s*\)""",
    re.IGNORECASE,
)


BUN_ONLY_API = re.compile(
    r"""\bBun\.(?:gunzipSync|inflateSync)\b""",
)


SELF_PROPAGATION_PATTERNS: list[tuple[str, re.Pattern, Severity, str, str]] = [
    (
        "npm_publish",
        WORM_NPM_PUBLISH,
        Severity.CRITICAL,
        "npm publish/whoami in install script — worm self-propagation",
        "Remove npm publish/whoami from install scripts. Legitimate packages never publish during install.",
    ),
    (
        "remote_pipe_shell",
        REMOTE_PIPE_SHELL,
        Severity.CRITICAL,
        "Remote payload piped to shell — download-and-execute pattern",
        "Remove curl|bash or wget|sh patterns. Use pinned dependencies instead.",
    ),
    (
        "node_eval_oneliner",
        NODE_EVAL_ONELINER,
        Severity.HIGH,
        "node -e inline execution — obfuscated payload pattern",
        "Remove node -e one-liners from install scripts. They are a common attack vector.",
    ),
    (
        "bun_payload",
        BUN_PAYLOAD,
        Severity.CRITICAL,
        "Shai-Hulud 2.0 Bun payload file detected",
        "This is a known Shai-Hulud 2.0 payload. Remove immediately and audit all credentials.",
    ),
    (
        "github_repo_creation",
        GITHUB_REPO_CREATION,
        Severity.CRITICAL,
        "Shai-Hulud GitHub repo creation pattern detected",
        "This pattern creates attacker-controlled GitHub repos for credential exfiltration.",
    ),
    (
        "git_config_manipulation",
        GIT_CONFIG_MANIPULATION,
        Severity.CRITICAL,
        "Git config manipulation — repository hijacking pattern",
        "git config --unset core.bare is used by Shai-Hulud to hijack repositories.",
    ),
    (
        "workflow_injection",
        WORKFLOW_INJECTION,
        Severity.CRITICAL,
        "GitHub workflow deletion — CI/CD hijacking pattern",
        "Deleting .github/workflows is a Shai-Hulud attack pattern to inject malicious CI.",
    ),
    (
        "destructive_fallback",
        DESTRUCTIVE_FALLBACK,
        Severity.CRITICAL,
        "Destructive fallback — home directory wipe pattern",
        "Shai-Hulud 2.0 wipes the home directory as a destructive fallback. Remove this immediately.",
    ),
    (
        "self_modify_package",
        SELF_MODIFY_PACKAGE,
        Severity.CRITICAL,
        "Self-modifying package.json — worm rewrites its own manifest",
        "writeFileSync to package.json is a Shai-Hulud self-propagation pattern.",
    ),
    (
        "glob_scan_nm",
        GLOB_SCAN_NODE_MODULES,
        Severity.HIGH,
        "Node_modules scanning — worm target discovery pattern",
        "Scanning node_modules for package.json files is a Shai-Hulud propagation pattern.",
    ),
    (
        "bun_run_exec",
        BUN_RUN_EXEC,
        Severity.HIGH,
        "Bun runtime execution in install/lifecycle script — Mini Shai-Hulud evasion pattern",
        "Bun is used to evade Node-based monitoring (no --require hook) and run Bun-only payloads. "
        "Legitimate packages almost never invoke `bun run` from an install/prepare script. Audit the target script.",
    ),
    (
        "silent_fail_after_exec",
        SILENT_FAIL_AFTER_EXEC,
        Severity.HIGH,
        "Forced exit after script execution — hides payload run from install output",
        "`&& exit 1` / `|| exit 0` after a command makes npm treat a (often optional) dependency as failed "
        "so the install looks benign after the payload already ran. Inspect what executed before the exit.",
    ),
    (
        "campaign_identifier",
        CAMPAIGN_IDENTIFIERS,
        Severity.CRITICAL,
        "Known attack campaign identifier detected",
        "This matches known Shai-Hulud campaign identifiers (MUT-8694, s1ngularity/Nx, firedalazer).",
    ),
    (
        "ci_secrets_exfil",
        CI_SECRETS_EXFIL,
        Severity.CRITICAL,
        "CI secrets dump — toJSON(secrets) exfiltration pattern",
        "Dumping toJSON(secrets) exposes every CI secret to a workflow step. "
        "This is the Mini Shai-Hulud workflow-injection exfiltration stage. Remove and rotate all CI secrets.",
    ),
    (
        "bun_only_api",
        BUN_ONLY_API,
        Severity.HIGH,
        "Bun-only runtime API in package source — Mini Shai-Hulud payload trait",
        "Payloads use Bun-only APIs (Bun.gunzipSync) so they cannot run under Node, evading Node-based "
        "monitoring. Legitimate dependencies rarely require Bun at runtime. Review the source.",
    ),
]


def _scan_scripts_for_worm(pkg: dict, pkg_json: Path) -> list[Finding]:
    findings: list[Finding] = []
    scripts = pkg.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    has_lifecycle_script = any(k in scripts for k in INSTALL_SCRIPT_KEYS)
    for dep_field in ("dependencies", "optionalDependencies", "devDependencies", "peerDependencies"):
        deps = pkg.get(dep_field, {})
        if not isinstance(deps, dict):
            continue
        for dep_name, dep_spec in deps.items():
            spec = str(dep_spec)
            if GIT_URL_DEP.search(spec):
                sev = Severity.CRITICAL if has_lifecycle_script else Severity.MEDIUM
                findings.append(
                    Finding(
                        rule_id="L2-WORM-001",
                        severity=sev,
                        confidence=Confidence.HIGH if has_lifecycle_script else Confidence.MEDIUM,
                        package=pkg_label,
                        file=str(pkg_json),
                        message=(
                            "Git-resolved dependency with install-time lifecycle script — "
                            "Mini Shai-Hulud delivery pattern"
                            if has_lifecycle_script
                            else "Git-resolved dependency — verify provenance"
                        ),
                        evidence=f"{dep_field}.{dep_name}: {spec[:80]}",
                        remediation=(
                            "A dependency resolving to a git/GitHub URL runs lifecycle scripts at install "
                            "time and bypasses the registry's published-version controls. Pin to a registry "
                            "version, or vendor and review the code. Treat git deps + prepare/postinstall as hostile."
                        ),
                        references=[
                            "https://snyk.io/blog/tanstack-npm-packages-compromised/",
                            "https://www.picussecurity.com/resource/blog/mini-shai-hulud-the-npm-supply-chain-worm-explained",
                        ],
                    )
                )

    for script_key in INSTALL_SCRIPT_KEYS:
        if script_key not in scripts:
            continue
        script_value = str(scripts[script_key])

        for _name, pattern, severity, message, remediation in SELF_PROPAGATION_PATTERNS:
            for match in pattern.finditer(script_value):
                matched_text = match.group(0)[:120]
                findings.append(
                    Finding(
                        rule_id="L2-WORM-001",
                        severity=severity,
                        confidence=Confidence.HIGH,
                        package=pkg_label,
                        file=str(pkg_json),
                        message=message,
                        evidence=f"scripts.{script_key}: {matched_text}",
                        remediation=remediation,
                        references=[
                            "https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/",
                            "https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/",
                        ],
                    )
                )

    return findings


def _scan_source_for_worm(file_path: Path, pkg_label: str) -> list[Finding]:
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

    for _name, pattern, severity, message, remediation in SELF_PROPAGATION_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            matched_text = match.group(0)[:120]
            findings.append(
                Finding(
                    rule_id="L2-WORM-001",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    package=pkg_label,
                    file=str(file_path),
                    line=line_num,
                    message=message,
                    evidence=matched_text,
                    remediation=remediation,
                    references=[
                        "https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/",
                        "https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/",
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
            findings.extend(_scan_source_for_worm(src_file, pkg_label))
            file_count += 1


def detect_worm_propagation(target: Path) -> list[Finding]:
    findings: list[Finding] = []

    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            findings.extend(_scan_scripts_for_worm(pkg, root_pkg))
            _scan_package_sources(target, pkg.get("name", "root"), findings)

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
                    findings.extend(_scan_scripts_for_worm(pkg, pkg_json))
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
                            findings.extend(_scan_scripts_for_worm(pkg, scoped_pkg))
                            _scan_package_sources(scoped_child, pkg_label, findings)

    return findings
