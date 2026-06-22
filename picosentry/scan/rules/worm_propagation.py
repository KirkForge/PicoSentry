from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .pattern_scanner import PatternScanner, TokenPattern
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


_REFERENCES = [
    "https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/",
    "https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/",
]


GIT_URL_DEP = re.compile(
    r"(?:^github:|^git\+|^git://|^https?://[^\s]+\.git|^[\w.-]+/[\w.-]+#)",
    re.IGNORECASE,
)


def _build_worm_patterns(confidence: Confidence) -> list[TokenPattern]:
    """Return token-filtered worm/self-propagation patterns.

    Patterns that contain regex alternatives are split into deterministic
    sub-patterns so each one has a reliable set of required literal tokens.
    The same pattern list is reused for install scripts (HIGH confidence) and
    package source files (MEDIUM confidence).
    """
    patterns: list[TokenPattern] = []

    # npm publish / whoami / token list in install scripts.
    for cmd, token in (
        ("whoami", "whoami"),
        ("publish", "publish"),
        ("token list", "token list"),
    ):
        patterns.append(
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(rf"\bnpm\s+{re.escape(cmd)}\b", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="npm publish/whoami in install script — worm self-propagation",
                remediation=(
                    "Remove npm publish/whoami from install scripts. Legitimate packages never publish during install."
                ),
                required_tokens=frozenset({"npm", token}),
                confidence=confidence,
                references=_REFERENCES,
            )
        )

    # Remote payload piped to shell / node.
    for downloader in ("curl", "wget", "fetch"):
        for shell in ("bash", "sh", "node"):
            patterns.append(
                TokenPattern(
                    rule_id="L2-WORM-001",
                    pattern=re.compile(
                        rf"\b{downloader}\s+.*[|\s]*{shell}\b",
                        re.IGNORECASE,
                    ),
                    severity=Severity.CRITICAL,
                    message="Remote payload piped to shell — download-and-execute pattern",
                    remediation="Remove curl|bash or wget|sh patterns. Use pinned dependencies instead.",
                    required_tokens=frozenset({downloader, shell}),
                    confidence=confidence,
                    references=_REFERENCES,
                )
            )

    patterns.extend(
        [
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bnode\s+-e\s+['\"]", re.IGNORECASE),
                severity=Severity.HIGH,
                message="node -e inline execution — obfuscated payload pattern",
                remediation="Remove node -e one-liners from install scripts. They are a common attack vector.",
                required_tokens=frozenset({"node -e"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bsetup_bun\.js\b", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="Shai-Hulud 2.0 Bun payload file detected",
                remediation="This is a known Shai-Hulud 2.0 payload. Remove immediately and audit all credentials.",
                required_tokens=frozenset({"setup_bun.js"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bbun_environment\.js\b", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="Shai-Hulud 2.0 Bun payload file detected",
                remediation="This is a known Shai-Hulud 2.0 payload. Remove immediately and audit all credentials.",
                required_tokens=frozenset({"bun_environment.js"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bmakeRepo\b.*\bShai-Hulud\b", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="Shai-Hulud GitHub repo creation pattern detected",
                remediation="This pattern creates attacker-controlled GitHub repos for credential exfiltration.",
                required_tokens=frozenset({"makerepo", "shai-hulud"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bShai-Hulud\b", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="Shai-Hulud GitHub repo creation pattern detected",
                remediation="This pattern creates attacker-controlled GitHub repos for credential exfiltration.",
                required_tokens=frozenset({"shai-hulud"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bgit\s+config\s+--unset\s+core\.bare\b", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="Git config manipulation — repository hijacking pattern",
                remediation="git config --unset core.bare is used by Shai-Hulud to hijack repositories.",
                required_tokens=frozenset({"git config", "core.bare"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\brm\s+-rf\s+.*\.github/workflows\b", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="GitHub workflow deletion — CI/CD hijacking pattern",
                remediation="Deleting .github/workflows is a Shai-Hulud attack pattern to inject malicious CI.",
                required_tokens=frozenset({"rm -rf", ".github/workflows"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\brm\s+-rf\s+~", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="Destructive fallback — home directory wipe pattern",
                remediation=(
                    "Shai-Hulud 2.0 wipes the home directory as a destructive fallback. Remove this immediately."
                ),
                required_tokens=frozenset({"rm -rf", "~"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\brm\s+-rf\s+\$", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="Destructive fallback — home directory wipe pattern",
                remediation=(
                    "Shai-Hulud 2.0 wipes the home directory as a destructive fallback. Remove this immediately."
                ),
                required_tokens=frozenset({"rm -rf", "$"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"writeFileSync\s*\(.*package\.json", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="Self-modifying package.json — worm rewrites its own manifest",
                remediation="writeFileSync to package.json is a Shai-Hulud self-propagation pattern.",
                required_tokens=frozenset({"writefilesync", "package.json"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"glob.*node_modules.*package\.json", re.IGNORECASE),
                severity=Severity.HIGH,
                message="Node_modules scanning — worm target discovery pattern",
                remediation="Scanning node_modules for package.json files is a Shai-Hulud propagation pattern.",
                required_tokens=frozenset({"glob", "node_modules"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bbun\s+run\b", re.IGNORECASE),
                severity=Severity.HIGH,
                message="Bun runtime execution in install/lifecycle script — Mini Shai-Hulud evasion pattern",
                remediation=(
                    "Bun is used to evade Node-based monitoring (no --require hook) "
                    "and run Bun-only payloads. Legitimate packages almost never invoke `bun run` "
                    "from an install/prepare script. Audit the target script."
                ),
                required_tokens=frozenset({"bun run"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bbun\s+x\b", re.IGNORECASE),
                severity=Severity.HIGH,
                message="Bun runtime execution in install/lifecycle script — Mini Shai-Hulud evasion pattern",
                remediation=(
                    "Bun is used to evade Node-based monitoring (no --require hook) "
                    "and run Bun-only payloads. Legitimate packages almost never invoke `bun x` "
                    "from an install/prepare script. Audit the target script."
                ),
                required_tokens=frozenset({"bun x"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bbun\s+exec\b", re.IGNORECASE),
                severity=Severity.HIGH,
                message="Bun runtime execution in install/lifecycle script — Mini Shai-Hulud evasion pattern",
                remediation=(
                    "Bun is used to evade Node-based monitoring (no --require hook) "
                    "and run Bun-only payloads. Legitimate packages almost never invoke `bun exec` "
                    "from an install/prepare script. Audit the target script."
                ),
                required_tokens=frozenset({"bun exec"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
        ]
    )

    # Forced exit after payload run.
    for sep in ("&&", "||", ";"):
        patterns.append(
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(rf"{re.escape(sep)}\s*exit\s+\d", re.IGNORECASE),
                severity=Severity.HIGH,
                message="Forced exit after script execution — hides payload run from install output",
                remediation=(
                    "`&& exit 1` / `|| exit 0` after a command makes npm treat a dependency as failed "
                    "so the install looks benign after the payload already ran. "
                    "Inspect what executed before the exit."
                ),
                required_tokens=frozenset({sep, "exit"}),
                confidence=confidence,
                references=_REFERENCES,
            )
        )

    # Known campaign identifiers.
    for identifier, token in (
        ("MUT-8694", "mut-8694"),
        ("mut-8964", "mut-8964"),
        ("s1ngularity.*Nx", "s1ngularity"),
        ("Shai-Hulud", "shai-hulud"),
        ("Sha1-Hulud", "sha1-hulud"),
        ("firedalazer", "firedalazer"),
    ):
        patterns.append(
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(rf"\b{identifier}\b", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="Known attack campaign identifier detected",
                remediation=(
                    "This matches known Shai-Hulud campaign identifiers (MUT-8694, s1ngularity/Nx, firedalazer)."
                ),
                required_tokens=frozenset({token}),
                confidence=confidence,
                references=_REFERENCES,
            )
        )

    patterns.extend(
        [
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"toJSON\s*\(\s*secrets\s*\)", re.IGNORECASE),
                severity=Severity.CRITICAL,
                message="CI secrets dump — toJSON(secrets) exfiltration pattern",
                remediation="Dumping toJSON(secrets) exposes every CI secret to a workflow step. "
                "This is the Mini Shai-Hulud workflow-injection exfiltration stage. Remove and rotate all CI secrets.",
                required_tokens=frozenset({"tojson", "secrets"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bBun\.gunzipSync\b", re.IGNORECASE),
                severity=Severity.HIGH,
                message="Bun-only runtime API in package source — Mini Shai-Hulud payload trait",
                remediation=(
                    "Payloads use Bun-only APIs (Bun.gunzipSync) so they cannot run under Node, "
                    "evading Node-based monitoring. Legitimate dependencies rarely require Bun at runtime. "
                    "Review the source."
                ),
                required_tokens=frozenset({"bun.gunzipsync"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
            TokenPattern(
                rule_id="L2-WORM-001",
                pattern=re.compile(r"\bBun\.inflateSync\b", re.IGNORECASE),
                severity=Severity.HIGH,
                message="Bun-only runtime API in package source — Mini Shai-Hulud payload trait",
                remediation=(
                    "Payloads use Bun-only APIs (Bun.inflateSync) so they cannot run under Node, "
                    "evading Node-based monitoring. Legitimate dependencies rarely require Bun at runtime. "
                    "Review the source."
                ),
                required_tokens=frozenset({"bun.inflatesync"}),
                confidence=confidence,
                references=_REFERENCES,
            ),
        ]
    )

    return patterns


_SCRIPT_SCANNER = PatternScanner(_build_worm_patterns(Confidence.HIGH))
_SOURCE_SCANNER = PatternScanner(_build_worm_patterns(Confidence.MEDIUM))


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

        for finding in _SCRIPT_SCANNER.scan_text(script_value, pkg_label, str(pkg_json)):
            findings.append(
                replace(
                    finding,
                    evidence=f"scripts.{script_key}: {finding.evidence}",
                    line=None,
                )
            )

    return findings


def _scan_source_for_worm(file_path: Path, pkg_label: str) -> list[Finding]:
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
