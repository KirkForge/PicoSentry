
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import Confidence, Finding, Severity

logger = logging.getLogger("picosentry.dangerous_build_hooks")

__all__ = ["detect_dangerous_build_hooks"]


MAX_FILE_BYTES = 512_000
MAX_FILES_PER_PACKAGE = 200


SKIP_DIRS = frozenset({
    "dist", "build", "out", ".cache", "__pycache__", ".git", ".hg", ".svn",
})
SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".map", ".lock", ".so", ".dll", ".dylib", ".exe",
})


# Patterns that, when present in a build-time file, indicate malicious behavior.
# These intentionally use literal substring/regex detection so results remain
# deterministic and offline. Each entry is (label, severity, regex, remediation_key).
SUSPICIOUS_PATTERNS: tuple[tuple[str, Severity, re.Pattern[str], str], ...] = (
    (
        "spawns subprocess during build",
        Severity.CRITICAL,
        re.compile(
            r"\b(?:std::process::Command|Command::new|std::process::exit|"
            r"os\.system|os\.popen|subprocess\.|child_process|\.exec\(|"
            r"\.execSync\(|\.spawn\(|\.spawnSync\(|system\(|\`[^`]*\`|"
            r"sh\s+-c|bash\s+-c|cmd\.exe|powershell\.exe|Start-Process|"
            r"Invoke-Expression|IEX\b|Process\.Start|System\.Diagnostics\.Process)",
            re.IGNORECASE,
        ),
        "subprocess",
    ),
    (
        "downloads code over network during build",
        Severity.CRITICAL,
        re.compile(
            r"(?:\b(?:curl|wget)\s[^\n\"'`]*(?:\||\s\-o\s|\-\-output|\.exe|http|ftp)|"
            r"Invoke-WebRequest|DownloadString|DownloadFile|"
            r"urllib\.request\.urlretrieve|urllib\.request\.urlopen|requests\.get\(|reqwest::|hyper::Client|http::Request|http\.request\(|"
            r"ftp://|https?://[^\s\"'`]+(?:\.(?:exe|sh|bat|ps1|zip|tar\.gz|tgz|dll|so|dylib))|"
            r"\bcargo install\b|\bgem install\b|\bpip install\b|"
            r"\bnpm install\b|\byarn add\b|\bnuget install\b)",
            re.IGNORECASE,
        ),
        "network",
    ),
    (
        "obfuscated payload in build script",
        Severity.HIGH,
        re.compile(
            r"(?:base64\.b64decode|base64::decode|BASE64|atob|Buffer\.from|"
            r"fromhex|decode_hex|hex::decode|hex::decode_to_slice|"
            r"zlib\.decompress|flate2|include_bytes!|include_str!|"
            r"\\x[0-9a-fA-F]{2})",
            re.IGNORECASE,
        ),
        "obfuscation",
    ),
    (
        "reads credentials during build",
        Severity.CRITICAL,
        re.compile(
            r"(?:\.cargo/credentials|\.m2/settings\.xml|\.npmrc|\.netrc|\.env|"
            r"~/.ssh|/etc/passwd|CARGO_REGISTRY_TOKEN|NPM_TOKEN|GITHUB_TOKEN|"
            r"NODE_AUTH_TOKEN|RUBYGEMS_API_KEY|NUGET_API_KEY|MAVEN_CENTRAL_TOKEN|"
            r"process\.env\.(?:TOKEN|SECRET|KEY|PASS|AUTH|CREDENTIAL|AWS_|GITHUB_|NPM_))",
            re.IGNORECASE,
        ),
        "credentials",
    ),
    (
        "writes to system paths during build",
        Severity.HIGH,
        re.compile(
            r"\b(?:/usr/bin|/usr/local/bin|/bin/|/sbin/|/etc/|/var/|C:\\\\Windows|"
            r"%APPDATA%|%LOCALAPPDATA%|~/.bashrc|~/.zshrc|~/.profile|"
            r"PATH.*=|\.bash_profile|\.zsh_profile|registry\.hivelogin)",
            re.IGNORECASE,
        ),
        "system_path",
    ),
)


ECOSYSTEM_FILES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "cargo": (
        ("Cargo.toml", "build.rs"),
        (".rs", ".toml"),
    ),
    "go": (
        ("go.mod",),
        (".go", ".mod"),
    ),
    "rubygems": (
        (".gemspec", "Rakefile", "extconf.rb", "Gemfile"),
        (".gemspec", ".rb"),
    ),
    "maven": (
        ("pom.xml",),
        (".xml",),
    ),
    "nuget": (
        (".csproj", ".nuspec", ".targets", ".props"),
        (".csproj", ".nuspec", ".targets", ".props", ".ps1"),
    ),
}


def _detect_ecosystem(target: Path) -> str | None:
    """Return the dominant non-npm/pypi ecosystem marker present in target."""
    if not target.is_dir():
        return None
    for ecosystem, (manifest_files, _scan_suffixes) in ECOSYSTEM_FILES.items():
        for marker in manifest_files:
            if marker.startswith("."):
                # Suffix-style marker (e.g., .gemspec, .csproj)
                if any(f.name.lower().endswith(marker) for f in target.iterdir() if f.is_file()):
                    return ecosystem
            else:
                if (target / marker).is_file():
                    return ecosystem
                if any(f.name == marker for f in target.iterdir() if f.is_file()):
                    return ecosystem
        # Also detect by glob for extensions that are strong ecosystem signals.
        if ecosystem == "nuget":
            if any(target.glob("*.csproj")) or any(target.glob("*.nuspec")):
                return "nuget"
    return None


REMEDIATIONS: dict[str, str] = {
    "subprocess": (
        "Build scripts must not spawn subprocesses. Move any required shell work "
        "into a documented CI step, not a dependency build hook."
    ),
    "network": (
        "Build scripts must not download code or artifacts over the network. "
        "Vendor dependencies in the repository or use a private registry/mirror."
    ),
    "obfuscation": (
        "Build scripts should not contain encoded or compressed payloads. "
        "Replace obfuscated code with readable, reviewable source."
    ),
    "credentials": (
        "Build scripts must not read credential files or secret environment variables. "
        "Pass secrets through explicit CI environment injection only."
    ),
    "system_path": (
        "Build scripts must not write to system paths or modify user shell profiles. "
        "Install artifacts to project-local directories only."
    ),
}


def _read_text(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    if size > MAX_FILE_BYTES:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _scan_build_file(path: Path, ecosystem: str) -> list[Finding]:
    findings: list[Finding] = []
    content = _read_text(path)
    if not content:
        return findings

    pkg_label = path.parent.name or path.name

    matched_keys: set[str] = set()
    for label, severity, pattern, remediation_key in SUSPICIOUS_PATTERNS:
        for match in pattern.finditer(content):
            if remediation_key in matched_keys:
                # One finding per file per remediation category is enough; avoids
                # flooding the report on a single heavily-obfuscated build script.
                continue
            matched_keys.add(remediation_key)
            line_num = content[: match.start()].count("\n") + 1
            matched_text = match.group(0)[:120]
            findings.append(
                Finding(
                    rule_id="L2-BUILD-001",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(path),
                    line=line_num,
                    message=f"Dangerous build-time hook: {label}",
                    evidence=matched_text,
                    remediation=REMEDIATIONS[remediation_key],
                    references=[
                        "https://blog.rust-lang.org/2023/10/25/crates-io-postmortem.html",
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec61c",
                    ],
                    ecosystem=ecosystem,
                )
            )

    return findings


def _iter_target_files(target: Path, suffixes: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    if not target.is_dir():
        return files
    for f in target.rglob("*"):
        if not f.is_file() or f.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in f.parts):
            continue
        if f.suffix.lower() in suffixes or f.name.lower().endswith(suffixes):
            files.append(f)
    return files


def detect_dangerous_build_hooks(target: Path, corpus_dir: Path) -> list[Finding]:
    """Scan non-npm/pypi build hooks for suspicious install-time behavior."""
    findings: list[Finding] = []

    ecosystem = _detect_ecosystem(target)
    if ecosystem is None:
        return findings

    manifest_files, scan_suffixes = ECOSYSTEM_FILES[ecosystem]

    # Always scan declared manifest/hook files in the project root.
    scanned_paths: set[Path] = set()
    for name in manifest_files:
        if name.startswith("."):
            # Suffix-style markers: scan any root file that ends with the marker.
            for path in target.iterdir():
                if path.is_file() and path.name.lower().endswith(name):
                    scanned_paths.add(path)
                    findings.extend(_scan_build_file(path, ecosystem))
        else:
            path = target / name
            if path.is_file():
                scanned_paths.add(path)
                findings.extend(_scan_build_file(path, ecosystem))

    # Scan project source files with matching suffixes, but be selective.
    scanned_count = 0
    for path in _iter_target_files(target, scan_suffixes):
        if path.resolve() in scanned_paths:
            continue
        if scanned_count >= MAX_FILES_PER_PACKAGE:
            break
        if path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        findings.extend(_scan_build_file(path, ecosystem))
        scanned_count += 1

    return findings
