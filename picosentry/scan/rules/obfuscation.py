"""
L2-OBFS-001 through 004: Obfuscated payload detection.

Catches eval(), new Function(), hex strings, base64 exec, and unicode escapes
that hide malicious intent in JavaScript/TypeScript packages.

Pure function: (target_path, corpus_dir) → List[Finding]
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Finding, Severity

__all__ = ["detect_obfuscation"]
# Binary extensions to skip — no point regexing images or compiled files.
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

# Maximum file size to scan (500 KB). Larger files are skipped.
MAX_FILE_BYTES = 512_000

# Max files to scan per package in node_modules (prevents O(n) rglob explosion)
MAX_FILES_PER_PACKAGE = 200

# JS/TS extensions to scan
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx"}

# Directories to skip during node_modules traversal
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

# ---- Rule patterns ----

EVAL_PATTERN: tuple = (
    "L2-OBFS-001",
    re.compile(r"\b(?:eval|Function)\s*\(", re.IGNORECASE),
    Severity.CRITICAL,
    "Dynamic code execution via {func}",
    "Remove {func} calls. Use static imports or JSON.parse for data.",
)

HEX_STRING_PATTERN: tuple = (
    "L2-OBFS-002",
    re.compile(r"""(?:["'])(\\x[0-9a-fA-F]{2}){4,}(?:["'])"""),
    Severity.HIGH,
    "Hex-encoded string detected",
    "Decode the hex string and replace with readable literal.",
)

BASE64_EXEC_PATTERN: tuple = (
    "L2-OBFS-003",
    re.compile(
        r"\b(?:atob|Buffer\.from)\s*\([^)]*\)[\s\S]*?"
        r"\b(?:eval|Function)\s*\(",
        re.IGNORECASE,
    ),
    Severity.CRITICAL,
    "Base64 decode followed by eval/Function execution",
    "Never decode base64 and eval the result. Replace with static config.",
)

UNICODE_ESCAPE_PATTERN: tuple = (
    "L2-OBFS-004",
    re.compile(r"""(?:["'])(\\u[0-9a-fA-F]{4}){4,}(?:["'])"""),
    Severity.HIGH,
    "Unicode-escaped string detected",
    "Decode the unicode escape sequence and use readable literals.",
)

PATTERNS: list[tuple] = [
    EVAL_PATTERN,
    HEX_STRING_PATTERN,
    BASE64_EXEC_PATTERN,
    UNICODE_ESCAPE_PATTERN,
]


def _scan_file(file_path: Path) -> list[Finding]:
    """Scan a single file for obfuscation patterns."""
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

    # Derive package name from path
    parts = file_path.parts
    pkg_label = "unknown"
    if "node_modules" in parts:
        idx = parts.index("node_modules")
        if idx + 1 < len(parts):
            scoped = parts[idx + 1].startswith("@")
            pkg_label = f"{parts[idx + 1]}/{parts[idx + 2]}" if scoped and idx + 2 < len(parts) else parts[idx + 1]

    for rule_id, pattern, severity, msg_tmpl, remediation in PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            matched_text = match.group(0)[:120]

            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(file_path),
                    line=line_num,
                    message=msg_tmpl.format(func=matched_text.split("(")[0]) if "{func}" in msg_tmpl else msg_tmpl,
                    evidence=matched_text,
                    remediation=remediation,
                    references=[
                        "https://github.com/nodesource/node-js-sec-best-practices",
                    ],
                )
            )

    return findings


def detect_obfuscation(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect obfuscated payloads in JS/TS files.
    No network calls. Pure filesystem scan.
    """
    findings: list[Finding] = []

    # Root source files
    if target.is_dir():
        for ext in JS_EXTENSIONS:
            for f in target.glob(f"*{ext}"):
                findings.extend(_scan_file(f))

        # node_modules — scan per-package with file budget and skip-dir filtering
        nm = target / "node_modules"
        if nm.is_dir():
            for child in sorted(nm.iterdir()):
                if not child.is_dir() or child.name.startswith("."):
                    continue

                # Each top-level directory (scoped or unscoped) gets its own budget
                if child.name.startswith("@"):
                    # Scoped package directory: @scope/
                    for scoped_child in sorted(child.iterdir()):
                        if not scoped_child.is_dir():
                            continue
                        file_count = 0
                        for f in scoped_child.rglob("*"):
                            if f.is_symlink():
                                continue
                            if not f.is_file():
                                continue
                            if f.suffix not in JS_EXTENSIONS:
                                continue
                            if any(part in SKIP_DIRS for part in f.parts):
                                continue
                            if file_count >= MAX_FILES_PER_PACKAGE:
                                break
                            findings.extend(_scan_file(f))
                            file_count += 1
                else:
                    # Unscoped package directory
                    file_count = 0
                    for f in child.rglob("*"):
                        if f.is_symlink():
                            continue
                        if not f.is_file():
                            continue
                        if f.suffix not in JS_EXTENSIONS:
                            continue
                        if any(part in SKIP_DIRS for part in f.parts):
                            continue
                        if file_count >= MAX_FILES_PER_PACKAGE:
                            break
                        findings.extend(_scan_file(f))
                        file_count += 1
    elif target.is_file() and target.suffix in JS_EXTENSIONS:
        findings.extend(_scan_file(target))

    return findings
