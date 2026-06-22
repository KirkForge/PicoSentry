from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .pattern_scanner import PatternScanner, TokenPattern

__all__ = ["detect_obfuscation"]

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


MAX_FILE_BYTES = 512_000


MAX_FILES_PER_PACKAGE = 200


JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx"}


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


_REFERENCES = [
    "https://github.com/nodesource/node-js-sec-best-practices",
]


# Backward-compatible tuple constants.  These are kept because tests and external
# callers import them directly and expect index 1 to be the compiled regex.
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


# Public tuple list preserved for compatibility.
PATTERNS: list[tuple] = [
    EVAL_PATTERN,
    HEX_STRING_PATTERN,
    BASE64_EXEC_PATTERN,
    UNICODE_ESCAPE_PATTERN,
]


# Internal token-filter scanner.  Patterns that contain regex alternatives are
# split into deterministic sub-patterns so each one has a reliable set of
# required literal tokens.  This lets us skip the expensive regex on files that
# cannot possibly match.
_OBFS_SCANNER = PatternScanner(
    [
        # L2-OBFS-001 split by dynamic-code function.
        TokenPattern(
            rule_id="L2-OBFS-001",
            pattern=re.compile(r"\beval\s*\(", re.IGNORECASE),
            severity=Severity.CRITICAL,
            message="Dynamic code execution via {func}",
            remediation="Remove {func} calls. Use static imports or JSON.parse for data.",
            required_tokens=frozenset({"eval"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
        ),
        TokenPattern(
            rule_id="L2-OBFS-001",
            pattern=re.compile(r"\bFunction\s*\(", re.IGNORECASE),
            severity=Severity.CRITICAL,
            message="Dynamic code execution via {func}",
            remediation="Remove {func} calls. Use static imports or JSON.parse for data.",
            required_tokens=frozenset({"function"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
        ),
        # L2-OBFS-002 hex escapes.
        TokenPattern(
            rule_id="L2-OBFS-002",
            pattern=HEX_STRING_PATTERN[1],
            severity=Severity.HIGH,
            message="Hex-encoded string detected",
            remediation="Decode the hex string and replace with readable literal.",
            required_tokens=frozenset({r"\x"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
        ),
        # L2-OBFS-003 split into four deterministic source/function combinations.
        TokenPattern(
            rule_id="L2-OBFS-003",
            pattern=re.compile(r"\batob\s*\([^)]*\)[\s\S]*?\beval\s*\(", re.IGNORECASE),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by eval/Function execution",
            remediation="Never decode base64 and eval the result. Replace with static config.",
            required_tokens=frozenset({"atob", "eval"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
        ),
        TokenPattern(
            rule_id="L2-OBFS-003",
            pattern=re.compile(r"\batob\s*\([^)]*\)[\s\S]*?\bFunction\s*\(", re.IGNORECASE),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by eval/Function execution",
            remediation="Never decode base64 and eval the result. Replace with static config.",
            required_tokens=frozenset({"atob", "function"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
        ),
        TokenPattern(
            rule_id="L2-OBFS-003",
            pattern=re.compile(r"\bBuffer\.from\s*\([^)]*\)[\s\S]*?\beval\s*\(", re.IGNORECASE),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by eval/Function execution",
            remediation="Never decode base64 and eval the result. Replace with static config.",
            required_tokens=frozenset({"buffer.from", "eval"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
        ),
        TokenPattern(
            rule_id="L2-OBFS-003",
            pattern=re.compile(r"\bBuffer\.from\s*\([^)]*\)[\s\S]*?\bFunction\s*\(", re.IGNORECASE),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by eval/Function execution",
            remediation="Never decode base64 and eval the result. Replace with static config.",
            required_tokens=frozenset({"buffer.from", "function"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
        ),
        # L2-OBFS-004 unicode escapes.
        TokenPattern(
            rule_id="L2-OBFS-004",
            pattern=UNICODE_ESCAPE_PATTERN[1],
            severity=Severity.HIGH,
            message="Unicode-escaped string detected",
            remediation="Decode the unicode escape sequence and use readable literals.",
            required_tokens=frozenset({r"\u"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
        ),
    ]
)


def _package_label(file_path: Path) -> str:
    parts = file_path.parts
    if "node_modules" in parts:
        idx = parts.index("node_modules")
        if idx + 1 < len(parts):
            scoped = parts[idx + 1].startswith("@")
            return f"{parts[idx + 1]}/{parts[idx + 2]}" if scoped and idx + 2 < len(parts) else parts[idx + 1]
    return "unknown"


def _scan_file(file_path: Path) -> list[Finding]:
    return _OBFS_SCANNER.scan_file(
        file_path,
        _package_label(file_path),
        max_bytes=MAX_FILE_BYTES,
        skip_extensions=SKIP_EXTENSIONS,
        skip_dirs=SKIP_DIRS,
    )


def detect_obfuscation(target: Path) -> list[Finding]:
    findings: list[Finding] = []

    if target.is_dir():
        for ext in JS_EXTENSIONS:
            for f in target.glob(f"*{ext}"):
                findings.extend(_scan_file(f))

        nm = target / "node_modules"
        if nm.is_dir():
            for child in sorted(nm.iterdir()):
                if not child.is_dir() or child.name.startswith("."):
                    continue

                if child.name.startswith("@"):
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
