from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .pypi_utils import detect_pypi_project

__all__ = ["detect_pypi_obfuscation"]


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
        ".pyc",
        ".pyo",
        ".pyd",
        ".so",
        ".dll",
        ".dylib",
    }
)


MAX_FILE_BYTES = 512_000


MAX_FILES_PER_PACKAGE = 200


PY_EXTENSIONS = {".py"}


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
        "*.egg-info",
        "*.dist-info",
        "node_modules",
    }
)


EVAL_PATTERN = re.compile(
    r"\b(?:exec|eval)\s*\(",
    re.IGNORECASE,
)

BASE64_DECODE_PATTERN = re.compile(
    r"""\b(?:base64\.b64decode|base64\.decodestring|binascii\.unhexlify)\s*\([^)]*\)""",
    re.IGNORECASE,
)

HEX_STRING_PATTERN = re.compile(
    r"""(?:["'])(?:\\x[0-9a-fA-F]{2}){4,}(?:["'])""",
)

UNICODE_OBFUSCATION_PATTERN = re.compile(
    r"\b(?:chr\(|ord\()\s*\d{2,}\s*\)\s*[+]\s*(?:chr\(|ord\()",
)

COMPRESSED_PAYLOAD_PATTERN = re.compile(
    r"""__(?:import__|import)\(['"]zlib['"]\)""",
)

MARSHAL_LOAD_PATTERN = re.compile(
    r"\bmarshal\.(?:loads|load)\s*\(",
)

BASE64_EXEC_PATTERN = re.compile(
    r"(?:base64|b64decode|unhexlify)\s*\([^)]*\)[\s\S]{0,200}?"
    r"(?:exec|eval)\s*\(",
    re.IGNORECASE,
)


def _scan_python_file(file_path: Path) -> list[Finding]:
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

    parts = file_path.parts
    pkg_label = "unknown"
    py_markers = ("site-packages", ".venv", "venv")
    for marker in py_markers:
        if marker in parts:
            idx = parts.index(marker)

            sp_idx = parts.index("site-packages") if "site-packages" in parts else -1
            if sp_idx >= 0 and sp_idx + 1 < len(parts):
                pkg_label = parts[sp_idx + 1]
                break
            if idx + 1 < len(parts) and not parts[idx + 1].startswith("."):
                pkg_label = parts[idx + 1]
                break

    patterns: list[tuple[str, re.Pattern, Severity, str, str]] = [
        (
            "L2-PYPI-OBFS-001",
            EVAL_PATTERN,
            Severity.CRITICAL,
            "Dynamic code execution via {func}",
            "Remove exec/eval calls. Use static imports instead.",
        ),
        (
            "L2-PYPI-OBFS-002",
            BASE64_DECODE_PATTERN,
            Severity.HIGH,
            "Base64-decoded string detected",
            "Remove base64-encoded payloads from source code.",
        ),
        (
            "L2-PYPI-OBFS-003",
            HEX_STRING_PATTERN,
            Severity.HIGH,
            "Hex-encoded string detected",
            "Decode the hex string and replace with readable literal.",
        ),
        (
            "L2-PYPI-OBFS-004",
            UNICODE_OBFUSCATION_PATTERN,
            Severity.HIGH,
            "Unicode character arithmetic obfuscation detected",
            "Replace chr()/ord() arithmetic with readable string literals.",
        ),
        (
            "L2-PYPI-OBFS-005",
            COMPRESSED_PAYLOAD_PATTERN,
            Severity.CRITICAL,
            "Compressed (zlib) payload imported for execution",
            "Remove zlib-compressed payloads from source code.",
        ),
        (
            "L2-PYPI-OBFS-006",
            MARSHAL_LOAD_PATTERN,
            Severity.CRITICAL,
            "Marshal deserialization detected (arbitrary code execution)",
            "Replace marshal.loads() with safe deserialization.",
        ),
        (
            "L2-PYPI-OBFS-007",
            BASE64_EXEC_PATTERN,
            Severity.CRITICAL,
            "Base64 decode followed by exec/eval",
            "Never decode base64 and exec the result. Replace with static config.",
        ),
    ]

    for rule_id, pattern, severity, msg_tmpl, remediation_text in patterns:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            matched_text = match.group(0)[:120]

            func_name = matched_text.split("(")[0] if "(" in matched_text else pattern.pattern[:20]
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(file_path),
                    line=line_num,
                    message=msg_tmpl.format(func=func_name) if "{func}" in msg_tmpl else msg_tmpl,
                    evidence=matched_text,
                    remediation=remediation_text,
                    references=[
                        "https://docs.python.org/3/library/functions.html#exec",
                        "https://peps.python.org/pep-0668/",
                    ],
                    ecosystem="pypi",
                )
            )

    return findings


def detect_pypi_obfuscation(target: Path) -> list[Finding]:
    findings: list[Finding] = []

    if not detect_pypi_project(target):
        return findings

    if target.is_dir():
        for ext in PY_EXTENSIONS:
            for f in target.glob(f"*{ext}"):
                if not f.is_file() or f.is_symlink():
                    continue
                findings.extend(_scan_python_file(f))

        for site_dir in _find_site_dirs(target):
            if site_dir.is_dir():
                for child in sorted(site_dir.iterdir()):
                    if not child.is_dir() or child.name.startswith("."):
                        continue
                    file_count = 0
                    for f in child.rglob("*.py"):
                        if f.is_symlink():
                            continue
                        if not f.is_file():
                            continue
                        if any(part in SKIP_DIRS for part in f.parts):
                            continue
                        if file_count >= MAX_FILES_PER_PACKAGE:
                            break
                        findings.extend(_scan_python_file(f))
                        file_count += 1

    elif target.is_file() and target.suffix in PY_EXTENSIONS:
        findings.extend(_scan_python_file(target))

    return findings


def _find_site_dirs(target: Path) -> list[Path]:
    dirs: list[Path] = []
    patterns = [
        ".venv/lib/python*/site-packages",
        "venv/lib/python*/site-packages",
    ]
    for pattern in patterns:
        for p in target.glob(pattern):
            if p.is_dir() and p not in dirs:
                dirs.append(p)
    return dirs
