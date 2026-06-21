from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .pattern_scanner import PatternScanner, TokenPattern
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


_REFERENCES = [
    "https://docs.python.org/3/library/functions.html#exec",
    "https://peps.python.org/pep-0668/",
]


_EVAL_PATTERN = re.compile(
    r"\b(?:exec|eval)\s*\(",
    re.IGNORECASE,
)

_BASE64_DECODE_PATTERN = re.compile(
    r"""\b(?:base64\.b64decode|base64\.decodestring|binascii\.unhexlify)\s*\([^)]*\)""",
    re.IGNORECASE,
)

_HEX_STRING_PATTERN = re.compile(
    r"""(?:["'])(?:\\x[0-9a-fA-F]{2}){4,}(?:["'])""",
)

_UNICODE_OBFUSCATION_PATTERN = re.compile(
    r"\b(?:chr\(|ord\()\s*\d{2,}\s*\)\s*[+]\s*(?:chr\(|ord\()",
)

_COMPRESSED_PAYLOAD_PATTERN = re.compile(
    r"""__(?:import__|import)\(['"]zlib['"]\)""",
)

_MARSHAL_LOAD_PATTERN = re.compile(
    r"\bmarshal\.(?:loads|load)\s*\(",
)

_BASE64_EXEC_PATTERN = re.compile(
    r"(?:base64|b64decode|unhexlify)\s*\([^)]*\)[\s\S]{0,200}?"
    r"(?:exec|eval)\s*\(",
    re.IGNORECASE,
)


# Internal token-filter scanner.  Patterns with regex alternatives are split
# into deterministic sub-patterns so each one has a reliable set of required
# literal tokens.
_PYPI_OBFS_SCANNER = PatternScanner(
    [
        # L2-PYPI-OBFS-001 split by dynamic-code function.
        TokenPattern(
            rule_id="L2-PYPI-OBFS-001",
            pattern=re.compile(r"\bexec\s*\(", re.IGNORECASE),
            severity=Severity.CRITICAL,
            message="Dynamic code execution via {func}",
            remediation="Remove exec/eval calls. Use static imports instead.",
            required_tokens=frozenset({"exec"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        TokenPattern(
            rule_id="L2-PYPI-OBFS-001",
            pattern=re.compile(r"\beval\s*\(", re.IGNORECASE),
            severity=Severity.CRITICAL,
            message="Dynamic code execution via {func}",
            remediation="Remove exec/eval calls. Use static imports instead.",
            required_tokens=frozenset({"eval"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        # L2-PYPI-OBFS-002 split by base64 decode function.
        TokenPattern(
            rule_id="L2-PYPI-OBFS-002",
            pattern=re.compile(r"\bbase64\.b64decode\s*\([^)]*\)", re.IGNORECASE),
            severity=Severity.HIGH,
            message="Base64-decoded string detected",
            remediation="Remove base64-encoded payloads from source code.",
            required_tokens=frozenset({"base64.b64decode"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        TokenPattern(
            rule_id="L2-PYPI-OBFS-002",
            pattern=re.compile(r"\bbase64\.decodestring\s*\([^)]*\)", re.IGNORECASE),
            severity=Severity.HIGH,
            message="Base64-decoded string detected",
            remediation="Remove base64-encoded payloads from source code.",
            required_tokens=frozenset({"base64.decodestring"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        TokenPattern(
            rule_id="L2-PYPI-OBFS-002",
            pattern=re.compile(r"\bbinascii\.unhexlify\s*\([^)]*\)", re.IGNORECASE),
            severity=Severity.HIGH,
            message="Base64-decoded string detected",
            remediation="Remove base64-encoded payloads from source code.",
            required_tokens=frozenset({"binascii.unhexlify"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        # L2-PYPI-OBFS-003 hex escapes.
        TokenPattern(
            rule_id="L2-PYPI-OBFS-003",
            pattern=_HEX_STRING_PATTERN,
            severity=Severity.HIGH,
            message="Hex-encoded string detected",
            remediation="Decode the hex string and replace with readable literal.",
            required_tokens=frozenset({r"\x"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        # L2-PYPI-OBFS-004 split by chr/ord.
        TokenPattern(
            rule_id="L2-PYPI-OBFS-004",
            pattern=re.compile(r"\bchr\(\s*\d{2,}\s*\)\s*[+]\s*(?:chr\(|ord\()", re.IGNORECASE),
            severity=Severity.HIGH,
            message="Unicode character arithmetic obfuscation detected",
            remediation="Replace chr()/ord() arithmetic with readable string literals.",
            required_tokens=frozenset({"chr(", "+"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        TokenPattern(
            rule_id="L2-PYPI-OBFS-004",
            pattern=re.compile(r"\bord\(\s*\d{2,}\s*\)\s*[+]\s*(?:chr\(|ord\()", re.IGNORECASE),
            severity=Severity.HIGH,
            message="Unicode character arithmetic obfuscation detected",
            remediation="Replace chr()/ord() arithmetic with readable string literals.",
            required_tokens=frozenset({"ord(", "+"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        # L2-PYPI-OBFS-005 compressed payload.
        TokenPattern(
            rule_id="L2-PYPI-OBFS-005",
            pattern=_COMPRESSED_PAYLOAD_PATTERN,
            severity=Severity.CRITICAL,
            message="Compressed (zlib) payload imported for execution",
            remediation="Remove zlib-compressed payloads from source code.",
            required_tokens=frozenset({"zlib"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        # L2-PYPI-OBFS-006 marshal load.
        TokenPattern(
            rule_id="L2-PYPI-OBFS-006",
            pattern=_MARSHAL_LOAD_PATTERN,
            severity=Severity.CRITICAL,
            message="Marshal deserialization detected (arbitrary code execution)",
            remediation="Replace marshal.loads() with safe deserialization.",
            required_tokens=frozenset({"marshal."}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        # L2-PYPI-OBFS-007 split by source and target function.
        TokenPattern(
            rule_id="L2-PYPI-OBFS-007",
            pattern=re.compile(
                r"\bbase64\s*\([^)]*\)[\s\S]{0,200}?\bexec\s*\(",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by exec/eval",
            remediation="Never decode base64 and exec the result. Replace with static config.",
            required_tokens=frozenset({"base64", "exec"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        TokenPattern(
            rule_id="L2-PYPI-OBFS-007",
            pattern=re.compile(
                r"\bbase64\s*\([^)]*\)[\s\S]{0,200}?\beval\s*\(",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by exec/eval",
            remediation="Never decode base64 and exec the result. Replace with static config.",
            required_tokens=frozenset({"base64", "eval"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        TokenPattern(
            rule_id="L2-PYPI-OBFS-007",
            pattern=re.compile(
                r"\bb64decode\s*\([^)]*\)[\s\S]{0,200}?\bexec\s*\(",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by exec/eval",
            remediation="Never decode base64 and exec the result. Replace with static config.",
            required_tokens=frozenset({"b64decode", "exec"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        TokenPattern(
            rule_id="L2-PYPI-OBFS-007",
            pattern=re.compile(
                r"\bb64decode\s*\([^)]*\)[\s\S]{0,200}?\beval\s*\(",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by exec/eval",
            remediation="Never decode base64 and exec the result. Replace with static config.",
            required_tokens=frozenset({"b64decode", "eval"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        TokenPattern(
            rule_id="L2-PYPI-OBFS-007",
            pattern=re.compile(
                r"\bunhexlify\s*\([^)]*\)[\s\S]{0,200}?\bexec\s*\(",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by exec/eval",
            remediation="Never decode base64 and exec the result. Replace with static config.",
            required_tokens=frozenset({"unhexlify", "exec"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
        TokenPattern(
            rule_id="L2-PYPI-OBFS-007",
            pattern=re.compile(
                r"\bunhexlify\s*\([^)]*\)[\s\S]{0,200}?\beval\s*\(",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            message="Base64 decode followed by exec/eval",
            remediation="Never decode base64 and exec the result. Replace with static config.",
            required_tokens=frozenset({"unhexlify", "eval"}),
            confidence=Confidence.HIGH,
            references=_REFERENCES,
            ecosystem="pypi",
        ),
    ]
)


def _package_label(file_path: Path) -> str:
    parts = file_path.parts
    py_markers = ("site-packages", ".venv", "venv")
    for marker in py_markers:
        if marker in parts:
            idx = parts.index(marker)

            sp_idx = parts.index("site-packages") if "site-packages" in parts else -1
            if sp_idx >= 0 and sp_idx + 1 < len(parts):
                return parts[sp_idx + 1]

            if idx + 1 < len(parts) and not parts[idx + 1].startswith("."):
                return parts[idx + 1]

    return "unknown"


def _scan_python_file(file_path: Path) -> list[Finding]:
    return _PYPI_OBFS_SCANNER.scan_file(
        file_path,
        _package_label(file_path),
        max_bytes=MAX_FILE_BYTES,
        skip_extensions=SKIP_EXTENSIONS,
        skip_dirs=SKIP_DIRS,
    )


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
