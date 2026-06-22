"""Unit tests for the shared literal-token pattern scanner."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

from picosentry.scan.models import Confidence, Severity
from picosentry.scan.rules.pattern_scanner import PatternScanner, TokenPattern


def _make_pattern(
    rule_id: str = "L2-TEST-001",
    pattern: str = r"\beval\s*\(",
    required_tokens: tuple[str, ...] = ("eval(",),
    message: str = "Dynamic code execution via {func}",
    remediation: str = "Remove eval calls.",
    severity: Severity = Severity.CRITICAL,
    confidence: Confidence = Confidence.HIGH,
) -> TokenPattern:
    return TokenPattern(
        rule_id=rule_id,
        pattern=re.compile(pattern, re.IGNORECASE),
        severity=severity,
        message=message,
        remediation=remediation,
        required_tokens=frozenset(required_tokens),
        confidence=confidence,
    )


def test_token_filter_skips_regex_when_token_missing() -> None:
    scanner = PatternScanner([_make_pattern()])
    findings = scanner.scan_text("this file is completely benign", "pkg@1.0.0", "file.js")
    assert findings == []


def test_token_filter_runs_regex_when_token_present() -> None:
    scanner = PatternScanner([_make_pattern()])
    findings = scanner.scan_text("eval('x')", "pkg@1.0.0", "file.js")
    assert len(findings) == 1
    assert findings[0].rule_id == "L2-TEST-001"
    assert findings[0].message == "Dynamic code execution via eval"


def test_multiple_required_tokens_all_must_be_present() -> None:
    pattern = _make_pattern(
        pattern=r"base64.*eval\s*\(",
        required_tokens=("base64", "eval("),
        message="Base64 + eval",
    )
    scanner = PatternScanner([pattern])

    assert scanner.scan_text("eval('x')", "pkg", "file.js") == []
    assert scanner.scan_text("base64 stuff", "pkg", "file.js") == []

    findings = scanner.scan_text("base64('abc') && eval('x')", "pkg", "file.js")
    assert len(findings) == 1


def test_empty_required_tokens_always_runs_regex() -> None:
    pattern = TokenPattern(
        rule_id="L2-TEST-002",
        pattern=re.compile(r"\bmagic\b"),
        severity=Severity.MEDIUM,
        message="Magic word",
        remediation="Remove magic.",
        required_tokens=frozenset(),
    )
    scanner = PatternScanner([pattern])
    assert len(scanner.scan_text("no special word here", "pkg", "file.js")) == 0
    assert len(scanner.scan_text("magic", "pkg", "file.js")) == 1


def test_line_number_and_evidence() -> None:
    pattern = _make_pattern(pattern=r"\beval\s*\([^)]+\)")
    scanner = PatternScanner([pattern])
    text = "line1\nline2\neval('x')\nline4"
    findings = scanner.scan_text(text, "pkg@1.0.0", "file.js")
    assert len(findings) == 1
    assert findings[0].line == 3
    assert findings[0].evidence == "eval('x')"


def test_evidence_truncated_to_120() -> None:
    pattern = _make_pattern(pattern=r"\beval\s*\(.*\)")
    scanner = PatternScanner([pattern])
    long_arg = "x" * 200
    text = f"eval({long_arg})"
    findings = scanner.scan_text(text, "pkg", "file.js")
    assert len(findings[0].evidence) == 120


def test_message_without_func_template() -> None:
    pattern = _make_pattern(
        pattern=r"\bfoo\b",
        required_tokens=("foo",),
        message="Plain message",
    )
    scanner = PatternScanner([pattern])
    findings = scanner.scan_text("foo", "pkg", "file.js")
    assert findings[0].message == "Plain message"


def test_scan_file_skips_extensions() -> None:
    scanner = PatternScanner([_make_pattern()])
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "image.png"
        f.write_text("eval('x')")
        assert scanner.scan_file(f, "pkg", skip_extensions={".png"}) == []


def test_scan_file_skips_large_files() -> None:
    scanner = PatternScanner([_make_pattern()])
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "big.js"
        f.write_text("eval('x')\n" + "/* padding */\n" * 50_000)
        assert scanner.scan_file(f, "pkg", max_bytes=512_000) == []


def test_scan_file_skips_symlinks() -> None:
    scanner = PatternScanner([_make_pattern()])
    with tempfile.TemporaryDirectory() as tmp:
        real = Path(tmp) / "real.js"
        real.write_text("eval('x')")
        link = Path(tmp) / "link.js"
        link.symlink_to(real)
        assert scanner.scan_file(link, "pkg") == []


def test_scan_file_skips_dirs() -> None:
    scanner = PatternScanner([_make_pattern()])
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp) / "dist"
        dist.mkdir()
        f = dist / "evil.js"
        f.write_text("eval('x')")
        assert scanner.scan_file(f, "pkg", skip_dirs={"dist"}) == []


def test_scan_file_returns_findings_when_filter_passes() -> None:
    scanner = PatternScanner([_make_pattern()])
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "evil.js"
        f.write_text("// benign\neval('x')")
        findings = scanner.scan_file(f, "evil@1.0.0")
        assert len(findings) == 1
        assert findings[0].file == str(f)


def test_scan_files_respects_max_files() -> None:
    scanner = PatternScanner([_make_pattern()])
    with tempfile.TemporaryDirectory() as tmp:
        files = []
        for i in range(5):
            f = Path(tmp) / f"evil{i}.js"
            f.write_text("eval('x')")
            files.append(f)
        findings = scanner.scan_files(files, "pkg", max_files=2)
        assert len(findings) == 2


def test_reuse_present_tokens_across_scans() -> None:
    pattern = _make_pattern()
    scanner = PatternScanner([pattern])
    text = "eval('x')"
    tokens = scanner._present_tokens(text)
    assert "eval(" in tokens
    findings1 = scanner.scan_text(text, "pkg", "file1.js", present_tokens=tokens)
    findings2 = scanner.scan_text(text, "pkg", "file2.js", present_tokens=tokens)
    assert len(findings1) == 1
    assert len(findings2) == 1


def test_scanner_is_immutable() -> None:
    scanner = PatternScanner([_make_pattern()])
    # Frozen dataclass should not allow mutation.
    with pytest.raises(AttributeError):
        scanner.patterns = []  # type: ignore[misc]


def test_multiple_patterns_share_token_presence_map() -> None:
    p1 = _make_pattern(rule_id="R1", pattern=r"\beval\s*\(", required_tokens=("eval(",))
    p2 = _make_pattern(rule_id="R2", pattern=r"\bFunction\s*\(", required_tokens=("function(",))
    scanner = PatternScanner([p1, p2])
    findings = scanner.scan_text("eval('x')", "pkg", "file.js")
    assert [f.rule_id for f in findings] == ["R1"]
