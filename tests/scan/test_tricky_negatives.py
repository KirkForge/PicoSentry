"""
Tests for the tricky-negatives corpus (tests/scan/fixtures/validation/_tricky/).

This corpus is *not* part of the strict CI gate — those fixtures are
in ``positive/`` and ``negative/`` directories that the validation
harness walks. The ``_tricky/`` corpus lives outside the harness's
discovery path and exists for a different purpose: to document
**known detector limits** so users understand what each rule
explicitly does NOT catch.

Each fixture has a name like ``tricky_<ecosystem>_<pattern>`` and
asserts one of two outcomes:

  - "expected_fires": the named rule_id DOES fire. Documents a case
    where the rule matches a pattern a human would call borderline.
  - "expected_clean": zero findings. Documents a case where the rule
    is correctly silent on a non-malicious pattern that LOOKS like
    the rule's target.

These tests guard against the limits drifting without notice — if a
detector changes and starts/stops matching a tricky pattern, the
relevant test fails.
"""

from __future__ import annotations

from pathlib import Path

from picosentry.scan.engine import create_default_engine

TRICKY_ROOT = Path(__file__).parent / "fixtures" / "validation" / "_tricky"


def _scan(fixture_dir: str) -> list[dict]:
    """Scan a single _tricky fixture and return its findings as dicts."""
    target = TRICKY_ROOT / fixture_dir
    assert target.is_dir(), f"Missing tricky fixture: {target}"
    engine = create_default_engine()
    result = engine.scan(target)
    out: list[dict] = []
    for f in result.findings:
        sev = f.severity
        # Severity is an enum; str(enum) gives "Severity.MEDIUM". We want "MEDIUM".
        sev_name = sev.name if hasattr(sev, "name") else str(sev)
        out.append(
            {
                "rule_id": f.rule_id,
                "severity": sev_name,
                "package": f.package,
                "message": f.message,
            }
        )
    return out


def _rule_ids(findings: list[dict]) -> set[str]:
    return {f["rule_id"] for f in findings}


# ── "expected_fires" — these document rules that DO match the pattern ──


def test_tricky_pypi_exec_compile_obfs_001_fires() -> None:
    """L2-PYPI-OBFS-001 (exec/eval) matches ``exec(compile(...))``.

    The detector's EVAL_PATTERN matches the literal ``exec(`` token, so
    the common obfuscation pattern ``exec(compile(src, '<string>', 'exec'))``
    is caught. (Also triggers L2-PYPI-POST-001 for setup.py code
    execution, which we don't assert here.)
    """
    findings = _scan("tricky_pypi_exec_compile")
    assert "L2-PYPI-OBFS-001" in _rule_ids(findings), f"Expected L2-PYPI-OBFS-001 to fire, got: {findings}"


def test_tricky_typosquat_lowpop_typo_001_fires() -> None:
    """L2-TYPO-001 matches ``l0dash`` (edit dist 2 from ``lodash``).

    Lower-popularity squats with simple homoglyphs (o→0) and letter
    drops still match the detector when within edit-distance threshold.
    """
    findings = _scan("tricky_typosquat_lowpop")
    assert "L2-TYPO-001" in _rule_ids(findings), f"Expected L2-TYPO-001 to fire on l0dash, got: {findings}"


def test_tricky_npm_git_dep_safe_worm_001_fires_at_medium() -> None:
    """L2-WORM-001 fires at MEDIUM on a git-resolved dep with no install script.

    This is the "shady-but-not-malicious" case: a package that pulls
    directly from git (bypassing the npm registry's integrity check)
    but has no install script. The detector flags it as a worm
    *risk* (medium) rather than confirmed worm activity.
    """
    findings = _scan("tricky_npm_git_dep_safe")
    worm = [f for f in findings if f["rule_id"] == "L2-WORM-001"]
    assert worm, f"Expected L2-WORM-001 to fire, got: {findings}"
    assert worm[0]["severity"] == "MEDIUM", (
        f"Expected MEDIUM severity for git-resolved dep without install script, got: {worm[0]['severity']}"
    )


# ── "expected_clean" — these document rules that are correctly silent ──


def test_tricky_npm_reads_etc_hosts_clean() -> None:
    """A package that reads /etc/hosts for legitimate DNS resolution fires nothing.

    Documents that L2-CRED-001 (credential access) and L2-NETEX-001
    (network exfil) do not over-match on /etc/hosts reads, which are
    a normal part of DNS resolution libraries.
    """
    findings = _scan("tricky_npm_reads_etc_hosts")
    assert findings == [], f"Expected clean (no findings) for /etc/hosts reader, got: {findings}"


def test_tricky_pypi_hex_buffer_clean() -> None:
    """``bytes.fromhex(...)`` does NOT trigger L2-PYPI-OBFS-002 (hex-string).

    The hex-string pattern matches literal ``\\xNN`` escapes in source,
    not runtime ``bytes.fromhex()`` calls. A library that decodes hex
    at runtime is not flagged as obfuscation. (This documents a known
    limit: dynamic hex decoding evades the detector.)
    """
    findings = _scan("tricky_pypi_hex_buffer")
    assert findings == [], f"Expected clean (no findings) for bytes.fromhex, got: {findings}"


def test_tricky_npm_dual_license_clean() -> None:
    """A package with a permissive dual license (``(MIT OR Apache-2.0)``) fires nothing.

    Documents that L2-LICENSE-001 (UNLICENSED / SUSPICIOUS_LICENSE) does
    not over-match on SPDX expression operators — only literal
    ``UNLICENSED`` or unknown license strings are flagged.
    """
    findings = _scan("tricky_npm_dual_license")
    assert findings == [], f"Expected clean (no findings) for permissive dual license, got: {findings}"


def test_tricky_pypi_obfs_exec_namespace_bypass_clean() -> None:
    """``globals()['ex' + 'ec'](...)`` evades L2-PYPI-OBFS-001 (exec/eval).

    The detector's EVAL_PATTERN matches the literal ``exec(`` / ``eval(``
    token. Splitting the function name across a string concatenation
    (or using ``getattr(__builtins__, 'ev'+'al')``, ``globals()['ex'+'ec']``,
    etc.) is a real-world obfuscation pattern that defeats this regex.

    An AST-based detector that resolves the call target before matching
    would catch this. Until that lands, this fixture documents the
    known limit and the test guards against it disappearing silently.
    """
    findings = _scan("pypi_obfs_exec_namespace_bypass")
    assert findings == [], (
        f"Expected clean (no findings) for exec() bypass via globals() string lookup, got: {findings}"
    )
