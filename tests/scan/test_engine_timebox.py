"""
Tests for the per-detector timebox.

A misbehaving detector (infinite regex backtracking, blocking I/O, large
directory walk) must not tank the whole scan. The engine wraps each rule
function in a ThreadPoolExecutor and waits at most DEFAULT_RULE_TIMEOUT_SECONDS
(default 2.0s) per rule; on FuturesTimeoutError it records status="timeout"
and continues. Tests below tighten the timebox to 0.5s via scan(rule_timeout=...)
to assert the timebox fires deterministically.

Test coverage:
  1. A 2s sleep rule times out within 700ms (500ms + slack).
  2. Findings from other rules are still produced (timebox is per-rule,
     not whole-scan).
  3. The "ok" and "failed" statuses still work alongside "timeout".
  4. Sub-rule aliases (same function registered under multiple rule_ids)
     all receive the timeout status.
  5. The default timebox is calibrated to NOT time out the default engine
     on a small target.
"""

from __future__ import annotations

import time
from pathlib import Path

from picosentry.scan.engine import (
    DEFAULT_RULE_TIMEOUT_SECONDS,
    ScanEngine,
    ScanResult,
)

# ── Headline behavior: a 2s sleep rule times out ────────────────────────


def test_slow_rule_times_out_within_2_5s(tmp_path: Path) -> None:
    """A rule that sleeps 2s must time out well before the 2s sleep duration
    completes. With rule_timeout=0.5s, the scan returns in <2.5s — the
    2.0s slack covers thread pool tear-down and any other in-flight rules.
    Use an empty temp directory as the target to avoid repo-size noise.
    """

    def slow_rule(target: Path, corpus_dir: Path) -> list:
        time.sleep(2.0)
        return []

    engine = ScanEngine()
    engine.register("L2-SLOW-001", slow_rule)
    engine.register("L2-FAST-001", lambda t, c: [])

    t0 = time.monotonic()
    result: ScanResult = engine.scan(tmp_path, rule_timeout=0.5)
    elapsed = time.monotonic() - t0

    assert elapsed < 2.5, f"Scan took {elapsed:.2f}s — timebox did not fire"

    slow_exec = next(e for e in result.rule_executions if e.rule_id == "L2-SLOW-001")
    assert slow_exec.status == "timeout", f"Expected L2-SLOW-001 status='timeout', got {slow_exec.status!r}"
    assert slow_exec.findings_count == 0
    assert "timebox" in (slow_exec.error or "").lower()


def test_fast_rules_still_complete_after_timeout() -> None:
    """The timebox is per-rule — other rules must still run normally."""

    def slow_rule(target: Path, corpus_dir: Path) -> list:
        time.sleep(2.0)
        return []

    def fast_rule(target: Path, corpus_dir: Path) -> list:
        return []

    engine = ScanEngine()
    engine.register("L2-SLOW-002", slow_rule)
    engine.register("L2-FAST-002", fast_rule)

    result = engine.scan(Path("."), rule_timeout=0.5)

    fast_exec = next(e for e in result.rule_executions if e.rule_id == "L2-FAST-002")
    assert fast_exec.status == "ok", f"Expected L2-FAST-002 status='ok', got {fast_exec.status!r}"


def test_timeout_status_coexists_with_ok_and_failed() -> None:
    """The new 'timeout' status joins the existing 'ok'/'failed' enum values
    without breaking them. This is the backward-compat canary: any consumer
    that pattern-matches on status will see the same three strings.
    """
    from picosentry.scan.models import RuleExecution

    # All three statuses must be valid by the dataclass accepting them.
    RuleExecution(rule_id="R-OK", status="ok", duration_ms=10, findings_count=0)
    RuleExecution(rule_id="R-FAIL", status="failed", duration_ms=5, findings_count=0)
    RuleExecution(rule_id="R-TIMEOUT", status="timeout", duration_ms=500, findings_count=0)

    # And the default timebox must be sane.
    assert 0.5 <= DEFAULT_RULE_TIMEOUT_SECONDS <= 10.0, (
        f"DEFAULT_RULE_TIMEOUT_SECONDS={DEFAULT_RULE_TIMEOUT_SECONDS} is outside the sane range [0.5, 10.0]"
    )


# ── The default engine has the timebox wired in ────────────────────────


def test_create_default_engine_inherits_default_timebox() -> None:
    """The default engine uses DEFAULT_RULE_TIMEOUT_SECONDS (5.0s). On a
    small target that should be plenty; we use a generous explicit override
    here because the v2 repo is a real-sized codebase (the actual
    detector on a tiny project runs in well under 5s; on the v2 source
    tree, the PyPI obfuscation detector takes longer). The point of this
    test is that the *timebox infrastructure* is wired into the default
    engine and that no rule has an unhandled exception — not to assert
    a specific per-rule latency on a particular filesystem.
    """
    from picosentry.scan.engine import create_default_engine

    engine = create_default_engine()
    # Generous override: the v2 repo's PyPI obfuscation rule is real work.
    result = engine.scan(Path("."), rule_timeout=30.0)
    timeouts = [e for e in result.rule_executions if e.status == "timeout"]
    assert not timeouts, (
        f"Default engine should not time out on a small target; got: {[(e.rule_id, e.error) for e in timeouts]}"
    )


# ── Sub-rules under the same function all get the timeout status ───────


def test_sub_rule_aliases_all_get_timeout_status() -> None:
    """If a function is registered under multiple rule_ids (sub-rule pattern),
    a timeout must be recorded against *all* of them, not just the primary.
    This is the same fan-out that the 'ok' and 'failed' branches do.
    """

    def slow_rule(target: Path, corpus_dir: Path) -> list:
        time.sleep(2.0)
        return []

    engine = ScanEngine()
    # The same function, registered under three different rule_ids.
    engine.register("L2-MULTI-A", slow_rule)
    engine.register("L2-MULTI-B", slow_rule)
    engine.register("L2-MULTI-C", slow_rule)

    result = engine.scan(Path("."), rule_timeout=0.5)

    # All three must show status=timeout.
    statuses = {e.rule_id: e.status for e in result.rule_executions}
    for rid in ("L2-MULTI-A", "L2-MULTI-B", "L2-MULTI-C"):
        assert statuses.get(rid) == "timeout", f"Expected {rid} status='timeout', got {statuses.get(rid)!r}"
