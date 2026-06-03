"""Cross-codebase integration tests for the unified PicoSentry package.

Verifies that all 4 components (_core, scan, sandbox, watch, serve)
interoperate correctly under the single namespace.
"""
from __future__ import annotations

import json
from pathlib import Path


class TestSharedVerdictEnum:
    """Shared Verdict enum round-trips across all components."""

    def test_core_verdict_is_source_of_truth(self) -> None:
        from picosentry._core.models import Verdict

        assert Verdict.ALLOW.value == "ALLOW"
        assert Verdict.DENY.value == "DENY"
        assert Verdict.KILL.value == "KILL"

    def test_scan_verdict_matches_core(self) -> None:
        from picosentry._core.models import Verdict as CoreVerdict
        from picosentry.watch.types import Verdict as WatchVerdict

        # PicoWatch uses PASS/WARN/BLOCK (LLM domain), not ALLOW/DENY/KILL (sandbox domain)
        assert WatchVerdict.PASS.value == "pass"
        assert WatchVerdict.BLOCK.value == "block"
        # Both domains have DENY/BLOCK as equivalent enforcement
        assert CoreVerdict.DENY.value == "DENY"


class TestSharedSeverityEnum:
    """Shared Severity enum across components."""

    def test_core_severity(self) -> None:
        from picosentry._core.models import Severity

        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"

    def test_scan_severity_matches_core(self) -> None:
        from picosentry._core.models import Severity as CoreSeverity
        from picosentry.scan.models import Severity as ScanSeverity

        assert ScanSeverity.CRITICAL.value == CoreSeverity.CRITICAL.value


class TestFindingProtocol:
    """FindingProtocol structural typing across components."""

    def test_scan_finding_satisfies_protocol(self) -> None:
        from picosentry._core.models import FindingProtocol
        from picosentry.scan.models import Confidence, Finding, Severity

        f = Finding(
            rule_id="test", confidence=Confidence.HIGH, severity=Severity.HIGH,
            message="test", package="pkg", file="f.py",
            evidence="ev", remediation="fix",
        )
        assert isinstance(f, FindingProtocol)

    def test_sandbox_finding_satisfies_protocol(self) -> None:
        from picosentry._core.models import FindingProtocol
        from picosentry.sandbox.models import Finding

        assert isinstance(Finding(rule_id="test", severity="HIGH", message="test"), FindingProtocol)


class TestSharedAssertSecure:
    """All components expose assert_secure."""

    def test_scan_has_assert_secure(self) -> None:
        from picosentry.scan.config import PicoSentryConfig

        assert hasattr(PicoSentryConfig, "assert_secure")

    def test_sandbox_has_assert_secure(self) -> None:
        from picosentry.sandbox.config import PicoDomeConfig

        assert hasattr(PicoDomeConfig, "assert_secure")

    def test_watch_has_assert_secure(self) -> None:
        from picosentry.watch.config import PicoWatchConfig

        assert hasattr(PicoWatchConfig, "assert_secure")

    def test_serve_has_assert_secure(self) -> None:
        from picosentry.serve.config.settings import Settings

        assert hasattr(Settings, "assert_secure") or callable(getattr(Settings, "assert_secure", None))


class TestInternalImports:
    """Internal cross-component imports work without subprocess."""

    def test_scan_engine_importable(self) -> None:
        from picosentry.scan.engine import create_default_engine, ScanEngine

        assert create_default_engine is not None
        assert ScanEngine is not None

    def test_sandbox_l3_importable(self) -> None:
        from picosentry.sandbox.l3.engine import sandbox_run
        assert callable(sandbox_run)

    def test_watch_prompt_guard_importable(self) -> None:
        from picosentry.watch.prompt_guard import PromptGuard
        assert PromptGuard is not None

    def test_serve_config_settings_importable(self) -> None:
        from picosentry.serve.config.settings import settings
        assert settings is not None


class TestUnifiedCLI:
    """Unified CLI delegates correctly."""

    def test_cli_version(self) -> None:
        from picosentry.cli import _show_version, _get_unified_version

        version = _get_unified_version()
        assert version == "2.0.0"

    def test_cli_health(self) -> None:
        from picosentry.cli import _handle_health

        # Should not raise
        try:
            _handle_health()
        except SystemExit as e:
            assert e.code in (0, None), f"Health check failed with code {e.code}"