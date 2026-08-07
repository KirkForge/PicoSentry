from __future__ import annotations

from unittest.mock import MagicMock, patch

from picosentry.scan.models import Finding
from picosentry._core.models import Severity, Confidence
from picosentry.firewall.scanner import FirewallScanner, FirewallVerdict, classify_path


class TestClassifyPath:
    def test_npm_package(self):
        result = classify_path("/express")
        assert result == ("npm", "express", "latest")

    def test_npm_package_version(self):
        result = classify_path("/express/4.18.0")
        assert result == ("npm", "express", "4.18.0")

    def test_npm_scoped_package(self):
        result = classify_path("/@types/node")
        assert result is not None
        assert result[0] == "npm"
        assert result[1] == "@types/node"

    def test_pypi_package(self):
        result = classify_path("/pypi/requests/json")
        assert result == ("pypi", "requests", "latest")

    def test_pypi_package_version(self):
        result = classify_path("/pypi/requests/2.31.0/json")
        assert result == ("pypi", "requests", "2.31.0")

    def test_unknown_path(self):
        assert classify_path("/favicon.ico") is None

    def test_npm_encoded_scope(self):
        result = classify_path("/@babel%2Fcore")
        assert result is not None
        assert result[0] == "npm"

    def test_npm_dotted_package(self):
        result = classify_path("/socket.io")
        assert result is not None
        assert result[0] == "npm"
        assert result[1] == "socket.io"


class TestFirewallScanner:
    def test_verdict_from_empty_findings(self):
        scanner = FirewallScanner()
        assert scanner.verdict_from_findings([]) == FirewallVerdict.ALLOW

    def test_verdict_block_on_critical(self):
        scanner = FirewallScanner(block_severities=["CRITICAL"])
        f = Finding(
            rule_id="TEST",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            package="evil",
            file="pkg.json",
            message="bad",
            evidence="test",
            remediation="remove",
        )
        assert scanner.verdict_from_findings([f]) == FirewallVerdict.BLOCK

    def test_verdict_quarantine_on_medium(self):
        scanner = FirewallScanner(block_severities=["CRITICAL"], quarantine_severities=["MEDIUM"])
        f = Finding(
            rule_id="TEST",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            package="meh",
            file="pkg.json",
            message="warn",
            evidence="test",
            remediation="review",
        )
        assert scanner.verdict_from_findings([f]) == FirewallVerdict.QUARANTINE

    def test_verdict_allow_on_low(self):
        scanner = FirewallScanner(block_severities=["CRITICAL", "HIGH"], quarantine_severities=["MEDIUM"])
        f = Finding(
            rule_id="TEST",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            package="ok",
            file="pkg.json",
            message="minor",
            evidence="test",
            remediation="ignore",
        )
        assert scanner.verdict_from_findings([f]) == FirewallVerdict.ALLOW

    def test_verdict_block_takes_priority_over_quarantine(self):
        scanner = FirewallScanner(block_severities=["CRITICAL"], quarantine_severities=["MEDIUM"])
        findings = [
            Finding(
                rule_id="T1",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                package="x",
                file="f",
                message="m",
                evidence="e",
                remediation="r",
            ),
            Finding(
                rule_id="T2",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                package="x",
                file="f",
                message="m",
                evidence="e",
                remediation="r",
            ),
        ]
        assert scanner.verdict_from_findings(findings) == FirewallVerdict.BLOCK

    def test_scan_metadata_caches_result(self):
        scanner = FirewallScanner(cache_ttl_seconds=60)
        metadata = {"name": "safe-pkg", "version": "1.0.0"}
        with patch.object(scanner, "_get_engine") as mock_engine:
            mock_result = MagicMock()
            mock_result.findings = []
            mock_engine.return_value.scan.return_value = mock_result
            v1, _f1 = scanner.scan_metadata("npm", "safe-pkg", "1.0.0", metadata)
            v2, _f2 = scanner.scan_metadata("npm", "safe-pkg", "1.0.0", metadata)
            assert v1 == FirewallVerdict.ALLOW
            assert v2 == FirewallVerdict.ALLOW
            assert mock_engine.return_value.scan.call_count == 1

    def test_scan_metadata_cache_preserves_findings(self):
        scanner = FirewallScanner(cache_ttl_seconds=60)
        metadata = {"name": "warn-pkg", "version": "1.0.0"}
        finding = Finding(
            rule_id="L2-OBFS-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            package="warn-pkg",
            file="pkg.json",
            message="obfuscated code",
            evidence="eval()",
            remediation="review",
        )
        with patch.object(scanner, "_get_engine") as mock_engine:
            mock_result = MagicMock()
            mock_result.findings = [finding]
            mock_engine.return_value.scan.return_value = mock_result
            _v1, f1 = scanner.scan_metadata("npm", "warn-pkg", "1.0.0", metadata)
            _v2, f2 = scanner.scan_metadata("npm", "warn-pkg", "1.0.0", metadata)
            assert len(f1) == 1
            assert len(f2) == 1
            assert f2[0].rule_id == "L2-OBFS-001"

    def test_scan_metadata_unknown_ecosystem_passes(self):
        scanner = FirewallScanner()
        v, _ = scanner.scan_metadata("cargo", "foo", "1.0.0", {})
        assert v == FirewallVerdict.ALLOW

    def test_scan_metadata_scan_exception_blocks(self):
        scanner = FirewallScanner()
        with patch.object(scanner, "_get_engine", side_effect=Exception("boom")):
            v, _ = scanner.scan_metadata("npm", "broken", "1.0.0", {"name": "broken"})
            assert v == FirewallVerdict.BLOCK
