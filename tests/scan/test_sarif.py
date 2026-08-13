from __future__ import annotations

import json

import pytest

from picosentry import __version__
from picosentry.scan.formatters.sarif import (
    SarifFormatter,
    _finding_fingerprint,
    format_sarif,
)
from picosentry.scan.models import (
    Confidence,
    Finding,
    RuleExecution,
    ScanResult,
    ScanStats,
    Severity,
)


def _make_result(
    findings=None,
    rule_executions=None,
    engine_version="2.1.1",
    corpus_version="abc123",
):
    return ScanResult(
        target="/tmp/test",
        engine_version=engine_version,
        corpus_version=corpus_version,
        findings=findings or [],
        stats=ScanStats(packages_scanned=1, files_scanned=10, duration_ms=100),
        rule_executions=rule_executions or [],
    )


def _finding(
    rule_id="L2-POST-001",
    severity=Severity.HIGH,
    package="evil@1.0.0",
    file="evil/package.json",
    line=5,
    message="Post-install script",
    evidence="scripts.postinstall",
    remediation="Remove script",
):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.EXACT,
        package=package,
        file=file,
        line=line,
        message=message,
        evidence=evidence,
        remediation=remediation,
    )


class TestSarifSchemaAndVersion:
    def test_schema_uri(self):
        sarif = json.loads(format_sarif(_make_result()))
        assert (
            sarif["$schema"]
            == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        )

    def test_version(self):
        sarif = json.loads(format_sarif(_make_result()))
        assert sarif["version"] == "2.1.0"


class TestSarifToolDriver:
    def test_driver_name_is_picosentry(self):
        sarif = json.loads(format_sarif(_make_result()))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "PicoSentry"

    def test_driver_version(self):
        sarif = json.loads(format_sarif(_make_result()))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["version"] == "2.1.1"

    def test_driver_information_uri(self):
        sarif = json.loads(format_sarif(_make_result()))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["informationUri"] == "https://github.com/KirkForge/PicoSentry"


class TestSarifRuleDescriptors:
    def test_rules_have_id_name_description(self):
        result = _make_result(findings=[_finding()])
        sarif = json.loads(format_sarif(result))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        rule = rules[0]
        assert rule["id"] == "L2-POST-001"
        assert rule["name"] == "post_install"
        assert "shortDescription" in rule
        assert "text" in rule["shortDescription"]

    def test_rules_have_help_uri(self):
        result = _make_result(findings=[_finding()])
        sarif = json.loads(format_sarif(result))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" in rule
        assert "L2-POST-001" in rule["helpUri"]

    def test_unknown_rule_gets_fallback_descriptor(self):
        f = Finding(
            rule_id="L99-UNKNOWN-999",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            package="x@1",
            file="a.js",
            line=1,
            message="m",
            evidence="e",
            remediation="r",
        )
        result = _make_result(findings=[f])
        sarif = json.loads(format_sarif(result))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"] == "L99-UNKNOWN-999"
        assert rule["name"] == "l99-unknown-999"
        assert rule["shortDescription"]["text"] == "m"

    def test_rules_deduplicated(self):
        result = _make_result(findings=[_finding(), _finding()])
        sarif = json.loads(format_sarif(result))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1


class TestSarifResults:
    def test_result_has_rule_id(self):
        result = _make_result(findings=[_finding()])
        sarif = json.loads(format_sarif(result))
        entry = sarif["runs"][0]["results"][0]
        assert entry["ruleId"] == "L2-POST-001"

    def test_severity_mapping(self):
        cases = [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ]
        for sev, expected_level in cases:
            result = _make_result(findings=[_finding(severity=sev)])
            sarif = json.loads(format_sarif(result))
            actual = sarif["runs"][0]["results"][0]["level"]
            assert actual == expected_level, f"Severity {sev} should map to {expected_level}"

    def test_result_has_message(self):
        result = _make_result(findings=[_finding()])
        sarif = json.loads(format_sarif(result))
        entry = sarif["runs"][0]["results"][0]
        assert entry["message"]["text"] == "Post-install script"

    def test_result_has_location(self):
        result = _make_result(findings=[_finding(file="evil/package.json", line=5)])
        sarif = json.loads(format_sarif(result))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "evil/package.json"
        assert loc["region"]["startLine"] == 5

    def test_result_location_default_line(self):
        f = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil@1.0.0",
            file="evil/package.json",
            line=None,
            message="m",
            evidence="e",
            remediation="r",
        )
        result = _make_result(findings=[f])
        sarif = json.loads(format_sarif(result))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 1

    def test_result_has_fingerprints(self):
        result = _make_result(findings=[_finding()])
        sarif = json.loads(format_sarif(result))
        entry = sarif["runs"][0]["results"][0]
        assert "fingerprints" in entry
        assert "primaryLocationLineHash" in entry["fingerprints"]
        assert len(entry["fingerprints"]["primaryLocationLineHash"]) == 64

    def test_fingerprint_is_deterministic(self):
        f = _finding()
        assert _finding_fingerprint(f) == _finding_fingerprint(f)

    def test_result_has_properties(self):
        result = _make_result(findings=[_finding()])
        sarif = json.loads(format_sarif(result))
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["package"] == "evil@1.0.0"
        assert props["confidence"] == "EXACT"
        assert props["ecosystem"] == "npm"
        assert props["evidence"] == "scripts.postinstall"
        assert props["remediation"] == "Remove script"

    def test_result_with_references(self):
        f = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil@1.0.0",
            file="evil/package.json",
            line=5,
            message="m",
            evidence="e",
            remediation="r",
            references=["https://example.com/advisory"],
        )
        result = _make_result(findings=[f])
        sarif = json.loads(format_sarif(result))
        refs = sarif["runs"][0]["results"][0]["properties"]["references"]
        assert refs == ["https://example.com/advisory"]

    def test_results_sorted(self):
        findings = [
            _finding(rule_id="L2-ZZZ-001"),
            _finding(rule_id="L2-AAA-001"),
        ]
        result = _make_result(findings=findings)
        sarif = json.loads(format_sarif(result))
        rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
        assert rule_ids == sorted(rule_ids)

    def test_empty_findings(self):
        result = _make_result()
        sarif = json.loads(format_sarif(result))
        assert sarif["runs"][0]["results"] == []


class TestSarifInvocations:
    def test_invocation_successful(self):
        result = _make_result(rule_executions=[RuleExecution(rule_id="L2-POST-001", status="ok")])
        sarif = json.loads(format_sarif(result))
        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True

    def test_invocation_failed_rule(self):
        result = _make_result(rule_executions=[RuleExecution(rule_id="L2-POST-001", status="failed", error="boom")])
        sarif = json.loads(format_sarif(result))
        invocations = sarif["runs"][0]["invocations"]
        assert invocations[0]["executionSuccessful"] is False
        notifications = invocations[0]["toolExecutionNotifications"]
        assert len(notifications) == 1
        assert notifications[0]["level"] == "error"
        assert "boom" in notifications[0]["message"]["text"]

    def test_invocation_timeout_rule(self):
        result = _make_result(
            rule_executions=[
                RuleExecution(
                    rule_id="L2-OBFS-001",
                    status="timeout",
                    error="exceeded 5s timebox",
                )
            ]
        )
        sarif = json.loads(format_sarif(result))
        notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert len(notifications) == 1
        assert notifications[0]["level"] == "warning"

    def test_invocation_properties(self):
        result = _make_result(engine_version="2.0.18", corpus_version="abc123")
        sarif = json.loads(format_sarif(result))
        props = sarif["runs"][0]["invocations"][0]["properties"]
        assert props["engine_version"] == "2.0.18"
        assert props["corpus_version"] == "abc123"

    def test_no_notifications_when_all_ok(self):
        result = _make_result(rule_executions=[RuleExecution(rule_id="L2-POST-001", status="ok")])
        sarif = json.loads(format_sarif(result))
        inv = sarif["runs"][0]["invocations"][0]
        assert "toolExecutionNotifications" not in inv


_SARIF_210_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)


def _full_sarif_output():
    findings = [
        _finding(),
        _finding(
            rule_id="L2-OBFS-001",
            severity=Severity.CRITICAL,
            package="obfs@2.0.0",
            file="obfs/setup.py",
            line=10,
            message="Eval call",
        ),
    ]
    executions = [
        RuleExecution(rule_id="L2-POST-001", status="success"),
        RuleExecution(rule_id="L2-OBFS-001", status="success"),
    ]
    result = _make_result(findings=findings, rule_executions=executions)
    return json.loads(format_sarif(result))


def _validate_structural_completeness(sarif):
    assert sarif["$schema"] == _SARIF_210_SCHEMA_URI
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) >= 1
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "PicoSentry"
    assert driver["version"] == __version__
    for rule in driver.get("rules", []):
        assert "id" in rule
        assert "name" in rule
        assert "shortDescription" in rule
        assert "text" in rule["shortDescription"]
    for result_entry in run.get("results", []):
        assert "ruleId" in result_entry
        assert "level" in result_entry
        assert "message" in result_entry
        assert "text" in result_entry["message"]
        assert "locations" in result_entry
        loc = result_entry["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "uri" in loc["artifactLocation"]
        assert "region" in loc
        assert "startLine" in loc["region"]
        assert "fingerprints" in result_entry
        assert "primaryLocationLineHash" in result_entry["fingerprints"]
    invocations = run.get("invocations", [])
    assert len(invocations) >= 1
    assert "executionSuccessful" in invocations[0]


class TestSarifJsonSchemaValidation:
    def test_full_output_validates_against_sarif_210_schema(self):
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")
        import urllib.request

        sarif = _full_sarif_output()
        try:
            with urllib.request.urlopen(_SARIF_210_SCHEMA_URI, timeout=15) as resp:
                schema = json.loads(resp.read())
            jsonschema.validate(sarif, schema)
        except (urllib.error.URLError, TimeoutError):
            _validate_structural_completeness(sarif)

    def test_structural_completeness_empty_findings(self):
        sarif = json.loads(format_sarif(_make_result()))
        _validate_structural_completeness(sarif)

    def test_structural_completeness_with_findings(self):
        sarif = _full_sarif_output()
        _validate_structural_completeness(sarif)

    def test_driver_version_matches_picosentry_version(self):
        sarif = json.loads(format_sarif(_make_result()))
        assert sarif["runs"][0]["tool"]["driver"]["version"] == __version__

    def test_schema_uri_is_210(self):
        from picosentry.scan.formatters.sarif import _SARIF_SCHEMA

        assert _SARIF_SCHEMA == _SARIF_210_SCHEMA_URI

    def test_schema_local_validation(self):
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        sarif = _full_sarif_output()
        schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["$schema", "version", "runs"],
            "properties": {
                "$schema": {"type": "string"},
                "version": {"type": "string", "enum": ["2.1.0"]},
                "runs": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["tool", "results", "invocations"],
                        "properties": {
                            "tool": {
                                "type": "object",
                                "required": ["driver"],
                                "properties": {
                                    "driver": {
                                        "type": "object",
                                        "required": ["name", "version", "rules"],
                                        "properties": {
                                            "name": {"type": "string"},
                                            "version": {"type": "string"},
                                            "informationUri": {"type": "string"},
                                            "rules": {"type": "array"},
                                        },
                                    }
                                },
                            },
                            "results": {"type": "array"},
                            "invocations": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["executionSuccessful"],
                                    "properties": {
                                        "executionSuccessful": {"type": "boolean"},
                                        "toolExecutionNotifications": {"type": "array"},
                                        "properties": {"type": "object"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }
        jsonschema.validate(sarif, schema)


class TestSarifFormatterClass:
    def test_sarif_formatter_produces_valid_json(self):
        result = _make_result(findings=[_finding()])
        output = SarifFormatter(result).format()
        data = json.loads(output)
        assert "runs" in data

    def test_format_sarif_delegates_to_formatter(self):
        result = _make_result(findings=[_finding()])
        assert format_sarif(result) == SarifFormatter(result).format()
