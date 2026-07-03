"""Tests for picodome.config — YAML loader, env overrides, CLI merge."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from picosentry.sandbox.config import (
    PicoDomeConfig,
    _find_config,
    _validate_config_keys,
    apply_env_overrides,
    load_config,
)

# ─── PicoDomeConfig defaults ────────────────────────────────────────


class TestConfigDefaults:
    def test_default_format(self):
        cfg = PicoDomeConfig()
        assert cfg.format == "table"

    def test_default_no_color(self):
        cfg = PicoDomeConfig()
        assert cfg.no_color is False

    def test_default_exit_code(self):
        cfg = PicoDomeConfig()
        assert cfg.exit_code is False

    def test_default_fail_on(self):
        cfg = PicoDomeConfig()
        assert cfg.fail_on is None

    def test_default_timeout(self):
        cfg = PicoDomeConfig()
        assert cfg.timeout == 30.0

    def test_default_token_budget(self):
        cfg = PicoDomeConfig()
        assert cfg.token_budget == 4096

    def test_default_deterministic_output(self):
        cfg = PicoDomeConfig()
        assert cfg.deterministic_output is False

    def test_default_log_format(self):
        cfg = PicoDomeConfig()
        assert cfg.log_format == "text"


# ─── _find_config ──────────────────────────────────────────────────


class TestFindConfig:
    def test_finds_yml(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("format: json\n")
        result = _find_config(tmp_path)
        assert result is not None
        assert result.name == ".picodome.yml"

    def test_finds_yaml(self, tmp_path):
        (tmp_path / ".picodome.yaml").write_text("format: json\n")
        result = _find_config(tmp_path)
        assert result is not None
        assert result.name == ".picodome.yaml"

    def test_yml_precedence_over_yaml(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("format: json\n")
        (tmp_path / ".picodome.yaml").write_text("format: sarif\n")
        result = _find_config(tmp_path)
        assert result.name == ".picodome.yml"

    def test_returns_none_when_no_config(self, tmp_path):
        result = _find_config(tmp_path)
        assert result is None


# ─── load_config — YAML parsing ────────────────────────────────────


class TestLoadConfigYAML:
    def test_loads_format(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("format: json\n")
        cfg = load_config(tmp_path)
        assert cfg.format == "json"

    def test_loads_fail_on(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("fail_on: high\n")
        cfg = load_config(tmp_path)
        assert cfg.fail_on == "high"

    def test_loads_no_color(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("no_color: true\n")
        cfg = load_config(tmp_path)
        assert cfg.no_color is True

    def test_loads_timeout(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("timeout: 60\n")
        cfg = load_config(tmp_path)
        assert cfg.timeout == 60.0

    def test_loads_token_budget(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("token_budget: 8192\n")
        cfg = load_config(tmp_path)
        assert cfg.token_budget == 8192

    def test_loads_deterministic_output(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("deterministic_output: true\n")
        cfg = load_config(tmp_path)
        assert cfg.deterministic_output is True

    def test_loads_exit_code(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("exit_code: true\n")
        cfg = load_config(tmp_path)
        assert cfg.exit_code is True

    def test_loads_log_format(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("log_format: json\n")
        cfg = load_config(tmp_path)
        assert cfg.log_format == "json"

    def test_loads_severity_overrides(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("severity_overrides:\n  L3-NET-001: info\n")
        cfg = load_config(tmp_path)
        assert cfg.severity_overrides == {"L3-NET-001": "info"}

    def test_loads_rules(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("rules:\n  - L3-NET-001\n  - L3-PROC-001\n")
        cfg = load_config(tmp_path)
        assert cfg.rules == ["L3-NET-001", "L3-PROC-001"]

    def test_invalid_format_ignored(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("format: invalid_format\n")
        cfg = load_config(tmp_path)
        assert cfg.format == "table"

    def test_invalid_fail_on_ignored(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("fail_on: super_critical\n")
        cfg = load_config(tmp_path)
        assert cfg.fail_on is None

    def test_non_dict_config_ignored(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("- list\n- not\n- dict\n")
        cfg = load_config(tmp_path)
        assert cfg.format == "table"

    def test_version_mismatch_warns(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("version: 999\nformat: json\n")
        cfg = load_config(tmp_path)
        assert cfg.format == "json"  # still parses

    def test_baseline_relative_path(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("baseline: my-baselines.json\n")
        cfg = load_config(tmp_path)
        assert str(tmp_path) in cfg.baseline

    def test_baseline_absolute_path(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("baseline: /tmp/baselines.json\n")
        cfg = load_config(tmp_path)
        assert cfg.baseline == "/tmp/baselines.json"

    def test_policy_relative_path(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("policy: my-policy.json\n")
        cfg = load_config(tmp_path)
        assert str(tmp_path) in cfg.policy

    def test_invalid_timeout_ignored(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("timeout: not_a_number\n")
        cfg = load_config(tmp_path)
        assert cfg.timeout == 30.0  # default

    def test_invalid_token_budget_ignored(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("token_budget: abc\n")
        cfg = load_config(tmp_path)
        assert cfg.token_budget == 4096  # default

    def test_non_list_rules_ignored(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("rules: not_a_list\n")
        cfg = load_config(tmp_path)
        assert cfg.rules is None

    def test_invalid_severity_overrides_ignored(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("severity_overrides: not_a_dict\n")
        cfg = load_config(tmp_path)
        assert cfg.severity_overrides == {}

    def test_empty_dir_returns_defaults(self, tmp_path):
        cfg = load_config(tmp_path)
        assert cfg.format == "table"
        assert cfg.timeout == 30.0

    def test_invalid_log_format_ignored(self, tmp_path):
        (tmp_path / ".picodome.yml").write_text("log_format: xml\n")
        cfg = load_config(tmp_path)
        assert cfg.log_format == "text"


# ─── apply_env_overrides ───────────────────────────────────────────


class TestEnvOverrides:
    def test_format_override(self):
        with patch.dict(os.environ, {"PICODOME_FORMAT": "json"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.format == "json"

    def test_timeout_override(self):
        with patch.dict(os.environ, {"PICODOME_TIMEOUT": "90"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.timeout == 90.0

    def test_no_color_override_true(self):
        with patch.dict(os.environ, {"PICODOME_NO_COLOR": "1"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.no_color is True

    def test_no_color_override_false(self):
        cfg = PicoDomeConfig()
        cfg.no_color = True
        with patch.dict(os.environ, {"PICODOME_NO_COLOR": "0"}):
            cfg = apply_env_overrides(cfg)
            assert cfg.no_color is False

    def test_token_budget_override(self):
        with patch.dict(os.environ, {"PICODOME_TOKEN_BUDGET": "8192"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.token_budget == 8192

    def test_fail_on_override(self):
        with patch.dict(os.environ, {"PICODOME_FAIL_ON": "critical"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.fail_on == "critical"

    def test_log_format_override(self):
        with patch.dict(os.environ, {"PICODOME_LOG_FORMAT": "json"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.log_format == "json"

    def test_deterministic_output_override(self):
        with patch.dict(os.environ, {"PICODOME_DETERMINISTIC_OUTPUT": "true"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.deterministic_output is True

    def test_empty_env_ignored(self):
        with patch.dict(os.environ, {"PICODOME_FORMAT": ""}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.format == "table"  # stays default

    def test_invalid_numeric_ignored(self):
        with patch.dict(os.environ, {"PICODOME_TIMEOUT": "not_a_number"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.timeout == 30.0  # stays default

    def test_baseline_override(self):
        with patch.dict(os.environ, {"PICODOME_BASELINE": "/tmp/baselines.json"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.baseline == "/tmp/baselines.json"

    def test_policy_override(self):
        with patch.dict(os.environ, {"PICODOME_POLICY": "/tmp/policy.json"}):
            cfg = apply_env_overrides(PicoDomeConfig())
            assert cfg.policy == "/tmp/policy.json"


# ─── merge_from_cli ────────────────────────────────────────────────


class TestMergeFromCLI:
    def _make_args(self, **overrides):
        defaults = {
            "format": None,
            "no_color": False,
            "exit_code": False,
            "fail_on": None,
            "baseline": None,
            "deterministic_output": False,
            "token_budget": None,
            "timeout": None,
            "policy": None,
            "rules": None,
            "log_format": None,
        }
        defaults.update(overrides)

        class Args:
            pass

        args = Args()
        for k, v in defaults.items():
            setattr(args, k, v)
        return args

    def test_format_override(self):
        cfg = PicoDomeConfig()
        merged = cfg.merge_from_cli(self._make_args(format="json"))
        assert merged.format == "json"

    def test_no_color_override(self):
        cfg = PicoDomeConfig()
        merged = cfg.merge_from_cli(self._make_args(no_color=True))
        assert merged.no_color is True

    def test_fail_on_implies_exit_code(self):
        cfg = PicoDomeConfig()
        merged = cfg.merge_from_cli(self._make_args(fail_on="high"))
        assert merged.fail_on == "high"
        assert merged.exit_code is True

    def test_timeout_override(self):
        cfg = PicoDomeConfig()
        merged = cfg.merge_from_cli(self._make_args(timeout=45.0))
        assert merged.timeout == 45.0

    def test_config_file_values_preserved(self):
        cfg = PicoDomeConfig()
        cfg.format = "sarif"
        cfg.timeout = 120.0
        merged = cfg.merge_from_cli(self._make_args())
        assert merged.format == "sarif"
        assert merged.timeout == 120.0

    def test_deterministic_output_override(self):
        cfg = PicoDomeConfig()
        merged = cfg.merge_from_cli(self._make_args(deterministic_output=True))
        assert merged.deterministic_output is True

    def test_log_format_override(self):
        cfg = PicoDomeConfig()
        merged = cfg.merge_from_cli(self._make_args(log_format="json"))
        assert merged.log_format == "json"

    def test_token_budget_override(self):
        cfg = PicoDomeConfig()
        merged = cfg.merge_from_cli(self._make_args(token_budget=8192))
        assert merged.token_budget == 8192

    def test_policy_override(self):
        cfg = PicoDomeConfig()
        merged = cfg.merge_from_cli(self._make_args(policy="/tmp/policy.json"))
        assert merged.policy == "/tmp/policy.json"

    def test_rules_override(self):
        cfg = PicoDomeConfig()
        merged = cfg.merge_from_cli(self._make_args(rules=["L3-NET-001"]))
        assert merged.rules == ["L3-NET-001"]


# ─── _validate_config_keys ─────────────────────────────────────────


class TestValidateConfigKeys:
    def test_known_keys_no_warning(self, tmp_path, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            _validate_config_keys({"format": "json", "timeout": 60}, tmp_path / "test.yml")
        assert not caplog.records

    def test_unknown_keys_warning(self, tmp_path, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            _validate_config_keys({"format": "json", "unknown_key": "val"}, tmp_path / "test.yml")
        assert len(caplog.records) == 1
        assert "unknown_key" in caplog.records[0].message.lower()


class TestLoadConfigExceptionNarrowing:
    """Config parse failures must return defaults for expected errors and propagate bugs."""

    def test_expected_yaml_error_returns_defaults(self, tmp_path, caplog, monkeypatch):
        import logging

        (tmp_path / ".picodome.yml").write_text("not: valid: yaml: [")
        from picosentry.sandbox import config as config_mod

        if config_mod._yaml is None:

            class _FakeYaml:
                class YAMLError(Exception):
                    pass

                @staticmethod
                def safe_load(_stream):
                    raise OSError("read failed")

            monkeypatch.setattr(config_mod, "_yaml", _FakeYaml())
        else:

            def _boom(*_args, **_kwargs):
                raise config_mod._yaml.YAMLError("parse failed")

            monkeypatch.setattr(config_mod._yaml, "safe_load", _boom)

        with caplog.at_level(logging.WARNING, logger="picodome.config"):
            cfg = load_config(tmp_path)

        assert cfg.format == "table"  # defaults preserved
        assert any("Failed to parse config file" in r.message for r in caplog.records)

    def test_unexpected_yaml_error_propagates(self, tmp_path, monkeypatch):
        (tmp_path / ".picodome.yml").write_text("format: json\n")
        from picosentry.sandbox import config as config_mod

        class _FakeYaml:
            class YAMLError(Exception):
                pass

            @staticmethod
            def safe_load(_stream):
                raise NameError("programmer mistake")

        monkeypatch.setattr(config_mod, "_yaml", _FakeYaml())

        with pytest.raises(NameError, match="programmer mistake"):
            load_config(tmp_path)
