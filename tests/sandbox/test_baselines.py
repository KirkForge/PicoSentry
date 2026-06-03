"""Tests for L4 baseline management."""

import json
import tempfile
from pathlib import Path

import pytest

from picosentry.sandbox.l4.baseline import (
    load_all_baselines,
    load_baseline,
    load_baselines_from_path,
    register_baseline,
)
from picosentry.sandbox.l4.models import Baseline


class TestLoadAllBaselines:
    def test_loads_all_shipped_baselines(self):
        baselines = load_all_baselines()
        assert len(baselines) >= 5  # npm, pip, node, python, curl

    def test_contains_npm_install(self):
        baselines = load_all_baselines()
        assert "npm-install" in baselines

    def test_contains_python_script(self):
        baselines = load_all_baselines()
        assert "python-script" in baselines

    def test_contains_node_script(self):
        baselines = load_all_baselines()
        assert "node-script" in baselines

    def test_contains_curl_wget(self):
        baselines = load_all_baselines()
        assert "curl-wget" in baselines

    def test_contains_pip_install(self):
        baselines = load_all_baselines()
        assert "python-pip-install" in baselines

    def test_returns_dict(self):
        baselines = load_all_baselines()
        assert isinstance(baselines, dict)


class TestLoadSpecificBaseline:
    def test_load_python_script(self):
        baseline = load_baseline("python-script")
        assert baseline is not None
        assert baseline.name == "python-script"
        assert baseline.package == "python"

    def test_load_npm_install(self):
        baseline = load_baseline("npm-install")
        assert baseline is not None
        assert baseline.name == "npm-install"
        assert baseline.package == "npm"

    def test_load_node_script(self):
        baseline = load_baseline("node-script")
        assert baseline is not None
        assert baseline.package == "node"

    def test_missing_baseline_returns_none(self):
        result = load_baseline("nonexistent-baseline-xyz")
        assert result is None

    def test_baseline_has_expected_fields(self):
        baseline = load_baseline("python-script")
        assert baseline.expected_network_calls == 0
        assert baseline.expected_dns_queries == 0
        assert baseline.expected_fs_ops == 100
        assert baseline.expected_spawns == 0
        assert baseline.expected_runtime_ms_range == (10, 30000)

    def test_npm_baseline_has_domains(self):
        baseline = load_baseline("npm-install")
        assert "registry.npmjs.org" in baseline.allowed_domains

    def test_npm_baseline_has_paths(self):
        baseline = load_baseline("npm-install")
        assert any("node_modules" in p for p in baseline.allowed_paths)


class TestRegisterCustomBaseline:
    def test_register_custom_baseline(self):
        custom = Baseline(
            name="my-custom",
            package="myapp",
            version="1.0",
            expected_network_calls=5,
            expected_dns_queries=2,
            expected_fs_ops=50,
            expected_spawns=1,
            expected_runtime_ms_range=(100, 10000),
            allowed_domains=["api.myapp.com"],
            allowed_paths=["/var/lib/myapp/**"],
            notes="Custom baseline for myapp",
        )
        try:
            register_baseline(custom)
            loaded = load_baseline("my-custom")
            assert loaded is not None
            assert loaded.name == "my-custom"
            assert loaded.package == "myapp"
        finally:
            from picosentry.sandbox.l4.baseline import SHIPPED_BASELINES

            SHIPPED_BASELINES.pop("my-custom", None)

    def test_register_overrides_existing(self):
        # Save original to restore after test
        from picosentry.sandbox.l4.baseline import SHIPPED_BASELINES

        original = SHIPPED_BASELINES.get("python-script")
        try:
            custom = Baseline(
                name="python-script",  # Same name as shipped
                package="python-override",
                expected_network_calls=999,
            )
            register_baseline(custom)
            loaded = load_baseline("python-script")
            assert loaded.package == "python-override"
            assert loaded.expected_network_calls == 999
        finally:
            # Restore original baseline to avoid poisoning other tests
            if original is not None:
                SHIPPED_BASELINES["python-script"] = original


class TestLoadBaselinesFromPath:
    def test_load_from_json_file(self, tmp_baselines_json_file):
        baselines = load_baselines_from_path(tmp_baselines_json_file)
        assert "test-custom-baseline" in baselines
        b = baselines["test-custom-baseline"]
        assert b.package == "myapp"
        assert b.expected_network_calls == 2
        assert b.expected_dns_queries == 1
        assert b.allowed_domains == ["api.example.com"]

    def test_load_multiple_baselines(self):
        data = [
            {
                "name": "baseline-a",
                "package": "pkg-a",
                "expected_network_calls": 1,
                "expected_dns_queries": 0,
                "expected_fs_ops": 10,
                "expected_spawns": 0,
                "expected_runtime_ms_range": [100, 5000],
            },
            {
                "name": "baseline-b",
                "package": "pkg-b",
                "expected_network_calls": 3,
                "expected_dns_queries": 2,
                "expected_fs_ops": 20,
                "expected_spawns": 1,
                "expected_runtime_ms_range": [200, 10000],
            },
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)

        baselines = load_baselines_from_path(path)
        assert len(baselines) == 2
        assert "baseline-a" in baselines
        assert "baseline-b" in baselines

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_baselines_from_path(Path("/nonexistent/baselines.json"))

    def test_baseline_to_dict_roundtrip(self, python_baseline):
        d = python_baseline.to_dict()
        assert d["name"] == "python-script"
        assert d["package"] == "python"
        assert d["expected_runtime_ms_range"] == [10, 30000]
        # Verify JSON-serializable
        json_str = json.dumps(d)
        assert isinstance(json_str, str)

    def test_baseline_runtime_range_as_list(self, python_baseline):
        d = python_baseline.to_dict()
        assert isinstance(d["expected_runtime_ms_range"], list)
        assert d["expected_runtime_ms_range"] == [10, 30000]
