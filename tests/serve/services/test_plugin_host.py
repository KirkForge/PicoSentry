"""Tests for the subprocess plugin host (env validation, lifecycle)."""

from __future__ import annotations

import pytest

from picosentry.serve.services.plugin_host import PluginHost
from picosentry.serve.services.plugin_manager import PluginMetadata


def _make_host(tmp_path, **overrides) -> PluginHost:
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    (plugin_dir / "handler.py").write_text(
        "from picosentry.serve.services.plugin_manager import PluginInterface\n"
        "class Handler(PluginInterface):\n"
        "    def initialize(self, config): return True\n"
    )

    metadata = PluginMetadata(
        name=overrides.get("name", "test_plugin"),
        version="1.0.0",
        author="pytest",
        description="test",
        entry_point="handler",
        hooks=["project_complete"],
        dependencies=[],
        capabilities=overrides.get("capabilities", []),
    )

    host = PluginHost.__new__(PluginHost)
    host.plugin_path = plugin_dir
    host.metadata = metadata
    host.module_checksum = "deadbeef"
    host.timeout = 5.0
    host._proc = None
    host._ready = False
    host._capabilities = set(metadata.capabilities)
    return host


class TestEnvValidation:
    """Plugin metadata that becomes env vars must be well-formed."""

    def test_valid_name_and_capabilities_pass(self, tmp_path):
        host = _make_host(tmp_path, name="my_plugin", capabilities=["network", "filesystem"])
        host._validate_env_values()

    @pytest.mark.parametrize("bad_name", ["plugin; rm -rf /", "plugin\nenv", "plugin=evil"])
    def test_invalid_name_characters_rejected(self, tmp_path, bad_name):
        host = _make_host(tmp_path, name=bad_name)
        with pytest.raises(ValueError, match="Invalid plugin name"):
            host._validate_env_values()

    def test_invalid_capability_name_rejected(self, tmp_path):
        host = _make_host(tmp_path, capabilities=["network", "file system"])
        with pytest.raises(ValueError, match="Invalid capability name"):
            host._validate_env_values()


class TestPluginHostHardening:
    """PluginHost must not leak internal errors or silently swallow shutdown failures."""

    def test_health_check_returns_sanitized_error(self, tmp_path, caplog, monkeypatch):
        import logging

        host = _make_host(tmp_path)

        def _boom(*args, **kwargs):
            raise RuntimeError("secret internal failure")

        monkeypatch.setattr(host, "_send", _boom)

        with caplog.at_level(logging.WARNING, logger="picoshogun.PluginHost"):
            result = host.health_check()

        assert result["status"] == "unhealthy"
        assert "secret internal failure" not in result.get("error", "")
        assert "RuntimeError" not in result.get("error", "")
        assert any("Plugin health check failed" in r.message for r in caplog.records)

    def test_shutdown_send_failure_is_logged(self, tmp_path, caplog, monkeypatch):
        import logging

        host = _make_host(tmp_path)

        def _boom(*args, **kwargs):
            raise RuntimeError("worker gone")

        monkeypatch.setattr(host, "_send", _boom)
        # _terminate needs a proc; provide a minimal fake so the test exercises
        # the except block and then returns cleanly.
        fake_proc = type(
            "_FakeProc",
            (),
            {
                "poll": lambda self: 1,
                "terminate": lambda self: None,
                "wait": lambda self, **kw: None,
                "kill": lambda self: None,
                "stdin": None,
                "pid": 12345,
            },
        )()
        host._proc = fake_proc
        host._ready = True

        with caplog.at_level(logging.DEBUG, logger="picoshogun.PluginHost"):
            host.shutdown()

        assert any("Shutdown request failed" in r.message for r in caplog.records)
