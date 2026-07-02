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
