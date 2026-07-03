"""Regression tests for PluginManager exception narrowing (P4 #10)."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from picosentry.serve.services.plugin_manager import PluginManager


def _write_manifest(plugin_dir: Path, name: str = "boom_plugin", **extra: Any) -> Path:
    manifest = {
        "name": name,
        "entry_point": "plugin",
        "version": "0.0.1",
        "hooks": [],
        "capabilities": [],
        **extra,
    }
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "plugin.json").write_text(json.dumps(manifest))
    (plugin_dir / "plugin.py").write_text("class Plugin:\n    pass\n")
    return plugin_dir


@pytest.fixture
def fake_nacl(monkeypatch):
    """Inject a minimal fake nacl so signature tests run whether or not pynacl is installed."""
    nacl = types.ModuleType("nacl")
    nacl.__path__ = []  # type: ignore[assignment]

    nacl_exceptions = types.ModuleType("nacl.exceptions")
    nacl_exceptions.BadSignatureError = RuntimeError

    nacl_signing = types.ModuleType("nacl.signing")

    class _FakeVerifyKey:
        def __init__(self, key_bytes: bytes):
            self._key = key_bytes

        def verify(self, message: bytes, signature: bytes) -> None:
            return None

    nacl_signing.VerifyKey = _FakeVerifyKey

    for name, mod in [
        ("nacl", nacl),
        ("nacl.exceptions", nacl_exceptions),
        ("nacl.signing", nacl_signing),
    ]:
        monkeypatch.setitem(sys.modules, name, mod)

    monkeypatch.setattr("picosentry.serve.services.plugin_manager.HAS_NACL", True)


class TestPluginManagerExceptionNarrowing:
    """Unexpected programmer errors in plugin loading must propagate."""

    def test_signature_verify_unexpected_error_propagates(self, monkeypatch, fake_nacl):
        """A NameError inside signature verification must not be swallowed."""

        def _boom(*args, **kwargs):
            raise NameError("programmer bug")

        monkeypatch.setattr(PluginManager, "_compute_manifest_signature_content", _boom)

        with pytest.raises(NameError, match="programmer bug"):
            PluginManager.verify_manifest_signature(
                meta={"name": "x"},
                module_checksum="a" * 64,
                signature_hex="b" * 128,
                public_key_hex="c" * 64,
                trusted_public_keys={"c" * 64},
            )

    def test_discovery_loop_unexpected_error_propagates(self, tmp_path, monkeypatch):
        """A NameError during manifest validation must not be swallowed."""
        _write_manifest(tmp_path / "boom")

        def _boom(*args, **kwargs):
            raise NameError("programmer bug")

        monkeypatch.setattr(PluginManager, "_validate_manifest", _boom)
        # Skip discovery during construction so we can exercise _load_plugins explicitly.
        monkeypatch.setenv("PICOSHOGUN_PLUGIN_WORKER", "1")
        manager = PluginManager(plugin_dir=str(tmp_path))

        # The discovery loop catches operational errors; NameError should propagate.
        with pytest.raises(NameError, match="programmer bug"):
            manager._load_plugins()

    def test_load_plugin_unexpected_error_propagates(self, tmp_path, monkeypatch):
        """A NameError inside PluginHost construction must not be swallowed."""
        plugin_dir = _write_manifest(tmp_path / "boom")

        class _BoomHost:
            def __init__(self, *args, **kwargs):
                raise NameError("programmer bug")

        # _load_plugin imports PluginHost lazily; patch the source class.
        monkeypatch.setattr(
            "picosentry.serve.services.plugin_host.PluginHost",
            _BoomHost,
        )
        # Skip bundled plugin discovery so we can exercise _load_plugin directly.
        monkeypatch.setenv("PICOSHOGUN_PLUGIN_WORKER", "1")
        manager = PluginManager()

        with pytest.raises(NameError, match="programmer bug"):
            manager._load_plugin(str(plugin_dir), {"name": "boom", "entry_point": "plugin"})
