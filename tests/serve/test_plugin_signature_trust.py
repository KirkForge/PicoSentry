"""Tests for plugin Ed25519 signature trust model.

The plugin manager now requires signatures to come from a configured
trusted-key set. Self-attested signatures (key shipped in the plugin's own
manifest) are not sufficient.

These tests monkey-patch the low-level Ed25519 verification so they do not
depend on the optional `pynacl` dependency being installed in the test runner.
The trust-model logic itself (key allowlist, required-vs-optional mode,
invalid-signature rejection) is what is exercised.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# Ensure the test settings match tests/serve/conftest.py
os.environ.setdefault("PICOSHOGUN_ENV", "test")
os.environ.setdefault("PICOSHOGUN_SECRET_KEY", "test-key-for-pytest-at-least-32-bytes!")


TRUSTED_PUBLIC_KEY = "ffdbacc3ef1b141c1b75e4e7f0da291e17e64229fcfb9f959bdb6b694fa3ed02"
TRUSTED_SIGNATURE = (
    "36943c9f12bc9d761dcbd9dde8f7d7b32a3f5aa82813263c90af548f88c1313"
    "037c87b5cac967cfc0650719d0865c115acc76cfa5b12df9de1789a4053ded50a"
)
UNTRUSTED_PUBLIC_KEY = "0000000000000000000000000000000000000000000000000000000000000000"
INVALID_SIGNATURE = "0" * len(TRUSTED_SIGNATURE)


def _write_plugin(base: Path, name: str, entry: str, manifest_overrides: dict | None = None) -> Path:
    """Write a minimal plugin with optional manifest overrides."""
    pdir = base / name
    pdir.mkdir(parents=True, exist_ok=True)
    manifest: dict = {
        "name": name,
        "version": "0.0.1",
        "author": "test",
        "description": f"tmp plugin {name}",
        "entry_point": entry,
        "hooks": ["alert"],
    }
    if manifest_overrides:
        manifest.update(manifest_overrides)
    (pdir / "plugin.json").write_text(json.dumps(manifest))
    (pdir / f"{entry}.py").write_text(
        "from typing import Any\n"
        "from picosentry.serve.services.plugin_manager import PluginInterface\n"
        f"class {name.title().replace('_', '')}Handler(PluginInterface):\n"
        "    def initialize(self, config):\n"
        "        return True\n"
        "    def on_alert(self, alert):\n"
        "        return alert\n"
    )
    return pdir


@pytest.fixture
def fresh_manager_class(monkeypatch):
    """Return a fresh PluginManager class from the cached module.

    Also patches HAS_NACL to True and replaces verify_manifest_signature
    with a deterministic stub that returns True iff the manifest public key
    is in the supplied trusted set and the signature is not the sentinel
    invalid signature. This lets the tests exercise the trust model without
    requiring the optional pynacl dependency.
    """
    from picosentry.serve.services import plugin_manager as pm_mod

    monkeypatch.setattr(pm_mod, "HAS_NACL", True)

    def stub_verify(_, __, signature_hex, public_key_hex, trusted_public_keys):
        if trusted_public_keys is not None and public_key_hex.lower() not in trusted_public_keys:
            return False
        return signature_hex != INVALID_SIGNATURE

    monkeypatch.setattr(pm_mod.PluginManager, "verify_manifest_signature", staticmethod(stub_verify))
    return pm_mod.PluginManager


def test_valid_signature_from_trusted_key_loads(fresh_manager_class, tmp_path, monkeypatch):
    """A plugin signed with a trusted public key is loaded and marked signed."""
    monkeypatch.setenv("PICOSHOGUN_TRUSTED_PUBLIC_KEYS", TRUSTED_PUBLIC_KEY)
    _write_plugin(
        tmp_path,
        "trusted_signed",
        "trusted_signed_mod",
        {
            "public_key": TRUSTED_PUBLIC_KEY,
            "signature": TRUSTED_SIGNATURE,
        },
    )

    pm = fresh_manager_class(extra_plugin_dirs=[str(tmp_path)])
    assert "trusted_signed" in pm.plugins
    assert pm.metadata["trusted_signed"].signed is True
    assert pm.metadata["trusted_signed"].public_key == TRUSTED_PUBLIC_KEY


def test_signature_from_untrusted_key_is_refused(fresh_manager_class, tmp_path, monkeypatch):
    """A plugin whose manifest public key is not in the trusted set is refused."""
    monkeypatch.setenv("PICOSHOGUN_TRUSTED_PUBLIC_KEYS", TRUSTED_PUBLIC_KEY)
    _write_plugin(
        tmp_path,
        "untrusted_signed",
        "untrusted_signed_mod",
        {
            "public_key": UNTRUSTED_PUBLIC_KEY,
            "signature": TRUSTED_SIGNATURE,
        },
    )

    pm = fresh_manager_class(extra_plugin_dirs=[str(tmp_path)])
    assert "untrusted_signed" not in pm.plugins


def test_invalid_signature_is_refused(fresh_manager_class, tmp_path, monkeypatch):
    """A plugin with a corrupt signature from a trusted key is refused."""
    monkeypatch.setenv("PICOSHOGUN_TRUSTED_PUBLIC_KEYS", TRUSTED_PUBLIC_KEY)
    _write_plugin(
        tmp_path,
        "bad_sig",
        "bad_sig_mod",
        {
            "public_key": TRUSTED_PUBLIC_KEY,
            "signature": INVALID_SIGNATURE,
        },
    )

    pm = fresh_manager_class(extra_plugin_dirs=[str(tmp_path)])
    assert "bad_sig" not in pm.plugins


def test_require_signed_with_no_trusted_keys_refuses_all(fresh_manager_class, tmp_path, monkeypatch):
    """PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1 without any trusted keys fails closed."""
    from picosentry.serve.services import plugin_manager as pm_mod

    monkeypatch.setenv("PICOSHOGUN_REQUIRE_SIGNED_PLUGINS", "1")
    monkeypatch.delenv("PICOSHOGUN_TRUSTED_PUBLIC_KEYS", raising=False)
    monkeypatch.delenv("PICOSHOGUN_TRUSTED_PUBLIC_KEYS_FILE", raising=False)
    monkeypatch.setattr(pm_mod, "BUNDLED_TRUSTED_PUBLIC_KEYS", ())
    _write_plugin(
        tmp_path,
        "required_signed",
        "required_signed_mod",
        {
            "public_key": TRUSTED_PUBLIC_KEY,
            "signature": TRUSTED_SIGNATURE,
        },
    )

    pm = fresh_manager_class(extra_plugin_dirs=[str(tmp_path)])
    assert "required_signed" not in pm.plugins


def test_unsigned_plugin_loads_in_optional_mode(fresh_manager_class, tmp_path, monkeypatch):
    """When signing is not required, an unsigned plugin still loads (marked unsigned)."""
    monkeypatch.delenv("PICOSHOGUN_REQUIRE_SIGNED_PLUGINS", raising=False)
    _write_plugin(tmp_path, "unsigned", "unsigned_mod")

    pm = fresh_manager_class(extra_plugin_dirs=[str(tmp_path)])
    assert "unsigned" in pm.plugins
    assert pm.metadata["unsigned"].signed is False


def test_bundled_test_plugin_is_trusted_by_default(fresh_manager_class, monkeypatch):
    """The bundled test_plugin public key is trusted by default and loads."""
    monkeypatch.delenv("PICOSHOGUN_TRUSTED_PUBLIC_KEYS", raising=False)
    monkeypatch.delenv("PICOSHOGUN_TRUSTED_PUBLIC_KEYS_FILE", raising=False)

    pm = fresh_manager_class()
    assert "test_plugin" in pm.plugins
    assert pm.metadata["test_plugin"].public_key == TRUSTED_PUBLIC_KEY
    assert pm.metadata["test_plugin"].signed is True


def test_trusted_public_keys_file_is_honored(fresh_manager_class, tmp_path, monkeypatch):
    """PICOSHOGUN_TRUSTED_PUBLIC_KEYS_FILE loads trusted keys from disk."""
    key_file = tmp_path / "trusted_keys.txt"
    key_file.write_text(TRUSTED_PUBLIC_KEY + "\n")
    monkeypatch.setenv("PICOSHOGUN_TRUSTED_PUBLIC_KEYS_FILE", str(key_file))
    monkeypatch.delenv("PICOSHOGUN_TRUSTED_PUBLIC_KEYS", raising=False)
    _write_plugin(
        tmp_path,
        "file_trusted",
        "file_trusted_mod",
        {
            "public_key": TRUSTED_PUBLIC_KEY,
            "signature": TRUSTED_SIGNATURE,
        },
    )

    pm = fresh_manager_class(extra_plugin_dirs=[str(tmp_path)])
    assert "file_trusted" in pm.plugins
    assert pm.metadata["file_trusted"].signed is True
