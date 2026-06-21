"""Verify pytest-timeout plugin is loaded — enterprise CI guard.

This test SKIPS if pytest-timeout is not installed. Enterprise CI installs the
``dev`` extras (which include pytest-timeout) so the guard still runs there.
"""

import pytest


def test_pytest_timeout_plugin_loaded(pytestconfig):
    """Enterprise CI guard: pytest-timeout must be loaded."""
    pytest.importorskip("timeout")
    assert pytestconfig.pluginmanager.hasplugin("timeout"), (
        "pytest-timeout plugin is not loaded. "
        "Enterprise CI requires timeout protection. "
        "Install with: pip install pytest-timeout"
    )
