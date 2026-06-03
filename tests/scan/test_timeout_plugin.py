"""Verify pytest-timeout plugin is loaded — enterprise CI guard.

This test FAILS if pytest-timeout is not installed, because enterprise
CI requires timeout protection for pathological inputs.
"""


def test_pytest_timeout_plugin_loaded(pytestconfig):
    """Enterprise CI guard: pytest-timeout must be loaded."""
    assert pytestconfig.pluginmanager.hasplugin("timeout"), (
        "pytest-timeout plugin is not loaded. "
        "Enterprise CI requires timeout protection. "
        "Install with: pip install pytest-timeout"
    )
