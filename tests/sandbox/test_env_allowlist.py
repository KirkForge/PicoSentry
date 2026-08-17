"""Sandbox env allowlist tests — WO4.0.0-010 deliverable 3.

The env=None path is an ALLOWLIST shared by every backend (one module,
l3/backends/_env_defaults.py). Previously the engine re-merged os.environ
minus a suffix denylist (leaking SECRET_KEY_FILE, *_APIKEY, KUBECONFIG,
SSH_AUTH_SOCK) while each backend carried its own dead-code allowlist.
"""

from __future__ import annotations

import inspect
import os

import pytest

from picosentry.sandbox.l3.backends._env_defaults import SANDBOX_ENV_ALLOWLIST, default_child_env
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.policy import default_policy

# Keys that must NEVER be in the allowlist (regression guard for drift).
FORBIDDEN_ALLOWLIST_KEYS = (
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
    "NPM_CONFIG_USERCONFIG",
    "PICODOME_API_TOKENS",
    "AWS_SECRET_ACCESS_KEY",
)


class TestDefaultChildEnv:
    def test_allowlist_excludes_secret_shaped_keys(self):
        for key in FORBIDDEN_ALLOWLIST_KEYS:
            assert key not in SANDBOX_ENV_ALLOWLIST

    def test_allowlist_has_runtime_discovery_basics(self):
        for key in ("PATH", "HOME", "LANG", "TMPDIR", "PYTHONPATH", "NODE_PATH"):
            assert key in SANDBOX_ENV_ALLOWLIST

    def test_default_child_env_filters_planted_secrets(self, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        monkeypatch.setenv("MY_SERVICE_APIKEY", "leak-me")
        monkeypatch.setenv("KUBECONFIG", "/home/u/.kube/config")
        monkeypatch.setenv("SECRET_KEY_FILE", "/etc/secret")
        env = default_child_env()
        assert env["PATH"] == "/usr/bin:/bin"
        assert "MY_SERVICE_APIKEY" not in env
        assert "KUBECONFIG" not in env
        assert "SECRET_KEY_FILE" not in env


class TestEngineEnvNoneUsesAllowlist:
    def test_env_none_child_gets_allowlist_only(self, monkeypatch):
        """Integration: a child spawned with env=None must see allowlisted
        vars and never the planted secrets (subprocess backend — always
        available, no kernel sandbox needed)."""
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        monkeypatch.setenv("PICODOME_TEST_SECRET_MARKER", "hunter2-marker")
        monkeypatch.setenv("SECRET_TOKEN", "tok-marker")
        result = sandbox_run(
            ["/usr/bin/env"],
            default_policy(),
            backend=SubprocessBackend(),
            env=None,
        )
        assert "hunter2-marker" not in result.stdout + result.stderr
        assert "tok-marker" not in result.stdout + result.stderr
        # Allowlisted vars do reach the child.
        assert "PATH=" in result.stdout

    def test_explicit_env_still_strip_filtered(self, monkeypatch):
        """Caller-supplied env dicts keep the pattern strip (defense in depth)."""
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        result = sandbox_run(
            ["/usr/bin/printenv", "CALLER_SECRET_TOKEN"],
            default_policy(),
            backend=SubprocessBackend(),
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CALLER_SECRET_TOKEN": "leak-me-not"},
        )
        assert "leak-me-not" not in result.stdout + result.stderr


class TestBackendEnvParity:
    def test_all_backends_share_the_default_env(self):
        """Every backend module references the shared allowlist helper on its
        env=None path — no divergent inline lists (the old inversion had the
        fallback backend richest)."""
        import picosentry.sandbox.l3.backends.landlock_backend as landlock
        import picosentry.sandbox.l3.backends.seatbelt_backend as seatbelt
        import picosentry.sandbox.l3.backends.seccomp_backend as seccomp
        import picosentry.sandbox.l3.backends.seccomp_trace.orchestrator as trace_orch
        import picosentry.sandbox.l3.backends.subprocess_backend as subprocess_be

        for module in (landlock, seatbelt, seccomp, trace_orch, subprocess_be):
            source = inspect.getsource(module)
            assert "default_child_env" in source, f"{module.__name__} must use the shared env allowlist"
            # No residual inline allowlist comprehension against os.environ.
            assert 'in ("PATH", "HOME", "LANG"' not in source, (
                f"{module.__name__} still carries an inline env allowlist"
            )

    @pytest.mark.parametrize(
        "env",
        [{}, {"PATH": "/usr/bin"}, None],
    )
    def test_backend_accepts_env_none_and_dicts(self, env):
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        result = SubprocessBackend().run(["/bin/echo", "parity"], default_policy(), env=env)
        assert "parity" in result.stdout
