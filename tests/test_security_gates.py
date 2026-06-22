"""Startup security-gate regression suite.

Pins the core ``assert_secure`` denylist / length checks so the well-known
placeholder secret key (``"change-me-in-production"`` and friends) and
trivially short keys always fail the gate — in production AND in
development.

Bypass: ``ALLOW_INSECURE_SECRET=true`` is the explicit escape hatch for
local dev work that hasn't picked a real key yet.  A bare
``assert_secure()`` call with no key and the env var set must NOT add
the secret_key violation.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from picosentry._core.config import SecurityViolation, assert_secure


# Well-known placeholders that the gate must reject.  These come from the
# picosentry.serve default, from tutorial copy-paste, and from common
# Stack Overflow snippets.  Any one of them is a bug to ship with.
DENYLISTED_KEYS = [
    "",
    "change-me-in-production",
    "changeme",
    "default",
    "secret",
    "password",
    "please-change-me",
    "your-secret-key",
    "your-secret-key-here",
]


@pytest.mark.parametrize("bad_key", DENYLISTED_KEYS)
def test_denylisted_keys_fail_the_gate(bad_key: str) -> None:
    """The default and other obvious placeholders must produce a violation
    in production, staging, AND development.  The previous gate only
    fired in production, which is how the v2.0.12 release shipped with
    the default secret in dev."""
    for env in ("production", "staging", "development", "test"):
        violations = assert_secure(
            secret_key=bad_key,
            env=env,
            block_on_error=False,
        )
        names = {v.check for v in violations}
        assert "secret_key" in names, (
            f"denylisted key {bad_key!r} in env={env!r} should produce a secret_key violation; got {names}"
        )
        # Every secret_key violation must be ERROR, not WARN — there's no
        # scenario where shipping the default is OK.
        sev = next(v.severity for v in violations if v.check == "secret_key")
        assert sev == "ERROR"


def test_short_key_fails_the_gate() -> None:
    """Keys under 32 bytes must be rejected regardless of value.

    A long-but-known value is no safer than a short random one once it's
    in a public example, so the length floor is the floor."""
    for env in ("production", "development"):
        violations = assert_secure(
            secret_key="a" * 31,  # 31 bytes, just under the floor
            env=env,
            block_on_error=False,
        )
        names = {v.check for v in violations}
        assert "secret_key_length" in names, (
            f"31-byte key in env={env!r} should produce a secret_key_length violation; got {names}"
        )


def test_strong_key_passes_the_gate() -> None:
    """A 32+ byte non-denylisted value must NOT produce a secret_key
    violation in any env.  This is the happy path the test conftest
    depends on (``test-key-for-pytest-at-least-32-bytes!``)."""
    strong = "a-strong-test-secret-key-thats-32-bytes-or-more!"
    assert len(strong) >= 32
    for env in ("production", "staging", "development", "test"):
        violations = assert_secure(
            secret_key=strong,
            env=env,
            block_on_error=False,
        )
        names = {v.check for v in violations}
        assert "secret_key" not in names, f"strong key in env={env!r} must not trip the secret_key check; got {names}"


def test_allow_insecure_secret_bypass() -> None:
    """``ALLOW_INSECURE_SECRET=true`` lets the gate run with a denylisted
    or short key — but only the secret_key check is bypassed; bind_host,
    CORS, and other checks still fire.  This is the dev escape hatch."""
    with patch.dict("os.environ", {"ALLOW_INSECURE_SECRET": "true"}):
        violations = assert_secure(
            secret_key="",  # would normally fail
            env="development",
            block_on_error=False,
        )
        names = {v.check for v in violations}
        assert "secret_key" not in names
        assert "secret_key_length" not in names
        # The other gate checks (bind_host, cors_origin, debug) still
        # apply — a denylisted/short key is one of several startup risks.
        # bind_host defaults to 127.0.0.1 in assert_secure, so that check
        # is silent.  CORS also defaults empty.  We assert the secret
        # checks are off; the rest of the function is unchanged.


def test_gate_returns_security_violation_instances() -> None:
    """Each violation must be a SecurityViolation (dataclass with .check,
    .message, .severity).  The serve mode formats these into logs and
    the integration tests assert on .check, so the shape is part of the
    contract."""
    violations = assert_secure(
        secret_key="change-me-in-production",
        env="production",
        block_on_error=False,
    )
    assert violations
    v = violations[0]
    assert isinstance(v, SecurityViolation)
    assert v.check
    assert v.message
    assert v.severity in {"ERROR", "WARN"}
