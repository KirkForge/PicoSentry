"""WO7.0.0-017: TokenAuth brute-force dict thread safety."""

from __future__ import annotations

import threading
from unittest.mock import patch

from picosentry.sandbox.auth import RBAC, TokenAuth, _hash_token


def test_concurrent_failed_attempts_no_lost_increments():
    """8 threads x 200 concurrent failed-logins → no RuntimeError, final count 1600."""
    with patch.dict("os.environ", {"PICODOME_API_TOKENS": "picodome-submitter-real-token-0123456789"}):
        auth = TokenAuth(rbac=RBAC())

    bad_hash = _hash_token("wrong-token-not-registered")
    n_threads = 8
    per_thread = 200
    errors: list[BaseException] = []

    def _hammer():
        for _ in range(per_thread):
            try:
                auth._record_failure(bad_hash)
            except BaseException as exc:
                errors.append(exc)

    threads = [threading.Thread(target=_hammer) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert errors == [], f"concurrent failures raised: {errors}"
    with auth._failed_attempts_lock:
        attempts, _ = auth._failed_attempts[bad_hash]
    assert attempts == n_threads * per_thread


def test_concurrent_validate_no_runtime_error():
    with patch.dict("os.environ", {"PICODOME_API_TOKENS": "picodome-submitter-real-token-0123456789"}):
        auth = TokenAuth(rbac=RBAC())

    errors: list[BaseException] = []

    def _hammer():
        for _ in range(100):
            try:
                auth.validate("wrong-token-not-registered")
            except BaseException as exc:
                errors.append(exc)

    threads = [threading.Thread(target=_hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert errors == [], f"concurrent validate raised: {errors}"
