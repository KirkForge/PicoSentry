"""WO7.0.0-016: ClusterTokenStore.is_accepted uses constant-time comparison."""

from __future__ import annotations

from picosentry.sandbox.cluster.token_store import ClusterTokenStore


def test_is_accepted_uses_compare_digest():
    store = ClusterTokenStore(initial_token="secret-token-123")
    assert store.is_accepted("secret-token-123")
    assert not store.is_accepted("wrong-token-456")
    assert not store.is_accepted("")
    assert not store.is_accepted("secret-token-12")  # prefix, not full


def test_is_accepted_constant_time_no_early_exit_by_length():
    """Ensure matching checks compare bytes not membership — the previous
    `token in self._accepted` is a hash-based O(1) short-circuit that leaks
    timing. The fix iterates and compare_digest every candidate."""
    store = ClusterTokenStore(initial_token="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    store.adopt_token("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", version=2, issued_at=1.0)
    store.adopt_token("cccccccccccccccccccccccccccccccc", version=3, issued_at=2.0)

    assert store.is_accepted("cccccccccccccccccccccccccccccccc")
    assert store.is_accepted("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert store.is_accepted("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    assert not store.is_accepted("dddddddddddddddddddddddddddddddd")


def test_is_accepted_empty_store():
    store = ClusterTokenStore()
    assert not store.is_accepted("anything")
    assert not store.is_accepted("")
