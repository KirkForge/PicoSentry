"""Cluster token store supporting safe rolling rotation.

Instead of a single shared secret, each node keeps:

- A **primary** token used to sign outbound gossip requests.
- An **accepted** set of tokens used to authenticate inbound requests.

During rotation a node generates/adopts a new primary token and propagates it
via gossip snapshots. Peers add the new token to their accepted set while still
accepting the old token, so the cluster stays connected during the rolling
update. After all peers have acknowledged the new token, the old token can be
retired.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class TokenInfo:
    token: str
    version: int
    issued_at: float
    primary: bool = False


class ClusterTokenStore:
    """Store for primary and accepted cluster tokens.

    Thread-safe.  All mutations are protected by a lock.
    """

    def __init__(self, initial_token: str = "") -> None:
        self._lock = threading.Lock()
        self._primary: TokenInfo | None = None
        self._accepted: dict[str, TokenInfo] = {}
        self._version_counter = 0
        if initial_token:
            self.set_primary(initial_token)

    def _next_version(self) -> int:
        self._version_counter += 1
        return self._version_counter

    @property
    def primary_token(self) -> str:
        with self._lock:
            return self._primary.token if self._primary else ""

    @property
    def accepted_tokens(self) -> set[str]:
        with self._lock:
            return set(self._accepted.keys())

    @property
    def accepted_token_infos(self) -> list[TokenInfo]:
        with self._lock:
            return list(self._accepted.values())

    def is_accepted(self, token: str) -> bool:
        with self._lock:
            return token in self._accepted

    def set_primary(self, token: str) -> TokenInfo:
        """Set a new primary token, adding the previous primary to accepted."""
        with self._lock:
            info = TokenInfo(
                token=token,
                version=self._next_version(),
                issued_at=time.time(),
                primary=True,
            )
            if self._primary is not None:
                old = self._primary
                self._accepted[old.token] = TokenInfo(
                    token=old.token,
                    version=old.version,
                    issued_at=old.issued_at,
                    primary=False,
                )
            self._primary = info
            self._accepted[token] = info
            return info

    def adopt_token(self, token: str, version: int, issued_at: float) -> bool:
        """Add an inbound token to the accepted set (e.g. from a gossip snapshot).

        Returns True if the token was newly added.
        """
        with self._lock:
            if token in self._accepted:
                return False
            self._accepted[token] = TokenInfo(
                token=token,
                version=version,
                issued_at=issued_at,
                primary=False,
            )
            return True

    def retire_older_than(self, cutoff: float) -> None:
        """Retire accepted tokens older than ``cutoff`` (epoch seconds).

        The current primary token is never retired.
        """
        with self._lock:
            primary_token = self._primary.token if self._primary else ""
            stale = [
                token for token, info in self._accepted.items() if token != primary_token and info.issued_at < cutoff
            ]
            for token in stale:
                self._accepted.pop(token, None)

    def rotate(self, new_token: str | None = None) -> TokenInfo:
        """Generate or adopt a new primary token and keep the old one accepted."""
        token = new_token or secrets.token_urlsafe(32)
        return self.set_primary(token)

    def to_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "primary": {
                    "token": self._primary.token,
                    "version": self._primary.version,
                    "issued_at": self._primary.issued_at,
                }
                if self._primary
                else None,
                "accepted": [
                    {
                        "token": info.token,
                        "version": info.version,
                        "issued_at": info.issued_at,
                    }
                    for info in self._accepted.values()
                ],
            }

    @classmethod
    def from_snapshot(cls, snapshot: dict[str, Any]) -> ClusterTokenStore:
        store = cls()
        primary = snapshot.get("primary")
        if primary:
            store._primary = TokenInfo(
                token=primary["token"],
                version=primary["version"],
                issued_at=primary["issued_at"],
                primary=True,
            )
            store._accepted[primary["token"]] = store._primary
            store._version_counter = max(store._version_counter, primary["version"])
        for info in snapshot.get("accepted", []):
            store._accepted[info["token"]] = TokenInfo(
                token=info["token"],
                version=info["version"],
                issued_at=info["issued_at"],
                primary=False,
            )
            store._version_counter = max(store._version_counter, info["version"])
        return store

    def __repr__(self) -> str:
        with self._lock:
            primary = self._primary.token[:8] + "..." if self._primary else "none"
            accepted = len(self._accepted)
            return f"ClusterTokenStore(primary={primary}, accepted={accepted})"


__all__ = ["ClusterTokenStore", "TokenInfo"]
