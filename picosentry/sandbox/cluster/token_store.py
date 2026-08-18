"""Cluster token store supporting safe rolling rotation.

Instead of a single shared secret, each node keeps:

- A **primary** token used to sign outbound gossip requests.
- An **accepted** set of tokens used to authenticate inbound requests.

During rotation a node generates/adopts a new primary token and propagates it
via gossip snapshots. Peers add the new token to their accepted set while still
accepting the old token, so the cluster stays connected during the rolling
update. After all peers have acknowledged the new token, the old token can be
retired.

WO5.0.0-030 — rotation announcements: a generated rotation derives the new
primary as ``HMAC-SHA256(old_primary, "picodome-cluster-rotation:v1:<ts>")``,
so every holder of the old primary can re-derive (and thus adopt) the new
token from public snapshot data alone. The snapshot carries only
``{announced_by, hmac, announced_at, grace_expires}`` where ``hmac`` is
``HMAC-SHA256(old_primary, new_primary)`` — the new token's raw bytes never
travel on the wire.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any


ROTATION_CONTEXT = "picodome-cluster-rotation:v1:"


def token_grace_seconds() -> float:
    """Shared-trust grace window (PICODOME_CLUSTER_TOKEN_GRACE_SECONDS, default 3600)."""
    try:
        grace = float(os.environ.get("PICODOME_CLUSTER_TOKEN_GRACE_SECONDS", "3600"))
    except (ValueError, TypeError):
        grace = 3600.0
    return grace


def derive_rotation_token(anchor_token: str, announced_at: float) -> str:
    """Derive the rotated primary from an anchor token every peer already holds."""
    ctx = f"{ROTATION_CONTEXT}{float(announced_at)}".encode()
    return hmac.new(anchor_token.encode("utf-8"), ctx, hashlib.sha256).hexdigest()


def token_digest(token: str) -> str:
    """Stable non-secret identifier for a token (gossip-safe)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


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
        self._announcement: dict[str, Any] | None = None
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

    @property
    def announcement(self) -> dict[str, Any] | None:
        """Current rotation announcement (copied), if one is in force."""
        with self._lock:
            return dict(self._announcement) if self._announcement else None

    def is_accepted(self, token: str) -> bool:
        with self._lock:
            return token in self._accepted

    def set_primary(self, token: str) -> TokenInfo:
        """Set a new primary token, adding the previous primary to accepted.

        The demoted token's grace clock restarts at rotation time (its
        ``issued_at`` is re-stamped), so ``retire_older_than`` measures grace
        from the rotation, not from the token's original issue date.
        """
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
                    issued_at=time.time(),
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

    def rotate(self, new_token: str | None = None, announced_by: str = "") -> TokenInfo:
        """Generate or adopt a new primary token and keep the old one accepted.

        With no explicit token, the new primary is derived as an HMAC of the
        old primary (see ``derive_rotation_token``) and a rotation announcement
        is recorded so peers can re-derive and adopt it from gossip snapshots.
        An explicitly supplied token cannot be peer-derivable, so no
        announcement is made (manual distribution applies) and any prior
        announcement is superseded.
        """
        with self._lock:
            if new_token is not None:
                self._announcement = None
                token = new_token
            else:
                old = self._primary.token if self._primary else ""
                if not old:
                    token = secrets.token_urlsafe(32)
                else:
                    announced_at = time.time()
                    token = derive_rotation_token(old, announced_at)
                    self._announcement = {
                        "announced_by": announced_by,
                        "hmac": hmac.new(old.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest(),
                        "announced_at": announced_at,
                        "grace_expires": announced_at + token_grace_seconds(),
                    }
        return self.set_primary(token)

    def apply_announcement(self, announcement: dict[str, Any]) -> bool:
        """Verify and apply a peer's rotation announcement.

        Every accepted token is tried as the derivation anchor; a match on the
        keyed digest proves the announcer held a token we already trust. If the
        anchor is our primary we follow the rotation (promote the derived
        token, demoting the anchor with a fresh grace clock); otherwise the
        derived token is adopted into the accepted set. Adopters keep the
        announcement so it re-broadcasts via their own snapshots.

        ponytail: ceiling — ANY-MEMBER adoption: any peer (or any holder of one
        still-accepted token) can rotate the cluster primary this way; upgrade
        to quorum adoption when cluster membership semantics exist.
        Returns True if new token material was adopted or promoted.
        """
        announced_at = announcement.get("announced_at")
        announced_hmac = announcement.get("hmac")
        if not isinstance(announced_at, (int, float)) or not isinstance(announced_hmac, str):
            return False
        ctx = f"{ROTATION_CONTEXT}{float(announced_at)}".encode()

        with self._lock:
            primary_token = self._primary.token if self._primary else ""
            anchor: str | None = None
            candidate = ""
            for token in list(self._accepted):
                candidate = hmac.new(token.encode("utf-8"), ctx, hashlib.sha256).hexdigest()
                expected = hmac.new(token.encode("utf-8"), candidate.encode("utf-8"), hashlib.sha256).hexdigest()
                if hmac.compare_digest(expected, announced_hmac):
                    anchor = token
                    break
            if anchor is None or candidate == primary_token or candidate in self._accepted:
                return False

        if anchor == primary_token:
            self.set_primary(candidate)
        else:
            self.adopt_token(candidate, version=0, issued_at=float(announced_at))
        with self._lock:
            self._announcement = dict(announcement)
        return True

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

    def to_gossip_snapshot(self) -> dict[str, Any]:
        """Secret-free view for the wire (WO4.0.0-019): digests + versions.

        Gossip snapshots used to ship every accepted token verbatim — any
        holder of ONE stale-but-accepted token could fetch the primary
        forever. Digests let peers verify shared trust without exchanging
        secret material. WO5.0.0-030 adds rotation announcements: the snapshot
        carries the keyed digest ``HMAC(old_primary, new_primary)`` plus public
        timing fields — never the new token itself. Peers re-derive the new
        primary from a token they already hold (see ``derive_rotation_token``)
        and verify it against the announced keyed digest.
        """
        with self._lock:
            return {
                "primary": {
                    "digest": token_digest(self._primary.token),
                    "version": self._primary.version,
                    "issued_at": self._primary.issued_at,
                }
                if self._primary
                else None,
                "accepted": [
                    {
                        "digest": token_digest(info.token),
                        "version": info.version,
                        "issued_at": info.issued_at,
                    }
                    for info in self._accepted.values()
                ],
                "announcement": dict(self._announcement) if self._announcement else None,
            }

    def accepted_digests(self) -> set[str]:
        with self._lock:
            return {token_digest(token) for token in self._accepted}

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


__all__ = ["ClusterTokenStore", "TokenInfo", "derive_rotation_token", "token_digest", "token_grace_seconds"]
