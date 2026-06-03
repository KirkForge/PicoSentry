"""PicoDome Notary — external audit transparency log integration.

Provides an optional layer of external verification for audit log entries
using Rekor (Sigstore's transparency log). When the notary is unavailable
(e.g., air-gapped/offline environments), PicoDome continues to operate
normally — the notary never blocks or crashes the system.

Architecture:
- ``AuditNotary`` ABC defines the contract (submit, verify, get_proof).
- ``RekorNotary`` talks to a Rekor transparency log API (network-dependent).
- ``NullNotary`` is a no-op for offline/air-gapped mode.
- HMAC-SHA256 signing of entries before submission for local integrity.
- All network calls are timeout-bounded (default 10s).
"""

from __future__ import annotations

from picosentry.sandbox.notary.rekor import (
    AuditNotary,
    NotaryConnectionError,
    NotaryError,
    NotaryTimeoutError,
    NotaryVerificationError,
    NullNotary,
    RekorNotary,
    get_default_notary,
    set_default_notary,
    sign_entry,
    verify_entry_signature,
)

__all__ = [
    "AuditNotary",
    "NullNotary",
    "RekorNotary",
    "NotaryError",
    "NotaryTimeoutError",
    "NotaryConnectionError",
    "NotaryVerificationError",
    "get_default_notary",
    "set_default_notary",
    "sign_entry",
    "verify_entry_signature",
]
