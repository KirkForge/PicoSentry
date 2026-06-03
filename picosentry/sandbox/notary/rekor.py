"""Rekor transparency log notary integration.

Submits audit entries to a Rekor transparency log for external, tamper-evident
verification. Falls back gracefully when offline — PicoDome must never crash
or block because an external service is unavailable.

Key design:
- HMAC-SHA256 signs every entry before submission (local integrity anchor).
- Rekor provides the external, append-only verification layer.
- All HTTP calls use a configurable timeout (default 10s).
- ``NullNotary`` is used in air-gapped/offline mode — records are signed
  locally but never submitted externally.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os as _os
import secrets as _secrets
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

try:
    import urllib.error
    import urllib.request

    _HAS_URLLIB = True
except ImportError:  # pragma: no cover
    _HAS_URLLIB = False

logger = logging.getLogger("picodome.notary")

# ─── Defaults ────────────────────────────────────────────────────────────────

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
DEFAULT_TIMEOUT_SECONDS = 10

# Generate a per-process random key if not configured via env var.
# WARNING: This key is different across process restarts. For persistent
# verification, set PICODOME_NOTARY_HMAC_KEY in your environment.
_process_hmac_key: str = _os.environ.get(
    "PICODOME_NOTARY_HMAC_KEY",
    f"picodome-local-{_secrets.token_hex(16)}",
)
DEFAULT_HMAC_KEY = _process_hmac_key

# ─── Exceptions ─────────────────────────────────────────────────────────────


class NotaryError(Exception):
    """Base exception for notary operations."""


class NotaryTimeoutError(NotaryError):
    """Raised when a notary HTTP call exceeds the timeout."""


class NotaryConnectionError(NotaryError):
    """Raised when the notary cannot connect to the transparency log."""


class NotaryVerificationError(NotaryError):
    """Raised when entry verification fails."""


# ─── HMAC-SHA256 Signing ────────────────────────────────────────────────────


def sign_entry(entry: dict[str, Any], key: str = DEFAULT_HMAC_KEY) -> str:
    """Sign an audit entry dict with HMAC-SHA256.

    The entry is canonicalised as sorted JSON before signing to ensure
    deterministic signatures regardless of dict insertion order.

    Args:
        entry: The audit event dict to sign.
        key: HMAC key (default: built-in key; override in production).

    Returns:
        Hex-encoded HMAC-SHA256 digest.
    """
    canonical = json.dumps(entry, sort_keys=True, default=str)
    return hmac.new(
        key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_entry_signature(
    entry: dict[str, Any],
    signature: str,
    key: str = DEFAULT_HMAC_KEY,
) -> bool:
    """Verify an HMAC-SHA256 signature against an audit entry.

    Args:
        entry: The audit event dict.
        signature: The hex-encoded HMAC-SHA256 digest to verify.
        key: HMAC key used for verification.

    Returns:
        True if the signature matches, False otherwise.
    """
    expected = sign_entry(entry, key=key)
    return hmac.compare_digest(expected, signature)


# ─── Data Models ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class NotaryResult:
    """Result of a notary submission."""

    uuid: str
    entry: dict[str, Any]
    hmac_signature: str
    submitted_at: str = ""
    rekor_uuid: str = ""


# ─── AuditNotary ABC ────────────────────────────────────────────────────────


class AuditNotary(ABC):
    """Abstract base class for audit notary backends.

    The notary provides two functions:
    1. Local HMAC-SHA256 signing of every entry (always available).
    2. External transparency log submission (optional, network-dependent).
    """

    @abstractmethod
    def submit_entry(self, entry: dict[str, Any]) -> str:
        """Submit an audit entry to the notary.

        Args:
            entry: The audit event dict to notarize.

        Returns:
            A UUID identifying this notarized entry. For ``NullNotary``,
            this is a locally-generated UUID. For ``RekorNotary``, this
            is the Rekor transparency log UUID.
        """

    @abstractmethod
    def verify_entry(self, uuid: str, entry: dict[str, Any]) -> bool:
        """Verify an entry against the notary.

        Args:
            uuid: The UUID returned by ``submit_entry``.
            entry: The audit event dict to verify.

        Returns:
            True if the entry is verified, False otherwise.
        """

    @abstractmethod
    def get_proof(self, uuid: str) -> dict[str, Any]:
        """Retrieve a transparency proof for a notarized entry.

        Args:
            uuid: The UUID returned by ``submit_entry``.

        Returns:
            A dict containing the proof data. For ``NullNotary``, this
            contains only the local HMAC signature. For ``RekorNotary``,
            this includes the inclusion proof from the Merkle tree.
        """


# ─── NullNotary (offline/air-gapped) ────────────────────────────────────────


class NullNotary(AuditNotary):
    """No-op notary for offline/air-gapped environments.

    Signs entries locally with HMAC-SHA256 but never submits to an
    external service. Useful when Rekor is unavailable or when running
    in an air-gapped environment.
    """

    def __init__(self, hmac_key: str = DEFAULT_HMAC_KEY) -> None:
        self._hmac_key = hmac_key
        self._entries: dict[str, dict[str, Any]] = {}
        if not _os.environ.get("PICODOME_NOTARY_HMAC_KEY"):
            logger.warning(
                "NullNotary: Using process-local HMAC key. Set PICODOME_NOTARY_HMAC_KEY for persistent verification."
            )

    def submit_entry(self, entry: dict[str, Any]) -> str:
        """Sign entry locally and store it. No network call.

        Returns a locally-generated UUID.
        """
        entry_uuid = str(uuid.uuid4())
        signature = sign_entry(entry, key=self._hmac_key)
        self._entries[entry_uuid] = {
            "entry": entry,
            "hmac_signature": signature,
            "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "notary": "null",
        }
        logger.debug("NullNotary: signed entry %s locally", entry_uuid[:8])
        return entry_uuid

    def verify_entry(self, uuid: str, entry: dict[str, Any]) -> bool:
        """Verify entry against local HMAC signature."""
        record = self._entries.get(uuid)
        if record is None:
            logger.warning("NullNotary: entry %s not found", uuid[:8])
            return False

        stored_entry = record["entry"]
        stored_sig = record["hmac_signature"]

        # Verify the entry content matches what was stored
        if json.dumps(stored_entry, sort_keys=True, default=str) != json.dumps(entry, sort_keys=True, default=str):
            logger.warning("NullNotary: entry content mismatch for %s", uuid[:8])
            return False

        # Verify HMAC signature
        return verify_entry_signature(entry, stored_sig, key=self._hmac_key)

    def get_proof(self, uuid: str) -> dict[str, Any]:
        """Return local proof (HMAC signature only, no Merkle proof)."""
        record = self._entries.get(uuid)
        if record is None:
            return {"error": f"Entry {uuid} not found"}

        return {
            "uuid": uuid,
            "notary": "null",
            "hmac_signature": record["hmac_signature"],
            "submitted_at": record["submitted_at"],
            "note": "No external transparency proof — NullNotary mode",
        }


# ─── RekorNotary (Sigstore transparency log) ───────────────────────────────


class RekorNotary(AuditNotary):
    """Rekor transparency log notary.

    Submits audit entries to a Rekor transparency log for external,
    tamper-evident verification. Falls back to local HMAC signing when
    Rekor is unavailable.

    All HTTP calls are timeout-bounded (default 10s). Network errors are
    caught and logged — PicoDome never crashes because Rekor is down.
    """

    def __init__(
        self,
        rekor_url: str = DEFAULT_REKOR_URL,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        hmac_key: str = DEFAULT_HMAC_KEY,
    ) -> None:
        self._rekor_url = rekor_url.rstrip("/")
        self._timeout = timeout
        self._hmac_key = hmac_key
        self._entries: dict[str, dict[str, Any]] = {}
        if not _os.environ.get("PICODOME_NOTARY_HMAC_KEY"):
            logger.warning(
                "RekorNotary: Using process-local HMAC key. Set PICODOME_NOTARY_HMAC_KEY for persistent verification."
            )

    def submit_entry(self, entry: dict[str, Any]) -> str:
        """Submit an audit entry to the Rekor transparency log.

        First signs locally with HMAC-SHA256, then attempts to submit
        to Rekor. If Rekor is unavailable, returns a local UUID and
        logs a warning — does not raise.

        Returns:
            Rekor UUID on success, or local UUID on failure.
        """
        # Always sign locally first
        hmac_signature = sign_entry(entry, key=self._hmac_key)

        # Attempt Rekor submission
        try:
            rekor_uuid = self._submit_to_rekor(entry, hmac_signature)
            self._entries[rekor_uuid] = {
                "entry": entry,
                "hmac_signature": hmac_signature,
                "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "notary": "rekor",
                "rekor_uuid": rekor_uuid,
            }
            logger.info("RekorNotary: submitted entry %s to Rekor", rekor_uuid[:8])
            return rekor_uuid
        except NotaryError as exc:
            # Rekor unavailable — fall back to local UUID
            local_uuid = str(uuid.uuid4())
            self._entries[local_uuid] = {
                "entry": entry,
                "hmac_signature": hmac_signature,
                "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "notary": "rekor-fallback",
                "error": str(exc),
            }
            logger.warning(
                "RekorNotary: Rekor unavailable (%s), using local UUID %s",
                exc,
                local_uuid[:8],
            )
            return local_uuid

    def verify_entry(self, uuid: str, entry: dict[str, Any]) -> bool:
        """Verify an entry against the notary.

        Checks both local HMAC signature and (if available) the Rekor
        transparency log.
        """
        record = self._entries.get(uuid)
        if record is None:
            # Try to look up in Rekor
            try:
                return self._verify_in_rekor(uuid, entry)
            except NotaryError:
                logger.warning("RekorNotary: cannot verify unknown UUID %s — Rekor unavailable", uuid[:8])
                return False

        stored_entry = record["entry"]
        stored_sig = record["hmac_signature"]

        # Verify local HMAC first
        if not verify_entry_signature(entry, stored_sig, key=self._hmac_key):
            logger.warning("RekorNotary: HMAC verification failed for %s", uuid[:8])
            return False

        # Verify content matches
        if json.dumps(stored_entry, sort_keys=True, default=str) != json.dumps(entry, sort_keys=True, default=str):
            logger.warning("RekorNotary: entry content mismatch for %s", uuid[:8])
            return False

        # If we have a Rekor UUID, try to verify against Rekor too
        rekor_uuid = record.get("rekor_uuid")
        if rekor_uuid and record.get("notary") == "rekor":
            try:
                return self._verify_in_rekor(rekor_uuid, entry)
            except NotaryError:
                # Rekor unavailable — local HMAC is sufficient
                logger.warning("RekorNotary: Rekor unavailable for verification of %s", uuid[:8])
                return True  # Local HMAC passed

        return True

    def get_proof(self, uuid: str) -> dict[str, Any]:
        """Retrieve a transparency proof for a notarized entry.

        Returns both the local HMAC signature and, if available, the
        Rekor inclusion proof.
        """
        record = self._entries.get(uuid)
        if record is None:
            # Try Rekor directly
            try:
                return self._get_rekor_proof(uuid)
            except NotaryError:
                return {"error": f"Entry {uuid} not found locally or in Rekor"}

        proof: dict[str, Any] = {
            "uuid": uuid,
            "notary": record.get("notary", "unknown"),
            "hmac_signature": record["hmac_signature"],
            "submitted_at": record["submitted_at"],
        }

        # If we have a Rekor UUID, try to get the Merkle proof
        rekor_uuid = record.get("rekor_uuid")
        if rekor_uuid and record.get("notary") == "rekor":
            try:
                rekor_proof = self._get_rekor_proof(rekor_uuid)
                proof["rekor_proof"] = rekor_proof
            except NotaryError:
                proof["rekor_proof"] = {"error": "Rekor unavailable"}

        return proof

    # ── Internal HTTP methods ───────────────────────────────────────────

    def _submit_to_rekor(self, entry: dict[str, Any], hmac_signature: str) -> str:
        """Submit an entry to the Rekor API.

        Uses urllib (no requests dependency) with timeout bounding.

        Raises:
            NotaryTimeoutError: If the request exceeds the timeout.
            NotaryConnectionError: If the connection fails.
        """
        if not _HAS_URLLIB:
            raise NotaryConnectionError("urllib not available")

        url = f"{self._rekor_url}/api/v1/log/entries"
        payload = {
            "kind": "intoto",
            "apiVersion": "0.0.1",
            "spec": {
                "content": {
                    "envelope": json.dumps(entry, sort_keys=True, default=str),
                },
                "signature": {
                    "keyid": "picodome-hmac",
                    "sig": hmac_signature,
                },
            },
        }

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status == 201:
                    data = json.loads(resp.read().decode("utf-8"))
                    # Rekor returns a dict with UUID keys
                    uuids = list(data.keys())
                    if uuids:
                        return uuids[0]
                    # Fallback: generate local UUID
                    return str(uuid.uuid4())
                else:
                    raise NotaryConnectionError(f"Rekor returned status {resp.status}")
        except NotaryError:
            raise
        except urllib.error.URLError as exc:
            if "timed out" in str(exc).lower():
                raise NotaryTimeoutError(f"Rekor request timed out: {exc}") from exc
            raise NotaryConnectionError(f"Rekor connection error: {exc}") from exc
        except TimeoutError:
            raise NotaryTimeoutError(f"Rekor request timed out after {self._timeout}s") from None
        except Exception as exc:
            raise NotaryConnectionError(f"Rekor submission error: {exc}") from exc

    def _verify_in_rekor(self, uuid: str, entry: dict[str, Any]) -> bool:
        """Verify an entry in the Rekor transparency log.

        Raises:
            NotaryError: If verification cannot be performed.
        """
        if not _HAS_URLLIB:
            raise NotaryConnectionError("urllib not available")

        url = f"{self._rekor_url}/api/v1/log/entries/{uuid}"

        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    # Verify the body content matches
                    body_content = data.get("body", {})
                    if isinstance(body_content, dict):
                        stored = body_content.get("content", {}).get("envelope", "")
                        current = json.dumps(entry, sort_keys=True, default=str)
                        return stored == current
                    return True  # Entry exists in Rekor
                return False
        except NotaryError:
            raise
        except urllib.error.URLError as exc:
            if "timed out" in str(exc).lower():
                raise NotaryTimeoutError(f"Rekor verification timed out: {exc}") from exc
            raise NotaryConnectionError(f"Rekor connection error: {exc}") from exc
        except TimeoutError:
            raise NotaryTimeoutError(f"Rekor verification timed out after {self._timeout}s") from None
        except Exception as exc:
            raise NotaryConnectionError(f"Rekor verification error: {exc}") from exc

    def _get_rekor_proof(self, uuid: str) -> dict[str, Any]:
        """Get a Merkle inclusion proof from Rekor.

        Raises:
            NotaryError: If the proof cannot be retrieved.
        """
        if not _HAS_URLLIB:
            raise NotaryConnectionError("urllib not available")

        url = f"{self._rekor_url}/api/v1/log/entries/{uuid}"

        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
                raise NotaryError(f"Rekor returned status {resp.status}")
        except NotaryError:
            raise
        except urllib.error.URLError as exc:
            if "timed out" in str(exc).lower():
                raise NotaryTimeoutError(f"Rekor proof retrieval timed out: {exc}") from exc
            raise NotaryConnectionError(f"Rekor connection error: {exc}") from exc
        except TimeoutError:
            raise NotaryTimeoutError(f"Rekor proof retrieval timed out after {self._timeout}s") from None
        except Exception as exc:
            raise NotaryConnectionError(f"Rekor proof retrieval error: {exc}") from exc


# ─── Module-level default notary ─────────────────────────────────────────────


_default_notary_lock = threading.Lock()
_default_notary: AuditNotary | None = None


def get_default_notary() -> AuditNotary:
    """Get the global default notary (lazy init, defaults to NullNotary).

    The default is ``NullNotary`` because PicoDome must work offline.
    Users who want Rekor integration should call ``set_default_notary()``
    with a ``RekorNotary`` instance.
    """
    global _default_notary
    if _default_notary is None:
        with _default_notary_lock:
            if _default_notary is None:
                _default_notary = NullNotary()
    return _default_notary


def set_default_notary(notary: AuditNotary) -> None:
    """Set the global default notary.

    Args:
        notary: An AuditNotary instance (NullNotary or RekorNotary).
    """
    global _default_notary
    _default_notary = notary
