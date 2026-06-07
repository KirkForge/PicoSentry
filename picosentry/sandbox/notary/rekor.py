
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


DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
DEFAULT_TIMEOUT_SECONDS = 10


_process_hmac_key: str = _os.environ.get(
    "PICODOME_NOTARY_HMAC_KEY",
    f"picodome-local-{_secrets.token_hex(16)}",
)
DEFAULT_HMAC_KEY = _process_hmac_key


class NotaryError(Exception):
    """Base exception for notary operations."""


class NotaryTimeoutError(NotaryError):
    """Raised when a notary HTTP call exceeds the timeout."""


class NotaryConnectionError(NotaryError):
    """Raised when the notary cannot connect to the transparency log."""


class NotaryVerificationError(NotaryError):
    """Raised when entry verification fails."""


def sign_entry(entry: dict[str, Any], key: str = DEFAULT_HMAC_KEY) -> str:
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
    expected = sign_entry(entry, key=key)
    return hmac.compare_digest(expected, signature)


@dataclass(frozen=True)
class NotaryResult:

    uuid: str
    entry: dict[str, Any]
    hmac_signature: str
    submitted_at: str = ""
    rekor_uuid: str = ""


class AuditNotary(ABC):

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


class NullNotary(AuditNotary):

    def __init__(self, hmac_key: str = DEFAULT_HMAC_KEY) -> None:
        self._hmac_key = hmac_key
        self._entries: dict[str, dict[str, Any]] = {}
        if not _os.environ.get("PICODOME_NOTARY_HMAC_KEY"):
            logger.warning(
                "NullNotary: Using process-local HMAC key. Set PICODOME_NOTARY_HMAC_KEY for persistent verification."
            )

    def submit_entry(self, entry: dict[str, Any]) -> str:
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
        record = self._entries.get(uuid)
        if record is None:
            logger.warning("NullNotary: entry %s not found", uuid[:8])
            return False

        stored_entry = record["entry"]
        stored_sig = record["hmac_signature"]


        if json.dumps(stored_entry, sort_keys=True, default=str) != json.dumps(entry, sort_keys=True, default=str):
            logger.warning("NullNotary: entry content mismatch for %s", uuid[:8])
            return False


        return verify_entry_signature(entry, stored_sig, key=self._hmac_key)

    def get_proof(self, uuid: str) -> dict[str, Any]:
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


class RekorNotary(AuditNotary):

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

        hmac_signature = sign_entry(entry, key=self._hmac_key)


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
        record = self._entries.get(uuid)
        if record is None:

            try:
                return self._verify_in_rekor(uuid, entry)
            except NotaryError:
                logger.warning("RekorNotary: cannot verify unknown UUID %s — Rekor unavailable", uuid[:8])
                return False

        stored_entry = record["entry"]
        stored_sig = record["hmac_signature"]


        if not verify_entry_signature(entry, stored_sig, key=self._hmac_key):
            logger.warning("RekorNotary: HMAC verification failed for %s", uuid[:8])
            return False


        if json.dumps(stored_entry, sort_keys=True, default=str) != json.dumps(entry, sort_keys=True, default=str):
            logger.warning("RekorNotary: entry content mismatch for %s", uuid[:8])
            return False


        rekor_uuid = record.get("rekor_uuid")
        if rekor_uuid and record.get("notary") == "rekor":
            try:
                return self._verify_in_rekor(rekor_uuid, entry)
            except NotaryError:

                logger.warning("RekorNotary: Rekor unavailable for verification of %s", uuid[:8])
                return True  # Local HMAC passed

        return True

    def get_proof(self, uuid: str) -> dict[str, Any]:
        record = self._entries.get(uuid)
        if record is None:

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


        rekor_uuid = record.get("rekor_uuid")
        if rekor_uuid and record.get("notary") == "rekor":
            try:
                rekor_proof = self._get_rekor_proof(rekor_uuid)
                proof["rekor_proof"] = rekor_proof
            except NotaryError:
                proof["rekor_proof"] = {"error": "Rekor unavailable"}

        return proof


    def _submit_to_rekor(self, entry: dict[str, Any], hmac_signature: str) -> str:
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

                    uuids = list(data.keys())
                    if uuids:
                        return uuids[0]

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
        if not _HAS_URLLIB:
            raise NotaryConnectionError("urllib not available")

        url = f"{self._rekor_url}/api/v1/log/entries/{uuid}"

        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))

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


_default_notary_lock = threading.Lock()
_default_notary: AuditNotary | None = None


def get_default_notary() -> AuditNotary:
    global _default_notary
    if _default_notary is None:
        with _default_notary_lock:
            if _default_notary is None:
                _default_notary = NullNotary()
    return _default_notary


def set_default_notary(notary: AuditNotary) -> None:
    global _default_notary
    _default_notary = notary
