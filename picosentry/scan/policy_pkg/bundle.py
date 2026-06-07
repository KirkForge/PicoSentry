"""Signed policy bundle export/import.

Extracted in v2.1.0 (refactor) from ``picosentry/scan/policy.py``.

Wraps a :class:`~picosentry.scan.policy_pkg.engine.Policy` in a JSON bundle
with a digest, optional cryptographic signature, and re-imports/verifies it.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from picosentry.scan.audit import audit
from picosentry.scan.crypto import (
    SignatureBundle,
    read_detached_signature,
    sign_content,
    verify_content,
    write_detached_signature,
)
from picosentry.scan.policy_pkg.engine import Policy

logger = logging.getLogger("picosentry.policy")


def export_signed_policy(
    policy: Policy,
    output_path: Path,
    signer: str = "",
    sign_method: str = "",
    sign_secret_key: str = "",
    sign_password: str = "",
) -> str:
    """Export a policy as a signed JSON bundle for org-wide distribution.

    The bundle includes the policy content plus a signature block with
    signer identity, digest, and timestamp. Teams can import signed
    policies and verify they haven't been tampered with.

    Args:
        policy: The Policy to export.
        output_path: Where to write the bundle.
        signer: Identity string (email, key ID, team name).
        sign_method: If set, cryptographically sign ("sigstore" or "minisign").
        sign_secret_key: Path to minisign secret key (minisign only).
        sign_password: Password for minisign secret key.

    Returns:
        Bundle digest string.
    """
    policy_dict = policy.to_dict()
    # Canonical JSON — no whitespace, sorted keys, same as importer uses
    policy_json = json.dumps(policy_dict, sort_keys=True, separators=(",", ":"))
    digest = f"sha256:{hashlib.sha256(policy_json.encode()).hexdigest()[:32]}"
    # Pretty-print for the file (human-readable bundle)
    pretty_json = json.dumps(policy_dict, sort_keys=True, indent=2)

    bundle = {
        "bundle_format": "1.0",
        "digest": digest,
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "signer": signer or "unsigned",
        "policy": policy_dict,
    }

    pretty_json = json.dumps(bundle, sort_keys=True, indent=2)
    output_path.write_text(pretty_json, encoding="utf-8")

    # Cryptographically sign the bundle if requested
    if sign_method:
        try:
            canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
            sig = sign_content(canonical.encode("utf-8"), sign_method, sign_secret_key, sign_password)
            write_detached_signature(sig, output_path)
            bundle["_crypto"] = sig.to_dict()
            logger.info(
                "Policy bundle cryptographically signed: provider=%s, identity=%s", sig.provider, sig.signer_identity
            )
        except ImportError as e:
            logger.warning("Cryptographic signing skipped: %s", e)
        except Exception as e:
            logger.error("Cryptographic signing failed: %s", e)

    logger.info("Exported signed policy bundle: %s (digest=%s)", output_path, digest)
    return digest


def import_policy_bundle(
    path: Path,
    verify: bool = True,
    verify_crypto: bool = False,
    public_key: str = "",
    offline: bool = False,
) -> Policy:
    """Import a signed policy bundle.

    Args:
        path: Path to the bundle JSON file.
        verify: If True, verify the digest.
        verify_crypto: If True, verify cryptographic signature.
        public_key: Path to minisign public key (minisign only).
        offline: If True, use offline Sigstore verification.

    Returns:
        The imported Policy.

    Raises:
        ValueError: If the bundle is invalid or verification fails.
    """
    import hashlib

    data = json.loads(path.read_text(encoding="utf-8"))

    if "policy" not in data:
        raise ValueError("Invalid policy bundle: missing 'policy' key")

    if verify and "digest" in data:
        policy_json = json.dumps(data["policy"], sort_keys=True, separators=(",", ":"))
        actual = f"sha256:{hashlib.sha256(policy_json.encode()).hexdigest()[:32]}"
        if data["digest"] != actual:
            raise ValueError(f"Policy bundle digest mismatch: expected={data['digest']} actual={actual}")

    # Verify cryptographic signature if requested
    if verify_crypto:
        sig_data = read_detached_signature(path)
        if sig_data is None:
            # Try embedded signature in bundle
            crypto_data = data.get("_crypto")
            if crypto_data and isinstance(crypto_data, dict):
                sig_data = SignatureBundle.from_dict(crypto_data)

        if sig_data is None:
            raise ValueError(
                "Cryptographic verification requested but no signature found. Use verify_crypto=False to skip."
            )

        if not sig_data.is_signed():
            raise ValueError(
                f"Policy bundle is not cryptographically signed "
                f"(provider={sig_data.provider}). Use verify_crypto=False to skip."
            )

        # Canonicalize the policy dict for verification
        canonical = json.dumps(data["policy"], sort_keys=True, separators=(",", ":"))
        try:
            ok = verify_content(
                canonical.encode("utf-8"),
                sig_data,
                public_key=public_key,
                offline=offline,
            )
            if not ok:
                raise ValueError(
                    "Cryptographic signature verification FAILED for policy bundle. "
                    "The bundle may have been tampered with."
                )
            logger.info(
                "Cryptographic signature verified: provider=%s, identity=%s",
                sig_data.provider,
                sig_data.signer_identity,
            )
        except ImportError as e:
            logger.warning("Cannot verify cryptographic signature: %s", e)
        except Exception as e:
            if "VerificationError" in type(e).__name__ or "FAILED" in str(e):
                raise
            raise ValueError(f"Cryptographic verification error: {e}") from e

    policy = Policy.from_dict(data["policy"])
    logger.info(
        "Imported policy bundle: signed by %s at %s",
        data.get("signer", "unsigned"),
        data.get("signed_at", "unknown"),
    )
    audit(
        "policy.import_bundle",
        target=str(path),
        metadata={
            "policy_digest": policy.digest,
            "signer": data.get("signer", "unsigned"),
            "signed_at": data.get("signed_at", "unknown"),
            "verified": verify,
        },
    )
    return policy


__all__ = ["export_signed_policy", "import_policy_bundle"]
