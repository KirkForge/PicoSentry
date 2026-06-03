"""Policy signing and verification using HMAC-SHA256.

Signed policies are YAML files with an appended signature block:

.. code-block:: yaml

    rules:
      - name: deny-shells
        pattern: "*/sh"
        action: deny

    # --- PICODOME SIGNATURE ---
    # algorithm: hmac-sha256
    # signature: <hex-encoded HMAC>
    # timestamp: 2026-05-22T17:00:00Z
    # key_id: default

The signature is computed over all lines *above* the signature block
(i.e., the original policy content). This ensures tampering with
any part of the policy invalidates the signature.

Key management:
  - PICODOME_POLICY_KEY: hex-encoded HMAC key (preferred)
  - PICODOME_POLICY_KEY_FILE: path to file containing hex-encoded key
  - If neither is set, policies are loaded without verification (warning logged).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("picodome.policy.signing")

SIGNATURE_MARKER = "# --- PICODOME SIGNATURE ---"
SUPPORTED_ALGORITHMS = frozenset({"hmac-sha256"})


@dataclass(frozen=True)
class PolicySignature:
    """A parsed signature block from a signed policy file."""

    algorithm: str
    signature: str
    timestamp: str
    key_id: str = "default"


@dataclass
class VerifyResult:
    """Result of verifying a signed policy."""

    valid: bool
    algorithm: str = ""
    key_id: str = ""
    timestamp: str = ""
    error: str = ""


# ─── Key management ────────────────────────────────────────────────────────


def load_key() -> bytes | None:
    """Load the HMAC key from environment, file, or K8s secret mount.

    Resolution order:
        1. PICODOME_POLICY_KEY — hex-encoded key directly in env
        2. PICODOME_POLICY_KEY_FILE — path to file containing hex key
           (K8s secret mounts: mount the secret as a file and set this var)
        3. None — no key configured, policies load without verification

    F4: In enterprise mode, a key MUST be configured or an error is logged.

    For Kubernetes, create a Secret and mount it:
        kubectl create secret generic picodome-policy-key \\
            --from-literal=key=<hex-encoded-key>
        # Mount in deployment:
        #   volumeMounts:
        #     - name: policy-key
        #       mountPath: /etc/picodome/keys
        #       readOnly: true
        # Set env: PICODOME_POLICY_KEY_FILE=/etc/picodome/keys/key

    Returns:
        The HMAC key as bytes, or None if not configured.
    """
    # 1. Direct hex key in env
    hex_key = os.environ.get("PICODOME_POLICY_KEY")
    if hex_key:
        try:
            return bytes.fromhex(hex_key)
        except ValueError:
            logger.error("PICODOME_POLICY_KEY is not valid hex")
            return None

    # 2. Key file path (also covers K8s secret mounts)
    key_file = os.environ.get("PICODOME_POLICY_KEY_FILE")
    if key_file:
        try:
            content = Path(key_file).read_text().strip()
            return bytes.fromhex(content)
        except (OSError, ValueError) as exc:
            logger.error("Failed to read policy key file '%s': %s", key_file, exc)
            return None

    # F4: In enterprise mode, require policy signing key
    if os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes"):
        logger.error(
            "ENTERPRISE MODE: No policy signing key configured. Set PICODOME_POLICY_KEY or PICODOME_POLICY_KEY_FILE."
        )
        return None

    return None


# Backward compat alias
_load_key = load_key


def generate_key() -> bytes:
    """Generate a new random 32-byte HMAC key.

    Returns:
        32 bytes of cryptographically random data suitable for HMAC-SHA256.
    """
    return os.urandom(32)


def key_to_hex(key: bytes) -> str:
    """Encode an HMAC key as hex string for storage."""
    return key.hex()


# ─── Signing ───────────────────────────────────────────────────────────────


def sign_policy(content: str, key: bytes, key_id: str = "default") -> str:
    """Sign a policy file's content by appending an HMAC-SHA256 signature.

    Args:
        content: The original policy YAML content (without any signature).
        key: The HMAC key as bytes.
        key_id: Identifier for this key (for key rotation).

    Returns:
        The policy content with the signature block appended.
    """
    # Compute HMAC-SHA256 over the original content
    sig = hmac.new(key, content.encode("utf-8"), hashlib.sha256).hexdigest()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    signature_block = (
        f"\n{SIGNATURE_MARKER}\n"
        f"# algorithm: hmac-sha256\n"
        f"# signature: {sig}\n"
        f"# timestamp: {timestamp}\n"
        f"# key_id: {key_id}\n"
    )

    return content + signature_block


def sign_policy_file(path: Path, key: bytes, key_id: str = "default") -> None:
    """Sign a policy file in place by appending the signature block.

    If the file is already signed, the old signature is removed first.
    """
    content = path.read_text(encoding="utf-8")
    # Strip existing signature if present
    content = strip_signature(content)
    signed = sign_policy(content, key, key_id=key_id)
    path.write_text(signed, encoding="utf-8")
    logger.info("Signed policy file: %s", path)


# ─── Verification ──────────────────────────────────────────────────────────


def parse_signature(content: str) -> PolicySignature | None:
    """Parse the signature block from a signed policy file.

    Returns:
        PolicySignature if found, None if the file is unsigned.
    """
    lines = content.split("\n")
    marker_idx = None
    for i, line in enumerate(lines):
        if line.strip() == SIGNATURE_MARKER.strip():
            marker_idx = i
            break

    if marker_idx is None:
        return None

    # Parse signature fields after the marker
    algo = ""
    sig = ""
    timestamp = ""
    key_id = "default"

    for line in lines[marker_idx + 1 :]:
        stripped = line.strip()
        if not stripped or not stripped.startswith("#"):
            break
        stripped = stripped.lstrip("# ").strip()
        if stripped.startswith("algorithm:"):
            algo = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("signature:"):
            sig = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("timestamp:"):
            timestamp = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("key_id:"):
            key_id = stripped.split(":", 1)[1].strip()

    if not algo or not sig:
        return None

    return PolicySignature(
        algorithm=algo,
        signature=sig,
        timestamp=timestamp,
        key_id=key_id,
    )


def strip_signature(content: str) -> str:
    """Remove the signature block from a policy file, returning only the policy content."""
    lines = content.split("\n")
    marker_idx = None
    for i, line in enumerate(lines):
        if line.strip() == SIGNATURE_MARKER.strip():
            marker_idx = i
            break

    if marker_idx is None:
        return content

    # Return everything before the marker (strip trailing blank lines)
    policy_lines = lines[:marker_idx]
    # Remove trailing empty lines
    while policy_lines and not policy_lines[-1].strip():
        policy_lines.pop()

    return "\n".join(policy_lines) + "\n"


def verify_policy(content: str, key: bytes, key_id: str = "default") -> VerifyResult:
    """Verify the HMAC-SHA256 signature of a policy file.

    Args:
        content: The full policy file content (including signature block).
        key: The HMAC key as bytes.
        key_id: Expected key identifier (for key rotation).

    Returns:
        VerifyResult with valid=True if the signature matches.
    """
    parsed = parse_signature(content)
    if parsed is None:
        return VerifyResult(valid=False, error="no signature found")

    if parsed.algorithm not in SUPPORTED_ALGORITHMS:
        return VerifyResult(
            valid=False,
            algorithm=parsed.algorithm,
            error=f"unsupported algorithm: {parsed.algorithm}",
        )

    if parsed.key_id != key_id:
        return VerifyResult(
            valid=False,
            algorithm=parsed.algorithm,
            key_id=parsed.key_id,
            error=f"key_id mismatch: expected '{key_id}', got '{parsed.key_id}'",
        )

    # Extract the policy content (everything before the signature marker)
    policy_content = strip_signature(content)

    # Compute expected HMAC
    expected_sig = hmac.new(key, policy_content.encode("utf-8"), hashlib.sha256).hexdigest()

    # Constant-time comparison to prevent timing attacks
    if hmac.compare_digest(expected_sig, parsed.signature):
        return VerifyResult(
            valid=True,
            algorithm=parsed.algorithm,
            key_id=parsed.key_id,
            timestamp=parsed.timestamp,
        )
    else:
        return VerifyResult(
            valid=False,
            algorithm=parsed.algorithm,
            key_id=parsed.key_id,
            error="signature mismatch — policy may have been tampered with",
        )


def verify_policy_file(path: Path, key: bytes, key_id: str = "default") -> VerifyResult:
    """Verify a signed policy file.

    Args:
        path: Path to the policy file.
        key: The HMAC key as bytes.
        key_id: Expected key identifier.

    Returns:
        VerifyResult with valid=True if the signature is valid.
    """
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        return VerifyResult(valid=False, error=f"cannot read file: {exc}")

    return verify_policy(content, key, key_id=key_id)


def load_policy_with_verification(
    path: Path, key: bytes | None = None, key_id: str = "default"
) -> tuple[str, VerifyResult | None]:
    """Load a policy file, verifying its signature if a key is provided.

    If no key is provided and the file is signed, a warning is logged.
    If no key is provided and the file is unsigned, it loads normally.

    Args:
        path: Path to the policy file.
        key: HMAC key for verification. If None, uses PICODOME_POLICY_KEY env.
        key_id: Expected key identifier.

    Returns:
        Tuple of (policy_content, verify_result).
        verify_result is None if no verification was attempted.
    """
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        return "", VerifyResult(valid=False, error=f"cannot read file: {exc}")

    # Determine key
    effective_key = key or _load_key()

    parsed = parse_signature(content)
    if parsed is None:
        # Unsigned policy
        if effective_key is not None:
            logger.warning(
                "Policy %s is unsigned but verification key is configured — rejecting unsigned policy",
                path,
            )
            return "", VerifyResult(valid=False, error="policy is unsigned but key is configured")
        logger.debug("Policy %s is unsigned (no verification key)", path)
        return content, None

    # Signed policy
    if effective_key is None:
        logger.warning(
            "Policy %s is signed but no verification key (PICODOME_POLICY_KEY) is configured — cannot verify",
            path,
        )
        return strip_signature(content), VerifyResult(
            valid=False,
            error="no verification key configured for signed policy",
        )

    result = verify_policy(content, effective_key, key_id=key_id)
    if not result.valid:
        logger.error("Policy %s signature verification FAILED: %s", path, result.error)
        return "", result

    logger.info("Policy %s signature verified (key_id=%s)", path, result.key_id)
    return strip_signature(content), result


# ─── Companion file approach (.sig) ────────────────────────────────────────


def sign_policy_companion(path: Path, key: bytes, key_id: str = "default") -> Path:
    """Sign a policy file and write the signature to a companion .sig file.

    This is the preferred approach for JSON policy files where inline
    signatures would break parsing.

    Args:
        path: Path to the policy file (JSON or YAML).
        key: HMAC key as bytes.
        key_id: Key identifier for rotation.

    Returns:
        Path to the created .sig file.
    """
    content = path.read_text(encoding="utf-8")
    sig = hmac.new(key, content.encode("utf-8"), hashlib.sha256).hexdigest()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    sig_data = {
        "algorithm": "hmac-sha256",
        "signature": sig,
        "timestamp": timestamp,
        "key_id": key_id,
        "policy_file": path.name,
    }

    sig_path = path.with_suffix(path.suffix + ".sig")
    sig_path.write_text(json.dumps(sig_data, indent=2) + "\n", encoding="utf-8")
    logger.info("Signed policy file (companion): %s -> %s", path, sig_path)
    return sig_path


def verify_policy_companion(path: Path, key: bytes, key_id: str = "default") -> VerifyResult:
    """Verify a policy file using its companion .sig file.

    Args:
        path: Path to the policy file.
        key: HMAC key as bytes.
        key_id: Expected key identifier.

    Returns:
        VerifyResult with valid=True if the signature matches.
    """
    sig_path = path.with_suffix(path.suffix + ".sig")
    if not sig_path.is_file():
        return VerifyResult(valid=False, error="companion signature file not found")

    try:
        sig_data = json.loads(sig_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return VerifyResult(valid=False, error=f"cannot read signature file: {exc}")

    algo = sig_data.get("algorithm", "")
    stored_sig = sig_data.get("signature", "")
    stored_key_id = sig_data.get("key_id", "default")
    timestamp = sig_data.get("timestamp", "")

    if algo not in SUPPORTED_ALGORITHMS:
        return VerifyResult(valid=False, algorithm=algo, error=f"unsupported algorithm: {algo}")

    if stored_key_id != key_id:
        return VerifyResult(
            valid=False,
            algorithm=algo,
            key_id=stored_key_id,
            error=f"key_id mismatch: expected '{key_id}', got '{stored_key_id}'",
        )

    # Compute expected HMAC over the policy file content
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        return VerifyResult(valid=False, error=f"cannot read policy file: {exc}")

    expected_sig = hmac.new(key, content.encode("utf-8"), hashlib.sha256).hexdigest()

    if hmac.compare_digest(expected_sig, stored_sig):
        return VerifyResult(
            valid=True,
            algorithm=algo,
            key_id=stored_key_id,
            timestamp=timestamp,
        )
    else:
        return VerifyResult(
            valid=False,
            algorithm=algo,
            key_id=stored_key_id,
            error="signature mismatch — policy may have been tampered with",
        )


def load_policy_with_companion_verification(
    path: Path,
    key: bytes | None = None,
    key_id: str = "default",
) -> tuple[str, VerifyResult | None]:
    """Load a policy file, verifying its companion .sig file if present.

    If a key is configured and a .sig file exists, verification is required.
    If a key is configured but no .sig file exists, the policy is rejected.
    If no key is configured, the policy loads without verification.

    Args:
        path: Path to the policy file.
        key: HMAC key. If None, uses PICODOME_POLICY_KEY env.
        key_id: Expected key identifier.

    Returns:
        Tuple of (content, verify_result).
    """
    effective_key = key or _load_key()
    sig_path = path.with_suffix(path.suffix + ".sig")
    has_sig = sig_path.is_file()

    if not has_sig and effective_key is None:
        # No sig, no key — load normally
        logger.debug("Policy %s has no signature and no verification key", path)
        content = path.read_text(encoding="utf-8")
        return content, None

    if not has_sig and effective_key is not None:
        # Key configured but no sig — reject
        logger.warning("Policy %s is unsigned but verification key is configured — rejecting", path)
        return "", VerifyResult(valid=False, error="policy is unsigned but key is configured")

    if has_sig and effective_key is None:
        # Sig present but no key — can't verify, warn and load
        logger.warning("Policy %s is signed but no verification key configured — loading without verification", path)
        content = path.read_text(encoding="utf-8")
        return content, VerifyResult(valid=False, error="no verification key configured for signed policy")

    # Both sig and key present — verify
    assert effective_key is not None
    result = verify_policy_companion(path, effective_key, key_id=key_id)
    if not result.valid:
        logger.error("Policy %s signature verification FAILED: %s", path, result.error)
        return "", result

    logger.info("Policy %s signature verified (key_id=%s)", path, result.key_id)
    content = path.read_text(encoding="utf-8")
    return content, result
