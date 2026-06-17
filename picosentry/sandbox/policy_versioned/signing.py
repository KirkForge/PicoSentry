
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

    algorithm: str
    signature: str
    timestamp: str
    key_id: str = "default"


@dataclass
class VerifyResult:

    valid: bool
    algorithm: str = ""
    key_id: str = ""
    timestamp: str = ""
    error: str = ""


def load_key() -> bytes | None:

    hex_key = os.environ.get("PICODOME_POLICY_KEY")
    if hex_key:
        try:
            return bytes.fromhex(hex_key)
        except ValueError:
            logger.exception("PICODOME_POLICY_KEY is not valid hex")
            return None


    key_file = os.environ.get("PICODOME_POLICY_KEY_FILE")
    if key_file:
        try:
            content = Path(key_file).read_text().strip()
            return bytes.fromhex(content)
        except (OSError, ValueError) as exc:
            logger.exception("Failed to read policy key file '%s': %s", key_file, exc)
            return None


    if os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes"):
        logger.error(
            "ENTERPRISE MODE: No policy signing key configured. Set PICODOME_POLICY_KEY or PICODOME_POLICY_KEY_FILE."
        )
        return None

    return None


_load_key = load_key


def generate_key() -> bytes:
    return os.urandom(32)


def key_to_hex(key: bytes) -> str:
    return key.hex()


def sign_policy(content: str, key: bytes, key_id: str = "default") -> str:

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
    content = path.read_text(encoding="utf-8")

    content = strip_signature(content)
    signed = sign_policy(content, key, key_id=key_id)
    path.write_text(signed, encoding="utf-8")
    logger.info("Signed policy file: %s", path)


def parse_signature(content: str) -> PolicySignature | None:
    lines = content.split("\n")
    marker_idx = None
    for i, line in enumerate(lines):
        if line.strip() == SIGNATURE_MARKER.strip():
            marker_idx = i
            break

    if marker_idx is None:
        return None


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
    lines = content.split("\n")
    marker_idx = None
    for i, line in enumerate(lines):
        if line.strip() == SIGNATURE_MARKER.strip():
            marker_idx = i
            break

    if marker_idx is None:
        return content


    policy_lines = lines[:marker_idx]

    while policy_lines and not policy_lines[-1].strip():
        policy_lines.pop()

    return "\n".join(policy_lines) + "\n"


def verify_policy(content: str, key: bytes, key_id: str = "default") -> VerifyResult:
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


    policy_content = strip_signature(content)


    expected_sig = hmac.new(key, policy_content.encode("utf-8"), hashlib.sha256).hexdigest()


    if hmac.compare_digest(expected_sig, parsed.signature):
        return VerifyResult(
            valid=True,
            algorithm=parsed.algorithm,
            key_id=parsed.key_id,
            timestamp=parsed.timestamp,
        )
    return VerifyResult(
        valid=False,
        algorithm=parsed.algorithm,
        key_id=parsed.key_id,
        error="signature mismatch — policy may have been tampered with",
    )


def verify_policy_file(path: Path, key: bytes, key_id: str = "default") -> VerifyResult:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        return VerifyResult(valid=False, error=f"cannot read file: {exc}")

    return verify_policy(content, key, key_id=key_id)


def load_policy_with_verification(
    path: Path, key: bytes | None = None, key_id: str = "default"
) -> tuple[str, VerifyResult | None]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        return "", VerifyResult(valid=False, error=f"cannot read file: {exc}")


    effective_key = key or _load_key()

    parsed = parse_signature(content)
    if parsed is None:

        if effective_key is not None:
            logger.warning(
                "Policy %s is unsigned but verification key is configured — rejecting unsigned policy",
                path,
            )
            return "", VerifyResult(valid=False, error="policy is unsigned but key is configured")
        logger.debug("Policy %s is unsigned (no verification key)", path)
        return content, None


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


def sign_policy_companion(path: Path, key: bytes, key_id: str = "default") -> Path:
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
    effective_key = key or _load_key()
    sig_path = path.with_suffix(path.suffix + ".sig")
    has_sig = sig_path.is_file()

    if not has_sig and effective_key is None:

        logger.debug("Policy %s has no signature and no verification key", path)
        content = path.read_text(encoding="utf-8")
        return content, None

    if not has_sig and effective_key is not None:

        logger.warning("Policy %s is unsigned but verification key is configured — rejecting", path)
        return "", VerifyResult(valid=False, error="policy is unsigned but key is configured")

    if has_sig and effective_key is None:

        logger.warning("Policy %s is signed but no verification key configured — loading without verification", path)
        content = path.read_text(encoding="utf-8")
        return content, VerifyResult(valid=False, error="no verification key configured for signed policy")


    assert effective_key is not None
    result = verify_policy_companion(path, effective_key, key_id=key_id)
    if not result.valid:
        logger.error("Policy %s signature verification FAILED: %s", path, result.error)
        return "", result

    logger.info("Policy %s signature verified (key_id=%s)", path, result.key_id)
    content = path.read_text(encoding="utf-8")
    return content, result
