from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("picosentry.crypto")


_HAS_SIGSTORE: bool | None = None


def _check_sigstore() -> bool:
    global _HAS_SIGSTORE
    if _HAS_SIGSTORE is None:
        try:
            import sigstore  # noqa: F401

            _HAS_SIGSTORE = True
        except ImportError:
            _HAS_SIGSTORE = False
            logger.debug("sigstore package not available — cryptographic signing disabled")
    return _HAS_SIGSTORE


def has_sigstore() -> bool:
    return _check_sigstore()


_HAS_MINISIGN: bool | None = None


def _check_minisign() -> bool:
    global _HAS_MINISIGN
    if _HAS_MINISIGN is None:
        import shutil

        if shutil.which("minisign"):
            _HAS_MINISIGN = True
            return _HAS_MINISIGN
        try:
            import subprocess

            result = subprocess.run(
                ["minisign", "-V"],
                capture_output=True,
                timeout=5,
                check=False,
            )

            _HAS_MINISIGN = result.returncode is not None
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            try:
                import minisign  # noqa: F401

                _HAS_MINISIGN = True
            except ImportError:
                _HAS_MINISIGN = False
    return _HAS_MINISIGN


def has_minisign() -> bool:
    return _check_minisign()


class SignatureBundle:
    def __init__(
        self,
        signer_identity: str = "",
        provider: str = "none",
        raw_signature: str = "",
        certificate: str = "",
        digest: str = "",
        signed_at: str = "",
    ) -> None:
        self.signer_identity = signer_identity
        self.provider = provider  # "sigstore", "minisign", "none"
        self.raw_signature = raw_signature  # base64-encoded signature
        self.certificate = certificate  # PEM certificate (Sigstore) or public key (minisign)
        self.digest = digest
        self.signed_at = signed_at or datetime.now(timezone.utc).isoformat()

    def is_signed(self) -> bool:
        return self.provider != "none" and bool(self.raw_signature)

    def to_dict(self) -> dict:
        return {
            "signer_identity": self.signer_identity,
            "provider": self.provider,
            "signature": self.raw_signature,
            "certificate": self.certificate,
            "digest": self.digest,
            "signed_at": self.signed_at,
        }

    @staticmethod
    def from_dict(d: dict) -> SignatureBundle:
        return SignatureBundle(
            signer_identity=d.get("signer_identity", ""),
            provider=d.get("provider", "none"),
            raw_signature=d.get("signature", ""),
            certificate=d.get("certificate", ""),
            digest=d.get("digest", ""),
            signed_at=d.get("signed_at", ""),
        )

    @staticmethod
    def unsigned(digest: str = "") -> SignatureBundle:
        return SignatureBundle(
            provider="none",
            digest=digest,
        )


def content_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def content_digest_short(content: bytes) -> str:
    return f"sha256:{content_digest(content)[:32]}"


def sign_content_sigstore(content: bytes) -> SignatureBundle:
    if not _check_sigstore():
        raise ImportError("sigstore package is required for Sigstore signing. Install with: pip install sigstore")

    import sigstore
    from sigstore.oidc import Issuer, detect_credential

    digest = content_digest(content)

    try:
        token = detect_credential()
        issuer = Issuer.production()  # sigstore.dev (public good instance)
    except Exception:
        token = detect_credential()
        issuer = Issuer.production()

    identity = token.identity() if hasattr(token, "identity") else "unknown"

    signing_result = sigstore.sign(
        content,
        identity_token=token,
        issuer=issuer,
    )

    logger.info("Signed content with Sigstore (identity=%s, digest=%s...)", identity, digest[:12])

    return SignatureBundle(
        signer_identity=identity,
        provider="sigstore",
        raw_signature=signing_result.bundle._to_b64()
        if hasattr(signing_result.bundle, "_to_b64")
        else str(signing_result.bundle),
        certificate=getattr(signing_result, "certificate", ""),
        digest=digest,
    )


def sign_content_minisign(content: bytes, secret_key: str, password: str = "") -> SignatureBundle:
    if not _check_minisign():
        raise ImportError(
            "minisign is required for minisign signing. Install with: apt install minisign  or  pip install minisign"
        )

    import base64
    import subprocess
    import tempfile

    digest = content_digest(content)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(content)
        tmp_path = tf.name

    try:
        cmd = ["minisign", "-S", "-s", secret_key, "-m", str(tmp_path)]
        if password:
            cmd.extend(["-p", password])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(f"minisign signing failed: {result.stderr}")

        sig_path = Path(str(tmp_path) + ".minisig")
        signature_b64 = base64.b64encode(sig_path.read_bytes()).decode()
        sig_path.unlink(missing_ok=True)

        try:
            subprocess.run(
                ["minisign", "-G", "-p", "-"],  # won't work for this
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            signer = "minisign-key"
        except Exception:
            signer = "minisign-key"

        logger.info("Signed content with minisign (key=%s, digest=%s...)", secret_key, digest[:12])

        return SignatureBundle(
            signer_identity=signer,
            provider="minisign",
            raw_signature=signature_b64,
            certificate="",  # minisign embeds key info in signature
            digest=digest,
        )

    finally:
        Path(tmp_path).unlink(missing_ok=True)


def sign_content(content: bytes, method: str = "sigstore", secret_key: str = "", password: str = "") -> SignatureBundle:
    if method == "sigstore":
        try:
            return sign_content_sigstore(content)
        except ImportError as e:
            logger.warning("Sigstore not available: %s", e)
            raise
    elif method == "minisign":
        return sign_content_minisign(content, secret_key, password)
    else:
        raise ValueError(f"Unknown signing method: {method}")


def verify_content_sigstore(content: bytes, signature_bundle_json: str, offline: bool = False) -> bool:
    if not _check_sigstore():
        raise ImportError("sigstore package is required for Sigstore verification. Install with: pip install sigstore")

    import base64

    import sigstore
    from sigstore.verify import VerificationMaterials, Verifier
    from sigstore.verify.policy import VerificationSuccess

    try:
        bundle_bytes = base64.b64decode(signature_bundle_json)

        materials = VerificationMaterials.from_bundle(
            input_=content,
            bundle=bundle_bytes,
            offline=offline,
        )

        verifier = Verifier.production()
        result = verifier.verify(materials)

        if isinstance(result, VerificationSuccess):
            logger.info(
                "Sigstore verification succeeded (offline=%s)",
                offline,
            )
            return True
        logger.warning("Sigstore verification failed: %s", result)
        return False

    except sigstore.errors.VerificationError:
        logger.exception("Sigstore verification error")
        raise
    except Exception:
        logger.exception("Sigstore verification failed")
        return False


def verify_content_minisign(content: bytes, signature_b64: str, public_key: str) -> bool:
    if not _check_minisign():
        raise ImportError("minisign is required for verification.")

    import base64
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(content)
        content_path = tf.name

    with tempfile.NamedTemporaryFile(delete=False, suffix=".minisig") as sf:
        sf.write(base64.b64decode(signature_b64))
        sig_path = sf.name

    try:
        cmd = ["minisign", "-V", "-x", sig_path, "-m", content_path]
        if public_key:
            cmd.extend(["-p", public_key])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode == 0:
            logger.info("minisign verification succeeded")
            return True
        logger.warning("minisign verification failed: %s", result.stderr.strip())
        return False

    finally:
        Path(content_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)


def verify_content(
    content: bytes, signature_bundle: SignatureBundle, public_key: str = "", offline: bool = False
) -> bool:
    if not signature_bundle.is_signed():
        logger.warning("No cryptographic signature present — rejecting unsigned bundle (fail-closed default)")
        return False  # Fail-closed: unsigned bundles are rejected by default

    if signature_bundle.provider == "sigstore":
        return verify_content_sigstore(
            content,
            signature_bundle.raw_signature,
            offline=offline,
        )
    if signature_bundle.provider == "minisign":
        return verify_content_minisign(
            content,
            signature_bundle.raw_signature,
            public_key,
        )
    raise ValueError(f"Unknown signature provider: {signature_bundle.provider}")


def sign_json_bundle(
    json_str: str, method: str = "sigstore", secret_key: str = "", password: str = ""
) -> SignatureBundle:

    data = json.loads(json_str)
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return sign_content(canonical.encode("utf-8"), method, secret_key, password)


def write_detached_signature(signature: SignatureBundle, output_path: Path) -> Path:
    sig_path = output_path.with_suffix(output_path.suffix + ".sig")
    sig_path.write_text(
        json.dumps(signature.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    logger.info("Wrote detached signature: %s", sig_path)
    return sig_path


def read_detached_signature(bundle_path: Path) -> SignatureBundle | None:
    sig_path = bundle_path.with_suffix(bundle_path.suffix + ".sig")
    if not sig_path.is_file():
        return None

    data = json.loads(sig_path.read_text(encoding="utf-8"))
    return SignatureBundle.from_dict(data)


def embed_signature(bundle_data: dict, signature: SignatureBundle) -> dict:
    result = dict(bundle_data)
    result["_crypto"] = signature.to_dict()
    return result


def extract_signature(bundle_data: dict) -> tuple[dict, SignatureBundle | None]:
    crypto_data = bundle_data.pop("_crypto", None)
    if crypto_data and isinstance(crypto_data, dict):
        return bundle_data, SignatureBundle.from_dict(crypto_data)
    return bundle_data, None
