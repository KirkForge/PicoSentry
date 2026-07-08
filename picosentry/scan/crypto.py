from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("picosentry.crypto")


_HAS_SIGSTORE: bool | None = None


def _check_sigstore() -> bool:
    global _HAS_SIGSTORE
    if _HAS_SIGSTORE is None:
        if importlib.util.find_spec("sigstore") is not None:
            _HAS_SIGSTORE = True
        else:
            _HAS_SIGSTORE = False
            logger.debug("sigstore package not available — cryptographic signing disabled")
    return _HAS_SIGSTORE


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
            _HAS_MINISIGN = importlib.util.find_spec("minisign") is not None
    return _HAS_MINISIGN


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

    from sigstore.models import ClientTrustConfig
    from sigstore.oidc import IdentityToken, Issuer
    from sigstore.sign import SigningContext

    digest = content_digest(content)

    trust_config = ClientTrustConfig.production()
    signing_ctx = SigningContext.from_trust_config(trust_config)

    identity_token_str = os.environ.get("SIGSTORE_IDENTITY_TOKEN")
    if identity_token_str:
        token = IdentityToken(identity_token_str)
        identity = token.identity
    else:
        oidc_issuer = os.environ.get("SIGSTORE_OIDC_ISSUER") or trust_config.signing_config.get_oidc_url()
        issuer = Issuer(oidc_issuer)
        token = issuer.identity_token()
        identity = token.identity

    with signing_ctx.signer(token) as signer:
        bundle = signer.sign_artifact(content)

    logger.info("Signed content with Sigstore (identity=%s, digest=%s...)", identity, digest[:12])

    return SignatureBundle(
        signer_identity=identity,
        provider="sigstore",
        raw_signature=bundle.to_json(),
        certificate="",
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


def verify_content_sigstore(
    content: bytes, signature_bundle_json: str, expected_identity: str = "", offline: bool = False
) -> bool:
    if not _check_sigstore():
        raise ImportError("sigstore package is required for Sigstore verification. Install with: pip install sigstore")

    from sigstore.errors import VerificationError
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.policy import Identity, UnsafeNoOp

    try:
        bundle = Bundle.from_json(signature_bundle_json)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError):
        logger.exception("Failed to parse Sigstore bundle")
        return False

    verifier = Verifier.production(offline=offline)
    policy = Identity(identity=expected_identity) if expected_identity else UnsafeNoOp()

    try:
        verifier.verify_artifact(content, bundle, policy)
        logger.info("Sigstore verification succeeded (offline=%s)", offline)
        return True
    except VerificationError as e:
        logger.warning("Sigstore verification failed: %s", e)
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
            expected_identity=signature_bundle.signer_identity,
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
