from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picosentry.scan.audit import audit
from picosentry.scan.crypto import (
    SignatureBundle,
    read_detached_signature,
    sign_content,
    verify_content,
    write_detached_signature,
)
from picosentry.scan.engine import user_corpus_dir
from picosentry.scan.ioc_registry import IoCRecord, _validate_ioc_id, list_custom_iocs, register_ioc

logger = logging.getLogger("picosentry.corpus_share")


PACK_VERSION = "1.0"


_MAX_PACK_BYTES = 10 * 1024 * 1024


BUILTIN_PACKS = {
    "known-attacks": "Known supply-chain attacks (event-stream, left-pad, etc.)",
    "typosquat-top1000": "Top 1000 npm packages for typosquat detection",
    "malicious-maintainers": "Known malicious maintainer accounts",
}


class CorpusPack:
    def __init__(self, name: str, description: str = "", author: str = "") -> None:
        self.name = name
        self.description = description
        self.author = author
        self.version = PACK_VERSION
        self.iocs: list[dict] = []
        self.created_at: str = ""  # set by seal() or explicitly
        self.pack_id: str = hashlib.sha256(name.encode()).hexdigest()[:12]

    def add_ioc(self, record: IoCRecord) -> None:
        self.iocs.append(record.to_dict())

    def digest(self) -> str:
        raw = json.dumps(
            {
                "pack_id": self.pack_id,
                "name": self.name,
                "iocs": sorted(self.iocs, key=lambda x: x.get("id", "")),
            },
            sort_keys=True,
        )
        return f"sha256:{hashlib.sha256(raw.encode()).hexdigest()[:32]}"

    def seal(self, signer: str) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        self._signature = {
            "signer": signer,
            "digest": self.digest(),
            "sealed_at": datetime.now(timezone.utc).isoformat(),
        }

    def sign(self, signer: str) -> None:
        raise NotImplementedError(
            "CorpusPack.sign() is removed — use seal() for content-integrity "
            "stamps or sign_cryptographically() for real cryptographic signatures."
        )

    def sign_cryptographically(
        self, method: str = "sigstore", secret_key: str = "", password: str = ""
    ) -> SignatureBundle:
        canonical = self.to_json().encode("utf-8")
        sig = sign_content(canonical, method, secret_key, password)
        self._signature = {
            "signer": sig.signer_identity,
            "digest": self.digest(),
            "sealed_at": sig.signed_at,
            "provider": sig.provider,
            "crypto_signature": sig.raw_signature,
            "certificate": sig.certificate,
        }
        logger.info(
            "Cryptographically signed pack '%s' with %s (identity=%s)",
            self.name,
            sig.provider,
            sig.signer_identity,
        )
        return sig

    def to_dict(self) -> dict:
        d = {
            "pack_format": self.version,
            "pack_id": self.pack_id,
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "created_at": self.created_at,
            "ioc_count": len(self.iocs),
            "iocs": self.iocs,
            "digest": self.digest(),
        }
        if hasattr(self, "_signature") and self._signature:
            d["signature"] = self._signature
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @staticmethod
    def from_dict(data: dict) -> CorpusPack:
        pack = CorpusPack(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            author=data.get("author", "unknown"),
        )
        pack.version = data.get("pack_format", PACK_VERSION)
        pack.pack_id = data.get("pack_id", "")
        pack.created_at = data.get("created_at", "")
        pack.iocs = data.get("iocs", [])

        sig = data.get("signature")
        if sig and isinstance(sig, dict):
            pack._signature = sig
        return pack

    @staticmethod
    def from_file(path: Path) -> CorpusPack:
        data = json.loads(path.read_text(encoding="utf-8"))
        return CorpusPack.from_dict(data)


def export_corpus_pack(
    output_path: Path,
    name: str = "my-iocs",
    description: str = "",
    author: str = "",
    sign_method: str = "",
    sign_secret_key: str = "",
    sign_password: str = "",
) -> CorpusPack:
    pack = CorpusPack(name=name, description=description, author=author)

    for record in list_custom_iocs():
        pack.add_ioc(record)

    if sign_method:
        try:
            sig = pack.sign_cryptographically(sign_method, sign_secret_key, sign_password)
            write_detached_signature(sig, output_path)
        except ImportError as e:
            logger.warning("Cryptographic signing skipped: %s", e)
        except Exception:
            logger.exception("Cryptographic signing failed")

    output_path.write_text(pack.to_json() + "\n", encoding="utf-8")
    logger.info("Exported %d IoCs to %s", len(pack.iocs), output_path)

    return pack


def import_corpus_pack(
    path: Path,
    allow_overwrite: bool = False,
    dry_run: bool = False,
    verify_crypto: bool = False,
    public_key: str = "",
    offline: bool = False,
) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Corpus pack not found: {path}")

    if path.suffix.lower() != ".json":
        raise ValueError(f"Corpus pack must be a .json file, got: {path.suffix!r}")

    try:
        size = path.stat().st_size
    except OSError as _err:
        raise OSError(f"Cannot stat corpus pack file: {path}") from _err
    if size > _MAX_PACK_BYTES:
        raise ValueError(f"Corpus pack file too large: {size} bytes > {_MAX_PACK_BYTES} bytes limit")

    pack = CorpusPack.from_file(path)

    if hasattr(pack, "_signature") and pack._signature:
        expected_digest = pack._signature.get("digest", "")
        actual_digest = pack.digest()
        if expected_digest and actual_digest != expected_digest:
            raise ValueError(
                f"Corpus pack digest mismatch: signed={expected_digest} "
                f"actual={actual_digest}. Pack may have been tampered with."
            )
        logger.info(
            "Corpus pack verified: signed by %s, digest %s",
            pack._signature.get("signer", "unknown"),
            actual_digest,
        )

    if verify_crypto:
        sig_data = read_detached_signature(path)
        if sig_data is None and hasattr(pack, "_signature"):
            crypto_sig = pack._signature.get("crypto_signature", "")
            if crypto_sig:
                provider = pack._signature.get("provider", "")
                cert = pack._signature.get("certificate", "")
                sig_data = SignatureBundle(
                    signer_identity=pack._signature.get("signer", ""),
                    provider=provider,
                    raw_signature=crypto_sig,
                    certificate=cert,
                    digest=pack._signature.get("digest", ""),
                    signed_at=pack._signature.get("sealed_at", ""),
                )

        if sig_data is None:
            raise ValueError(
                "Cryptographic verification requested but no signature found "
                f"for pack '{pack.name}'. Use --no-verify-crypto to skip."
            )

        if not sig_data.is_signed():
            raise ValueError(
                f"Pack '{pack.name}' is not cryptographically signed "
                f"(provider={sig_data.provider}). Use --no-verify-crypto to skip."
            )

        canonical = json.dumps(pack.to_dict(), sort_keys=True, separators=(",", ":"))
        try:
            ok = verify_content(
                canonical.encode("utf-8"),
                sig_data,
                public_key=public_key,
                offline=offline,
            )
            if not ok:
                raise ValueError(
                    f"Cryptographic signature verification FAILED for pack "
                    f"'{pack.name}'. Pack may have been tampered with."
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

    if pack.version != PACK_VERSION:
        logger.warning(
            "Pack version %s may not be compatible with current format %s",
            pack.version,
            PACK_VERSION,
        )

    stats: dict[str, Any] = {
        "pack_name": pack.name,
        "pack_id": pack.pack_id,
        "total": len(pack.iocs),
        "imported": 0,
        "skipped": 0,
        "errors": 0,
        "error_details": [],
    }

    for ioc_data in pack.iocs:
        try:
            if dry_run:
                stats["imported"] += 1
            else:
                register_ioc(ioc_data, allow_overwrite=allow_overwrite)
                stats["imported"] += 1
        except FileExistsError:
            stats["skipped"] += 1
        except Exception as e:
            stats["errors"] += 1
            stats["error_details"].append(str(e))

    logger.info(
        "Import complete: %d imported, %d skipped, %d errors",
        stats["imported"],
        stats["skipped"],
        stats["errors"],
    )

    audit("corpus.import", target=str(path), outcome="success" if stats["errors"] == 0 else "partial", metadata=stats)

    return stats


def validate_corpus_pack(path: Path) -> dict:
    result: dict[str, Any] = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "ioc_count": 0,
        "pack_name": "",
    }

    try:
        file_size = path.stat().st_size
    except OSError as e:
        result["valid"] = False
        result["errors"].append(f"Cannot stat file: {e}")
        return result
    if file_size > _MAX_PACK_BYTES:
        result["valid"] = False
        result["errors"].append(f"File too large: {file_size} bytes > {_MAX_PACK_BYTES} bytes limit")
        return result

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        pack = CorpusPack.from_dict(data)
        result["pack_name"] = pack.name
        result["ioc_count"] = len(pack.iocs)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        result["valid"] = False
        result["errors"].append(f"Parse error: {e}")
        return result

    for i, ioc in enumerate(pack.iocs):
        ioc_id = ioc.get("id", "")
        if ioc_id:
            try:
                _validate_ioc_id(ioc_id)
            except ValueError as e:
                result["errors"].append(f"IoC {i}: invalid id — {e}")
        if not ioc.get("name"):
            result["errors"].append(f"IoC {i}: missing 'name'")
        if not ioc.get("package_name"):
            result["errors"].append(f"IoC {i}: missing 'package_name'")
        if not ioc.get("description"):
            result["warnings"].append(f"IoC {i}: missing 'description'")

    if result["errors"]:
        result["valid"] = False

    audit(
        "corpus.validate",
        target=str(path),
        outcome="success" if result["valid"] else "failure",
        metadata={"ioc_count": result["ioc_count"], "error_count": len(result["errors"])},
    )

    return result


def list_available_packs() -> list[dict]:
    packs = []

    for name, desc in BUILTIN_PACKS.items():
        packs.append(
            {
                "name": name,
                "description": desc,
                "source": "built-in",
                "ioc_count": "varies",
            }
        )

    user_dir = user_corpus_dir()
    for f in sorted(user_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("pack_format"):
                packs.append(
                    {
                        "name": data.get("name", f.stem),
                        "description": data.get("description", ""),
                        "source": "user",
                        "ioc_count": data.get("ioc_count", len(data.get("iocs", []))),
                        "file": str(f),
                    }
                )
        except (json.JSONDecodeError, OSError):
            logger.debug("Failed to read corpus pack file: %s", f.name)

    return packs
