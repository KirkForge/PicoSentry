
from __future__ import annotations

import atexit
import contextlib
import logging
import os
import shutil
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("picodome.mtls")


@dataclass(frozen=True)
class MTLSConfig:


    cert_path: str = ""

    key_path: str = ""

    ca_path: str = ""

    dev_mode: bool = False

    min_tls_version: str = "TLSv1_2"

    verify_client: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "ca_path": self.ca_path,
            "cert_path": self.cert_path,
            "dev_mode": self.dev_mode,
            "key_path": self.key_path,
            "min_tls_version": self.min_tls_version,
            "verify_client": self.verify_client,
        }

    @classmethod
    def from_env(cls) -> MTLSConfig:
        return cls(
            cert_path=os.environ.get("PICODOME_TLS_CERT", ""),
            key_path=os.environ.get("PICODOME_TLS_KEY", ""),
            ca_path=os.environ.get("PICODOME_TLS_CA", ""),
            dev_mode=os.environ.get("PICODOME_TLS_DEV", "").lower() in ("1", "true", "yes"),
            verify_client=os.environ.get("PICODOME_TLS_VERIFY_CLIENT", "1").lower() in ("1", "true", "yes"),
        )

    @property
    def is_configured(self) -> bool:
        return bool(self.cert_path and self.key_path) or self.dev_mode


def create_ssl_context(config: MTLSConfig | None = None) -> ssl.SSLContext | None:
    if config is None:
        config = MTLSConfig.from_env()

    if not config.is_configured:
        logger.info("mTLS not configured — running in plaintext HTTP mode")
        return None

    if config.dev_mode:
        return _create_dev_ssl_context()

    if not config.cert_path or not config.key_path:
        logger.warning("mTLS enabled but cert/key not configured")
        return None


    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)


    with contextlib.suppress(AttributeError):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2


    try:
        ctx.load_cert_chain(certfile=config.cert_path, keyfile=config.key_path)
    except (ssl.SSLError, OSError):
        logger.exception("Failed to load TLS cert/key")
        raise


    if config.verify_client and config.ca_path:
        try:
            ctx.load_verify_locations(cafile=config.ca_path)
        except (ssl.SSLError, OSError):
            logger.exception("Failed to load CA bundle")
            raise
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif config.verify_client:

        ctx.set_default_verify_paths()
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE


    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS")


    ctx.options |= ssl.OP_NO_COMPRESSION


    with contextlib.suppress(AttributeError):
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF

    logger.info(
        "mTLS SSL context created: verify_client=%s min_version=%s",
        config.verify_client,
        config.min_tls_version,
    )

    return ctx


def reload_ssl_context(config: MTLSConfig | None = None) -> ssl.SSLContext | None:
    return create_ssl_context(config)


def get_tls_config_info(config: MTLSConfig | None = None) -> dict[str, Any]:
    if config is None:
        config = MTLSConfig.from_env()

    info: dict[str, Any] = {
        "mtls_enabled": config.is_configured,
        "dev_mode": config.dev_mode,
        "min_tls_version": config.min_tls_version,
        "verify_client": config.verify_client,
        "cert_path": config.cert_path,
        "key_path": config.key_path,
        "ca_path": config.ca_path,
    }


    if config.is_configured and not config.dev_mode:
        cert_path = Path(config.cert_path) if config.cert_path else None
        key_path = Path(config.key_path) if config.key_path else None
        ca_path = Path(config.ca_path) if config.ca_path else None

        info["cert_exists"] = cert_path.is_file() if cert_path else False
        info["key_exists"] = key_path.is_file() if key_path else False
        info["ca_exists"] = ca_path.is_file() if ca_path else False


        if cert_path and cert_path.is_file():
            try:
                import subprocess

                result = subprocess.run(
                    ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-dates", "-issuer"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if result.returncode == 0:
                    info["cert_details"] = result.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

    return info


def _create_dev_ssl_context() -> ssl.SSLContext:

    if os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes"):
        raise RuntimeError("PICODOME_TLS_DEV=1 is not allowed in enterprise mode. Provide proper certificates.")

    import subprocess

    logger.warning("Creating DEV self-signed TLS certificate — DO NOT USE IN PRODUCTION")

    tmpdir = tempfile.mkdtemp(prefix="picodome_tls_")
    atexit.register(lambda: shutil.rmtree(tmpdir, ignore_errors=True))

    cert_path = os.path.join(tmpdir, "server.crt")
    key_path = os.path.join(tmpdir, "server.key")

    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=picodome-dev/O=KirkForge",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.exception("Failed to generate dev TLS cert")
        raise RuntimeError(f"Cannot generate dev TLS cert: {e}") from e

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.verify_mode = ssl.CERT_NONE  # dev mode: no client verification

    logger.info("Dev SSL context created (self-signed, no client verification)")
    return ctx
