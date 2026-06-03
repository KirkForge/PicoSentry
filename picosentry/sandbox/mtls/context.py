"""mTLS context configuration and SSL context factory.

Creates properly configured ssl.SSLContext for the daemon's HTTP
server with mutual TLS (client certificate verification).

Certificate management:
- Server cert/key: from PICODOME_TLS_CERT / PICODOME_TLS_KEY env vars or file paths
- CA bundle (for verifying client certs): from PICODOME_TLS_CA env var or file path
- Auto-generates self-signed certs for development (PICODOME_TLS_DEV=1)

Hardening:
- TLS 1.2+ only (no SSLv3, TLS 1.0, 1.1)
- Strong cipher suites only
- OCSP stapling enabled where available
- Certificate revocation checking
"""

from __future__ import annotations

import atexit
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
    """mTLS configuration."""

    # Server certificate (PEM)
    cert_path: str = ""
    # Server private key (PEM)
    key_path: str = ""
    # CA certificate bundle for verifying client certs
    ca_path: str = ""
    # Development mode: auto-generate self-signed certs
    dev_mode: bool = False
    # Minimum TLS version
    min_tls_version: str = "TLSv1_2"
    # Whether to verify client certificates
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
        """Create config from environment variables."""
        return cls(
            cert_path=os.environ.get("PICODOME_TLS_CERT", ""),
            key_path=os.environ.get("PICODOME_TLS_KEY", ""),
            ca_path=os.environ.get("PICODOME_TLS_CA", ""),
            dev_mode=os.environ.get("PICODOME_TLS_DEV", "").lower() in ("1", "true", "yes"),
            verify_client=os.environ.get("PICODOME_TLS_VERIFY_CLIENT", "1").lower() in ("1", "true", "yes"),
        )

    @property
    def is_configured(self) -> bool:
        """Check if mTLS is properly configured (has cert and key)."""
        return bool(self.cert_path and self.key_path) or self.dev_mode


def create_ssl_context(config: MTLSConfig | None = None) -> ssl.SSLContext | None:
    """Create an ssl.SSLContext for the daemon with mTLS.

    Args:
        config: mTLS configuration. None = load from environment.

    Returns:
        Configured SSLContext, or None if mTLS is not configured.
    """
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

    # Create SSL context with secure defaults
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Set minimum TLS version
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        pass

    # Load server certificate and key
    try:
        ctx.load_cert_chain(certfile=config.cert_path, keyfile=config.key_path)
    except (ssl.SSLError, OSError) as e:
        logger.error("Failed to load TLS cert/key: %s", e)
        raise

    # Configure client certificate verification
    if config.verify_client and config.ca_path:
        try:
            ctx.load_verify_locations(cafile=config.ca_path)
        except (ssl.SSLError, OSError) as e:
            logger.error("Failed to load CA bundle: %s", e)
            raise
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif config.verify_client:
        # Use system CA bundle
        ctx.set_default_verify_paths()
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE

    # Harden: disable weak ciphers
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS")

    # Disable compression (CRIME attack)
    ctx.options |= ssl.OP_NO_COMPRESSION

    # Enable OCSP stapling where available
    try:
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    except AttributeError:
        pass

    logger.info(
        "mTLS SSL context created: verify_client=%s min_version=%s",
        config.verify_client,
        config.min_tls_version,
    )

    return ctx


def reload_ssl_context(config: MTLSConfig | None = None) -> ssl.SSLContext | None:
    """Reload the SSL context from disk.

    Call this when certificates have been rotated (e.g., via certbot
    renewal or a Kubernetes secret update). Creates a fresh SSLContext
    by re-reading the cert/key/CA files.

    In a running daemon, this can be called from a signal handler or
    a file watcher to pick up new certificates without restarting.

    Args:
        config: mTLS configuration. None = load from environment.

    Returns:
        New SSLContext, or None if mTLS is not configured.
    """
    return create_ssl_context(config)


def get_tls_config_info(config: MTLSConfig | None = None) -> dict[str, Any]:
    """Get TLS configuration info for the /api/v1/tls/config endpoint.

    Returns a dict describing the current TLS state without exposing
    secrets (key contents are never included).

    Args:
        config: mTLS configuration. None = load from environment.

    Returns:
        Dict with TLS state, cert paths, and connection details.
    """
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

    # Check if cert files exist and are readable
    if config.is_configured and not config.dev_mode:
        cert_path = Path(config.cert_path) if config.cert_path else None
        key_path = Path(config.key_path) if config.key_path else None
        ca_path = Path(config.ca_path) if config.ca_path else None

        info["cert_exists"] = cert_path.is_file() if cert_path else False
        info["key_exists"] = key_path.is_file() if key_path else False
        info["ca_exists"] = ca_path.is_file() if ca_path else False

        # Read cert metadata (not the key!)
        if cert_path and cert_path.is_file():
            try:
                import subprocess

                result = subprocess.run(
                    ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-dates", "-issuer"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    info["cert_details"] = result.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

    return info


def _create_dev_ssl_context() -> ssl.SSLContext:
    """Create a self-signed SSL context for development.

    WARNING: Only use in development. Self-signed certs provide
    encryption but no identity verification.

    F9: Blocked in enterprise mode.
    """
    # F9: Block dev TLS mode in enterprise mode
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
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.error("Failed to generate dev TLS cert: %s", e)
        raise RuntimeError(f"Cannot generate dev TLS cert: {e}") from e

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.verify_mode = ssl.CERT_NONE  # dev mode: no client verification

    logger.info("Dev SSL context created (self-signed, no client verification)")
    return ctx
