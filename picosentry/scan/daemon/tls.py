from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass

logger = logging.getLogger("picosentry.daemon")


@dataclass
class TLSConfig:
    cert_file: str = ""
    key_file: str = ""
    mtls_ca: str = ""

    def is_enabled(self) -> bool:
        return bool(self.cert_file and self.key_file)

    def is_mtls(self) -> bool:
        return self.is_enabled() and bool(self.mtls_ca)

    @staticmethod
    def from_env() -> "TLSConfig":
        import os

        return TLSConfig(
            cert_file=os.environ.get("PICOSENTRY_TLS_CERT", ""),
            key_file=os.environ.get("PICOSENTRY_TLS_KEY", ""),
            mtls_ca=os.environ.get("PICOSENTRY_MTLS_CA", ""),
        )

    def to_ssl_context(self) -> ssl.SSLContext | None:
        if not self.is_enabled():
            return None

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.cert_file, self.key_file)

        if self.mtls_ca:
            ctx.load_verify_locations(self.mtls_ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
            logger.info("mTLS enabled: client certificates required (CA: %s)", self.mtls_ca)
        else:
            ctx.verify_mode = ssl.CERT_NONE

        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS")

        return ctx
