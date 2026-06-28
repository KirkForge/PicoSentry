from __future__ import annotations

import ipaddress
import json
import logging
import os
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.sandbox.admission import AdmissionRequest

logger = logging.getLogger("picodome.admission.scanner")

_DEFAULT_DAEMON_URL = "http://127.0.0.1:8443"
_DEFAULT_MIN_SEVERITY = "high"

# Cloud metadata hostnames that must never be reachable via an
# operator-misconfigured daemon URL (SSRF to instance credentials).
_METADATA_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
    }
)


def _assert_daemon_url_safe(daemon_url: str) -> None:
    """Reject daemon URLs that point at link-local / cloud-metadata addresses.

    The daemon legitimately runs on loopback (the default) or a
    cluster-internal address, so RFC1918 is *not* blocked here — only the
    link-local metadata ranges that have no business being a scan daemon:
    169.254.0.0/16 (incl. 169.254.169.254 on AWS/GCP/Azure) and fe80::/10,
    plus the well-known metadata hostnames. Raises ValueError if unsafe.
    """
    host = (urlparse(daemon_url).hostname or "").strip().rstrip(".").lower()
    if not host:
        raise ValueError(f"daemon URL has no host: {daemon_url!r}")
    if host in _METADATA_HOSTNAMES:
        raise ValueError(f"daemon URL points at a cloud-metadata hostname: {daemon_url!r}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # not a bare IP; hostname allow-listing beyond metadata names is out of scope
    if ip.is_link_local:
        raise ValueError(
            f"daemon URL points at a link-local/metadata address ({ip}): {daemon_url!r}"
        )


SEVERITY_LEVELS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class ImageScanner:
    def __init__(
        self,
        enabled: bool | None = None,
        min_severity: str = _DEFAULT_MIN_SEVERITY,
        daemon_url: str | None = None,
        timeout: float = 30.0,
        fail_closed: bool | None = None,
    ) -> None:
        if enabled is None:
            enabled = os.environ.get("PICODOME_ADMISSION_SCAN_ENABLED", "").lower() in ("true", "1", "yes")
        self.enabled = enabled
        self.min_severity = min_severity
        self.daemon_url = daemon_url or os.environ.get("PICODOME_ADMISSION_DAEMON_URL", _DEFAULT_DAEMON_URL)
        # SSRF guard: a misconfigured daemon URL pointing at the cloud
        # metadata endpoint would exfiltrate instance credentials. Validate
        # when scanning is active so a bad config fails closed at startup.
        if self.enabled:
            _assert_daemon_url_safe(self.daemon_url)
        self.timeout = timeout
        self._min_level = SEVERITY_LEVELS.get(min_severity, 3)

        if fail_closed is None:
            # Security default: fail closed unless the operator explicitly opts out.
            # In enterprise mode this is unconditional.
            if os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes"):
                self._fail_closed = True
            else:
                self._fail_closed = os.environ.get(
                    "PICODOME_ADMISSION_FAIL_CLOSED", "true"
                ).lower() not in ("0", "false", "no")
        else:
            self._fail_closed = fail_closed

    def scan_pod(self, req: AdmissionRequest) -> tuple[bool, str]:
        if not self.enabled:
            return True, ""

        pod = req.object_raw
        if not pod:
            return True, ""

        spec = pod.get("spec", {})
        if not spec:
            return True, ""

        containers = spec.get("containers", []) + spec.get("initContainers", [])
        for container in containers:
            image = container.get("image", "")
            name = container.get("name", "unknown")
            if not image:
                continue

            allowed, reason = self._scan_image(image, name)
            if not allowed:
                return False, reason

        return True, ""

    def _scan_image(self, image: str, container_name: str) -> tuple[bool, str]:
        try:
            url = f"{self.daemon_url}/api/v1/scan"
            payload = json.dumps(
                {
                    "command": ["container-analysis", image],
                    "policy": "strict",
                }
            ).encode("utf-8")

            req = Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            response = urlopen(req, timeout=self.timeout)
            result = json.loads(response.read())

            verdict = result.get("verdict", "CLEAN")
            findings = result.get("findings", [])

            if verdict == "DENY":
                return False, (f"container '{container_name}' image '{image}' denied: {len(findings)} findings")

            blocking_findings = [
                f for f in findings if SEVERITY_LEVELS.get(f.get("severity", "low"), 0) >= self._min_level
            ]

            if blocking_findings:
                severities = [f.get("severity", "unknown") for f in blocking_findings]
                return False, (
                    f"container '{container_name}' image '{image}' blocked: "
                    f"{len(blocking_findings)} findings at {self.min_severity}+ severity "
                    f"({', '.join(severities[:3])})"
                )

            logger.debug("Image '%s' passed scan: %d findings, none blocking", image, len(findings))
            return True, ""

        except URLError as exc:
            if self._fail_closed:
                logger.exception(
                    "Cannot reach PicoDome daemon for image scan '%s' — denying (fail-closed)",
                    image,
                )
                return False, f"daemon unreachable: image '{image}' scan could not be performed"
            logger.warning(
                "Cannot reach PicoDome daemon for image scan '%s': %s — allowing (fail-open)",
                image,
                exc,
            )
            return True, ""

        except Exception as exc:
            if self._fail_closed:
                logger.exception("Image scan failed for '")
                return False, f"scan failed: image '{image}' scan error: {exc}"
            logger.warning("Image scan failed for '%s': %s — allowing", image, exc)
            return True, ""

    @property
    def min_severity_level(self) -> int:
        return self._min_level
