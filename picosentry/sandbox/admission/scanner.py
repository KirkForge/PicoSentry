
from __future__ import annotations

import json
import logging
import os
from urllib.error import URLError
from urllib.request import Request, urlopen

from picosentry.sandbox.admission import AdmissionRequest

logger = logging.getLogger("picodome.admission.scanner")

_DEFAULT_DAEMON_URL = "http://127.0.0.1:8443"
_DEFAULT_MIN_SEVERITY = "high"


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
        self.timeout = timeout
        self._min_level = SEVERITY_LEVELS.get(min_severity, 3)


        if fail_closed is None:
            self._fail_closed = os.environ.get("PICODOME_ADMISSION_FAIL_CLOSED", "").lower() in ("1", "true", "yes")
            if os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes"):
                self._fail_closed = True
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
                logger.error(
                    "Cannot reach PicoDome daemon for image scan '%s': %s — denying (fail-closed)",
                    image,
                    exc,
                )
                return False, f"daemon unreachable: image '{image}' scan could not be performed"
            else:
                logger.warning(
                    "Cannot reach PicoDome daemon for image scan '%s': %s — allowing (fail-open)",
                    image,
                    exc,
                )
                return True, ""

        except Exception as exc:
            if self._fail_closed:
                logger.error("Image scan failed for '%s': %s — denying (fail-closed)", image, exc)
                return False, f"scan failed: image '{image}' scan error: {exc}"
            else:
                logger.warning("Image scan failed for '%s': %s — allowing", image, exc)
                return True, ""

    @property
    def min_severity_level(self) -> int:
        return self._min_level
