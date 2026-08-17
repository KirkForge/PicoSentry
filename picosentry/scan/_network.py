from __future__ import annotations

import ipaddress
import json
import logging
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    import urllib.error
    import urllib.request
    from http.client import HTTPResponse

logger = logging.getLogger("picosentry._network")


DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# Cloud metadata hostnames that must never be reachable via an outbound fetch
# (SSRF to instance credentials). Loopback and RFC1918 are intentionally NOT
# blocked — local daemons and cluster-internal services are legitimate targets.
_METADATA_HOSTNAMES = frozenset({"metadata.google.internal", "metadata.goog", "metadata"})


class InsecureURLError(ValueError):
    """Raised when a non-HTTPS URL is passed to safe_urlopen."""


class ResponseTooLargeError(ValueError):
    """Raised when a response body exceeds the configured size limit."""


class UnsafeURLError(ValueError):
    """Raised when a URL targets a link-local / cloud-metadata address."""


def assert_url_safe(url: str) -> None:
    """Reject URLs pointing at link-local / cloud-metadata addresses (SSRF).

    Blocks 169.254.0.0/16 (incl. 169.254.169.254 on AWS/GCP/Azure) and
    fe80::/10, plus the well-known metadata hostnames. Loopback and RFC1918
    are allowed on purpose — the local daemon default and cluster-internal
    services are legitimate. Raises UnsafeURLError if unsafe.

    ponytail: bare-IP + known-hostname check only; a hostname that *resolves*
    to a metadata IP (DNS rebinding) is not caught. Upgrade path: resolve and
    check every A/AAAA before connect if that threat is in scope.
    """
    host = (urlparse(url).hostname or "").strip().rstrip(".").lower()
    if not host:
        raise UnsafeURLError(f"URL has no host: {url!r}")
    if host in _METADATA_HOSTNAMES:
        raise UnsafeURLError(f"URL points at a cloud-metadata hostname: {url!r}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # not a bare IP; hostname allow-listing beyond metadata names is out of scope
    if ip.is_link_local:
        raise UnsafeURLError(f"URL points at a link-local/metadata address ({ip}): {url!r}")


def safe_urlopen(
    url: str | urllib.request.Request,
    *,
    timeout: int = 30,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    allow_http: bool = False,
) -> tuple[HTTPResponse, bytes]:

    import urllib.error
    import urllib.request

    url_str = url.full_url if isinstance(url, urllib.request.Request) else url

    if not allow_http and not url_str.startswith("https://"):
        raise InsecureURLError(
            f"Refusing non-HTTPS URL (MITM risk): {url_str}. Set allow_http=True only for local development."
        )

    assert_url_safe(url_str)

    try:
        resp = urllib.request.urlopen(url, timeout=timeout)
    except urllib.error.URLError as exc:
        exc.url = url_str if isinstance(url_str, str) else getattr(url, "full_url", "")  # type: ignore[attr-defined]
        raise

    body = resp.read(max_bytes + 1)
    if len(body) > max_bytes:
        resp.close()
        raise ResponseTooLargeError(
            f"Response from {url_str} exceeded {max_bytes // (1024 * 1024)}MB limit. "
            "Possible network issue or MITM attack."
        )

    return resp, body


def fetch_registry_intel(
    name: str,
    ecosystem: str = "npm",
    *,
    timeout: int = 10,
) -> tuple[int | None, str | None]:
    """Fetch (download_count, first_release) for a package from its registry.

    PyPI: ``https://pypi.org/pypi/{name}/json`` — first release is the earliest
    ``upload_time`` across all releases. npm: ``https://registry.npmjs.org/{name}``
    for ``time.created`` plus the downloads API for a 30-day count.

    Degrades gracefully: any network/parse error returns ``(None, None)`` so
    offline scans get no intel and never crash.
    """
    import urllib.error

    try:
        if ecosystem == "pypi":
            return _fetch_pypi_intel(name, timeout=timeout)
        return _fetch_npm_intel(name, timeout=timeout)
    except (urllib.error.URLError, InsecureURLError, UnsafeURLError, ResponseTooLargeError, ValueError, OSError):
        logger.debug("Registry intel fetch failed for %s (%s)", name, ecosystem, exc_info=True)
        return None, None


def _fetch_pypi_intel(name: str, *, timeout: int) -> tuple[int | None, str | None]:
    _, body = safe_urlopen(f"https://pypi.org/pypi/{name}/json", timeout=timeout)
    data = json.loads(body.decode("utf-8", errors="replace"))
    releases = data.get("releases")
    first_release: str | None = None
    if isinstance(releases, dict):
        upload_times = []
        for files in releases.values():
            if isinstance(files, list):
                for f in files:
                    if isinstance(f, dict) and f.get("upload_time"):
                        upload_times.append(f["upload_time"])
        if upload_times:
            first_release = min(upload_times)
    return None, first_release


def _fetch_npm_intel(name: str, *, timeout: int) -> tuple[int | None, str | None]:
    _, body = safe_urlopen(f"https://registry.npmjs.org/{name}", timeout=timeout)
    data = json.loads(body.decode("utf-8", errors="replace"))
    time_field = data.get("time")
    first_release: str | None = None
    if isinstance(time_field, dict):
        created = time_field.get("created")
        if isinstance(created, str):
            first_release = created
    import urllib.error

    download_count: int | None = None
    try:
        _, dl_body = safe_urlopen(f"https://api.npmjs.org/downloads/point/last-month/{name}", timeout=timeout)
        dl_data = json.loads(dl_body.decode("utf-8", errors="replace"))
        if isinstance(dl_data, dict) and isinstance(dl_data.get("downloads"), int):
            download_count = dl_data["downloads"]
    except (urllib.error.URLError, InsecureURLError, UnsafeURLError, ResponseTooLargeError, ValueError, OSError):
        logger.debug("npm downloads fetch failed for %s", name, exc_info=True)
    return download_count, first_release
