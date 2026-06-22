from __future__ import annotations

import logging
import urllib.error
import urllib.request
from http.client import HTTPResponse

logger = logging.getLogger("picosentry._network")


DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


class InsecureURLError(ValueError):
    """Raised when a non-HTTPS URL is passed to safe_urlopen."""


class ResponseTooLargeError(ValueError):
    """Raised when a response body exceeds the configured size limit."""


def safe_urlopen(
    url: str | urllib.request.Request,
    *,
    timeout: int = 30,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    allow_http: bool = False,
) -> tuple[HTTPResponse, bytes]:

    url_str = url.full_url if isinstance(url, urllib.request.Request) else url

    if not allow_http and not url_str.startswith("https://"):
        raise InsecureURLError(
            f"Refusing non-HTTPS URL (MITM risk): {url_str}. Set allow_http=True only for local development."
        )

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
