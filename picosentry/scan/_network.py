"""Network helpers with TLS enforcement and size limits for PicoSentry.

All outbound HTTP in PicoSentry must go through safe_urlopen to:
  - Reject non-HTTPS URLs (MITM protection)
  - Cap response body size (OOM / disk-exhaustion protection)

The scanner engine itself is offline; this module is only used by
management, auth (JWKS), and the CLI update command.
"""

from __future__ import annotations

import logging
import urllib.error
import urllib.request
from http.client import HTTPResponse

logger = logging.getLogger("picosentry._network")

# Default maximum response body size (10 MB)
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
    """Open a URL with TLS enforcement and response size capping.

    Args:
        url: URL string or urllib Request object.
        timeout: Request timeout in seconds.
        max_bytes: Maximum allowed response body size.
        allow_http: If True, allow http:// URLs (for local dev only).

    Returns:
        Tuple of (response_object, body_bytes).

    Raises:
        InsecureURLError: If the URL scheme is not HTTPS.
        ResponseTooLargeError: If the response body exceeds max_bytes.
        urllib.error.URLError: If the request fails.
    """
    # Extract URL string for scheme check
    url_str = url.full_url if isinstance(url, urllib.request.Request) else url

    if not allow_http and not url_str.startswith("https://"):
        raise InsecureURLError(
            f"Refusing non-HTTPS URL (MITM risk): {url_str}. Set allow_http=True only for local development."
        )

    try:
        resp = urllib.request.urlopen(url, timeout=timeout)
    except urllib.error.URLError as exc:
        # Enrich with URL context for callers that only show the error string
        exc.url = url_str if isinstance(url_str, str) else getattr(url, "full_url", "")  # type: ignore[attr-defined]
        raise

    # Read with size cap
    body = resp.read(max_bytes + 1)
    if len(body) > max_bytes:
        resp.close()
        raise ResponseTooLargeError(
            f"Response from {url_str} exceeded {max_bytes // (1024 * 1024)}MB limit. "
            "Possible network issue or MITM attack."
        )

    return resp, body
