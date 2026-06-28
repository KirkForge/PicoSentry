"""A2: every outbound fetch via safe_urlopen is SSRF-guarded.

The link-local / cloud-metadata block now lives in scan._network so all
callers (JWKS fetch, corpus update, daemon push) inherit it, not just the
admission scanner.
"""

from __future__ import annotations

import pytest

from picosentry.scan._network import UnsafeURLError, assert_url_safe, safe_urlopen


@pytest.mark.parametrize(
    "url",
    [
        "https://pypi.org/simple/",
        "https://mirror.internal.example.com/corpus.tar",
        "http://127.0.0.1:8443",  # loopback daemon
        "http://10.0.0.5:8443",  # cluster-internal
    ],
)
def test_safe_urls_pass(url: str) -> None:
    assert_url_safe(url)  # must not raise


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.170.2/",  # ECS task metadata (link-local)
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://[fe80::1]/",  # IPv6 link-local
    ],
)
def test_metadata_urls_rejected(url: str) -> None:
    with pytest.raises(UnsafeURLError):
        assert_url_safe(url)


def test_safe_urlopen_blocks_metadata_before_network() -> None:
    # The guard fires before any socket is opened, so a metadata URL raises
    # regardless of reachability.
    with pytest.raises(UnsafeURLError):
        safe_urlopen("https://169.254.169.254/latest/meta-data/", timeout=1)
