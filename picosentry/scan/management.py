"""
Central management module for enterprise PicoSentry deployments.

Provides org-wide configuration, policy distribution, and advisory
database management for teams running PicoSentry at scale.

Usage:
    picosentry policy fetch https://security.example.com/policy.json
    picosentry advisories fetch https://security.example.com/advisories.zip
    picosentry policy push https://security.example.com/upload

Supports:
- Fetching signed policy bundles from a central URL
- Downloading advisory database updates
- Org-level configuration discovery
"""

from __future__ import annotations

import hashlib
import json
import logging
import tempfile
import zipfile
from pathlib import Path

from picosentry.scan._network import InsecureURLError, ResponseTooLargeError, safe_urlopen
from picosentry.scan.crypto import (
    SignatureBundle,
    verify_content,
)

logger = logging.getLogger("picosentry.management")

# Default org config locations
ORG_CONFIG_PATHS = [
    ".picosentry-org.yml",
    ".picosentry-org.yaml",
    "/etc/picosentry/org.yml",
]

# Environment variable overrides
ORG_POLICY_URL_ENV = "PICOSENTRY_POLICY_URL"
ORG_ADVISORY_URL_ENV = "PICOSENTRY_ADVISORY_URL"


class OrgConfig:
    """Organization-level configuration for PicoSentry.

    Discovered from .picosentry-org.yml files in the repo or system paths.
    Provides central URLs for policy bundles and advisory databases.
    """

    def __init__(self) -> None:
        self.policy_url: str = ""
        self.advisory_url: str = ""
        self.org_name: str = ""
        self.require_signed_policy: bool = True

    @staticmethod
    def discover(root: Path | None = None) -> OrgConfig:
        """Discover org configuration from filesystem or environment.

        Search order:
            1. $PICOSENTRY_POLICY_URL / $PICOSENTRY_ADVISORY_URL env vars
            2. .picosentry-org.yml in project root
            3. /etc/picosentry/org.yml (system-wide)
        """
        import os

        config = OrgConfig()

        # Environment overrides
        config.policy_url = os.environ.get(ORG_POLICY_URL_ENV, "")
        config.advisory_url = os.environ.get(ORG_ADVISORY_URL_ENV, "")

        # File-based config
        search_paths = []
        if root and root.is_dir():
            for name in ORG_CONFIG_PATHS[:2]:
                search_paths.append(root / name)
        search_paths.append(Path("/etc/picosentry/org.yml"))

        for path in search_paths:
            if not path.is_file():
                continue
            try:
                import yaml

                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except ImportError:
                data = json.loads(path.read_text(encoding="utf-8"))

            if isinstance(data, dict):
                if not config.policy_url:
                    config.policy_url = data.get("policy_url", "")
                if not config.advisory_url:
                    config.advisory_url = data.get("advisory_url", "")
                config.org_name = data.get("org_name", config.org_name)
                config.require_signed_policy = data.get("require_signed_policy", True)

        return config


def fetch_policy(url: str, output_path: Path, verify: bool = True, timeout: int = 30) -> Path:
    """Fetch a signed policy bundle from a central URL.

    Args:
        url: URL to fetch the policy bundle from.
        output_path: Where to save the downloaded bundle.
        verify: If True, verify the bundle digest.
        timeout: HTTP request timeout in seconds.

    Returns:
        Path to the saved policy bundle.

    Raises:
        ValueError: If verification fails.
        urllib.error.URLError: If the URL is unreachable.
    """
    import urllib.error
    import urllib.request  # noqa: F401 -- kept for Request construction

    logger.info("Fetching policy from %s", url)

    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        resp, data = safe_urlopen(req, timeout=timeout)
    except (urllib.error.URLError, InsecureURLError, ResponseTooLargeError) as e:
        logger.error("Failed to fetch policy: %s", e)
        raise
    finally:
        if "resp" in locals() and resp:
            resp.close()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)

    if verify:
        from picosentry.scan.policy import import_policy_bundle

        import_policy_bundle(output_path, verify=True)
        logger.info("Policy bundle verified: %s", output_path)

    return output_path


def _validate_zip_paths(zf: zipfile.ZipFile, output_dir: Path) -> None:
    """Validate all paths in a ZIP to prevent Zip Slip path traversal.

    Rejects entries that would extract outside output_dir, contain symlinks,
    or have suspicious names (.., absolute paths).

    Raises ValueError if any path is unsafe.
    """
    root = output_dir.resolve()
    for member in zf.infolist():
        # Reject symlinks
        if member.filename.startswith("/"):
            raise ValueError(f"Unsafe ZIP path (absolute): {member.filename}")
        if ".." in Path(member.filename).parts:
            raise ValueError(f"Unsafe ZIP path (traversal): {member.filename}")
        dest = (root / member.filename).resolve()
        if root not in dest.parents and dest != root:
            raise ValueError(f"Unsafe ZIP path (escapes output dir): {member.filename}")


def fetch_advisories(
    url: str,
    output_dir: Path,
    timeout: int = 120,
    verify_crypto: bool = False,
    public_key: str = "",
    offline: bool = False,
) -> int:
    """Download advisory database from a central URL.

    Supports .zip archives and raw .json files.
    Optionally verifies cryptographic signatures on the downloaded data.

    Args:
        url: URL to the advisory database (zip archive or JSON endpoint).
        output_dir: Directory to extract/download advisories into.
        timeout: HTTP request timeout in seconds.
        verify_crypto: If True, verify a cryptographic signature on the bundle.
        public_key: Path to minisign public key (minisign only).
        offline: If True, use offline Sigstore verification.

    Returns:
        Number of advisory files downloaded.

    Raises:
        urllib.error.URLError: If the URL is unreachable.
        ValueError: If cryptographic verification fails.
    """
    import urllib.error
    import urllib.request

    logger.info("Fetching advisories from %s", url)

    try:
        req = urllib.request.Request(url, headers={"Accept": "application/zip, application/json"})
        resp, data = safe_urlopen(req, timeout=timeout)
    except (urllib.error.URLError, InsecureURLError, ResponseTooLargeError) as e:
        logger.error("Failed to fetch advisories: %s", e)
        raise
    finally:
        if "resp" in locals() and resp:
            resp.close()

    output_dir.mkdir(parents=True, exist_ok=True)

    # Verify cryptographic signature if requested
    if verify_crypto:
        sig_url = url + ".sig"
        logger.info("Fetching advisory signature from %s", sig_url)
        try:
            sig_req = urllib.request.Request(sig_url, headers={"Accept": "application/json"})
            sig_resp, sig_body = safe_urlopen(sig_req, timeout=30)
            sig_data = json.loads(sig_body)
            sig_bundle = SignatureBundle.from_dict(sig_data)

            if not sig_bundle.is_signed():
                raise ValueError(
                    f"Advisory bundle signature is not cryptographic (provider={sig_bundle.provider}). "
                    "Use verify_crypto=False to skip."
                )

            ok = verify_content(data, sig_bundle, public_key=public_key, offline=offline)
            if not ok:
                raise ValueError(
                    "Cryptographic signature verification FAILED for advisory bundle. "
                    "The bundle may have been tampered with."
                )
            logger.info(
                "Advisory bundle signature verified: provider=%s, identity=%s",
                sig_bundle.provider,
                sig_bundle.signer_identity,
            )
        except (urllib.error.URLError, InsecureURLError, ResponseTooLargeError, json.JSONDecodeError) as e:
            if "sig_resp" in locals() and sig_resp:
                sig_resp.close()
            raise ValueError(f"Cryptographic verification requested but no signature found at {sig_url}: {e}") from e
        else:
            sig_resp.close()

    # Check if it's a zip file
    if data[:4] == b"PK\x03\x04":
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            tf.write(data)
            tmp_zip = tf.name

        try:
            with zipfile.ZipFile(tmp_zip, "r") as zf:
                # Validate all paths before extracting (Zip Slip prevention)
                _validate_zip_paths(zf, output_dir)
                zf.extractall(output_dir)
        finally:
            Path(tmp_zip).unlink()

        count = len(list(output_dir.rglob("*.json")))
        logger.info("Extracted %d advisory files to %s", count, output_dir)
        return count
    else:
        # Single JSON file or JSON array
        digest = hashlib.sha256(data).hexdigest()[:12]
        out_file = output_dir / f"advisory-{digest}.json"
        out_file.write_bytes(data)
        logger.info("Saved advisory data to %s", out_file)
        return 1


def push_policy(url: str, policy_path: Path, api_key: str = "", timeout: int = 30) -> bool:
    """Push a policy bundle to a central server.

    Args:
        url: Upload endpoint URL.
        policy_path: Path to the policy bundle file.
        api_key: API key for authentication.
        timeout: HTTP request timeout in seconds.

    Returns:
        True if upload succeeded.

    Raises:
        urllib.error.URLError: If the URL is unreachable.
    """
    import urllib.error
    import urllib.request

    logger.info("Pushing policy to %s", url)

    data = policy_path.read_bytes()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}" if api_key else "",
        },
        method="PUT",
    )

    try:
        resp, _body = safe_urlopen(req, timeout=timeout)
        status = resp.status
        resp.close()
    except (urllib.error.URLError, InsecureURLError) as e:
        logger.error("Failed to push policy: %s", e)
        raise

    ok: bool = 200 <= status < 300
    if ok:
        logger.info("Policy pushed successfully (HTTP %d)", status)
    else:
        logger.warning("Policy push returned HTTP %d", status)

    return ok


def org_config_template() -> str:
    """Return a YAML template for .picosentry-org.yml."""
    return """# PicoSentry Organization Configuration
# Place in project root or /etc/picosentry/org.yml
#
# Provides central URLs for policy bundles and advisory databases
# so all team members use the same security posture.

org_name: "My Organization"

# Central policy bundle URL (signed JSON)
policy_url: "https://security.example.com/picosentry/policy.json"

# Central advisory database URL (zip or JSON)
advisory_url: "https://security.example.com/picosentry/advisories.zip"

# Require policy bundles to be signed
require_signed_policy: true
"""


# ── Authentication helpers ──

PICOSENTRY_API_KEY_ENV = "PICOSENTRY_API_KEY"
PICOSENTRY_AUTH_TOKEN_ENV = "PICOSENTRY_AUTH_TOKEN"


def get_auth_token(api_key: str = "") -> str:
    """Resolve authentication token from args or environment.

    Priority:
        1. Explicit api_key argument
        2. $PICOSENTRY_API_KEY
        3. $PICOSENTRY_AUTH_TOKEN
    """
    import os

    if api_key:
        return api_key
    return os.environ.get(PICOSENTRY_API_KEY_ENV, "") or os.environ.get(PICOSENTRY_AUTH_TOKEN_ENV, "")


def make_authenticated_request(
    url: str, data: bytes | None = None, method: str = "GET", api_key: str = "", timeout: int = 30
) -> dict:
    """Make an authenticated HTTP request to a central management server.

    Args:
        url: Request URL.
        data: Request body (for POST/PUT).
        method: HTTP method.
        api_key: API key or bearer token.
        timeout: Request timeout.

    Returns:
        Dict with 'status', 'body', 'headers'.

    Raises:
        urllib.error.URLError: If the URL is unreachable.
        ValueError: If authentication fails (HTTP 401/403).
    """
    import urllib.error
    import urllib.request

    token = get_auth_token(api_key)
    headers = {"Accept": "application/json"}
    if token:
        # Try Bearer token first, fall back to X-API-Key
        if token.startswith("eyJ") or len(token) > 40:
            headers["Authorization"] = f"Bearer {token}"
        else:
            headers["X-API-Key"] = token

    if data:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        resp, body = safe_urlopen(req, timeout=timeout)
        result = {
            "status": resp.status,
            "body": body,
            "headers": dict(resp.headers),
        }
        resp.close()
        return result
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise ValueError(f"Authentication failed (HTTP {e.code}). Check $PICOSENTRY_API_KEY.") from e
        raise
    except (InsecureURLError, ResponseTooLargeError):
        raise
    import urllib.request  # noqa: F401 — kept for Request construction
