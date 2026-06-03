"""Webhook system for external integrations."""
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from picosentry.serve.database.manager import db

logger = logging.getLogger("picoshogun.Webhooks")

# Blocked URL patterns for SSRF protection
SSRF_BLOCKED_SCHEMES = {"file", "ftp", "data", "javascript", "vbscript"}
SSRF_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private
    ipaddress.ip_network("172.16.0.0/12"),     # Private
    ipaddress.ip_network("192.168.0.0/16"),     # Private
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local (AWS metadata)
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 private
]


def _resolve_hostname(hostname: str) -> list[str] | None:
    """Resolve a hostname to a list of IP address strings.

    Returns None if the hostname cannot be resolved.
    This function is a seam for testing: mock this to avoid live DNS lookups.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
        return [str(addr[4][0]) for addr in results]
    except socket.gaierror:
        return None


def _is_safe_webhook_url(url: str, dns_resolver=None) -> tuple:
    """Validate webhook URL against SSRF attacks.

    Returns (is_safe, reason) tuple.

    Args:
        url: The webhook URL to validate.
        dns_resolver: Optional callable that takes a hostname string and returns
            a list of IP address strings, or None if unresolvable.
            Defaults to socket.getaddrinfo-based resolution.
            Pass a mock for testing without live DNS.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    # Only allow HTTP/HTTPS
    if parsed.scheme not in ("http", "https"):
        return False, f"Scheme '{parsed.scheme}' not allowed. Only http/https."

    # Must have a hostname
    if not parsed.hostname:
        return False, "URL must have a hostname"

    # Resolve hostname and check against blocked networks
    resolve = dns_resolver or _resolve_hostname
    ips = resolve(parsed.hostname)

    if ips is None:
        # Hostname cannot be resolved — reject in production, but allow the
        # caller to decide based on context (e.g. test mode may skip DNS).
        return False, f"Cannot resolve hostname '{parsed.hostname}'"

    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for network in SSRF_BLOCKED_NETWORKS:
            if ip in network:
                return False, f"Target IP {ip} is in blocked network {network}"

    return True, "OK"


@dataclass
class Webhook:
    id: int
    name: str
    url: str
    secret: str
    events: list[str]
    active: bool
    retries: int
    created_at: datetime

class WebhookManager:
    """Manage outgoing webhooks with HMAC signing and retry logic."""

    def __init__(self, dns_resolver=None):
        self.dns_resolver = dns_resolver
        self.webhooks: dict[str, Webhook] = {}
        self._load_webhooks()

    def _load_webhooks(self):
        """Load active webhooks from picosentry.serve.database."""
        rows = db.execute("SELECT * FROM webhooks WHERE active = 1")
        for row in rows:
            webhook = Webhook(
                id=row["id"],
                name=row["name"],
                url=row["url"],
                secret=row["secret"],
                events=json.loads(row["events"]),
                active=row["active"],
                retries=row["retries"],
                created_at=row["created_at"]
            )
            self.webhooks[row["name"]] = webhook

    def create(self, name: str, url: str, events: list[str], secret: str = None) -> int:
        """Create a new webhook endpoint."""
        # SSRF protection: validate URL
        is_safe, reason = _is_safe_webhook_url(url, dns_resolver=self.dns_resolver)
        if not is_safe:
            raise ValueError(f"Webhook URL rejected: {reason}")

        secret = secret or secrets.token_urlsafe(32)

        webhook_id = db.execute_insert("""
            INSERT INTO webhooks (name, url, secret, events, active, retries)
            VALUES (?, ?, ?, ?, 1, 0)
        """, (name, url, secret, json.dumps(events)))

        self._load_webhooks()
        logger.info("Webhook created: %s -> %s", name, url)
        return webhook_id

    def delete(self, webhook_id: int) -> bool:
        """Deactivate a webhook."""
        db.execute("UPDATE webhooks SET active = 0 WHERE id = ?", (webhook_id,))
        self._load_webhooks()
        return True

    def sign_payload(self, payload: dict, secret: str) -> str:
        """Generate HMAC-SHA256 signature for a dict payload.

        Serializes the payload to JSON with sorted keys, then signs.
        For verifying incoming webhook signatures from raw bytes, use verify_signature().
        """
        payload_json = json.dumps(payload, sort_keys=True)
        return hmac.new(
            secret.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()

    def _sign_payload(self, payload: dict, secret: str) -> str:
        """Internal: sign a dict payload for outgoing webhooks."""
        return self.sign_payload(payload, secret)

    def dispatch(self, event: str, payload: dict) -> list[dict[str, Any]]:
        """Dispatch event to all matching webhooks."""
        results: list[dict[str, Any]] = []

        if not HAS_REQUESTS:
            logger.warning("requests library not available, skipping webhooks")
            return results

        for name, webhook in self.webhooks.items():
            if event not in webhook.events:
                continue

            event_payload: dict[str, Any] = {
                "event": event,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": payload
            }

            signature = self._sign_payload(event_payload, webhook.secret)

            try:
                response = requests.post(
                    webhook.url,
                    json=event_payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-PicoShogun-Signature": f"sha256={signature}",
                        "X-PicoShogun-Event": event,
                        "User-Agent": "PicoShogun-Webhook/2.0"
                    },
                    timeout=10
                )

                results.append({
                    "webhook": name,
                    "status": response.status_code,
                    "success": 200 <= response.status_code < 300
                })

                logger.info("Webhook %s: %s", name, response.status_code)

            except Exception as e:
                logger.error("Webhook %s failed: %s", name, e)
                results.append({
                    "webhook": name,
                    "status": 0,
                    "success": False,
                    "error": str(e)
                })

        return results

    def verify_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        """Verify incoming webhook signature using constant-time comparison.

        For raw bytes payloads (e.g. from incoming HTTP request bodies), pass the
        raw body bytes. For dict payloads, use sign_payload() to generate the
        expected signature instead.
        """
        expected = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()

        # Use hmac.compare_digest for constant-time comparison (prevents timing attacks)
        return hmac.compare_digest(signature, expected)

# Global webhook manager instance
webhook_manager = WebhookManager()
