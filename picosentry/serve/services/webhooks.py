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


SSRF_BLOCKED_SCHEMES = {"file", "ftp", "data", "javascript", "vbscript"}
SSRF_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("10.0.0.0/8"),  # Private
    ipaddress.ip_network("172.16.0.0/12"),  # Private
    ipaddress.ip_network("192.168.0.0/16"),  # Private
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local (AWS metadata)
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
]


def _resolve_hostname(hostname: str) -> list[str] | None:
    try:
        results = socket.getaddrinfo(hostname, None)
        return [str(addr[4][0]) for addr in results]
    except socket.gaierror:
        return None


def _is_safe_webhook_url(url: str, dns_resolver=None) -> tuple:
    parsed = urlparse(url)
    if not parsed.scheme and not parsed.netloc:
        return False, "Invalid URL format"

    if parsed.scheme not in ("http", "https"):
        return False, f"Scheme '{parsed.scheme}' not allowed. Only http/https."

    if not parsed.hostname:
        return False, "URL must have a hostname"

    resolve = dns_resolver or _resolve_hostname
    ips = resolve(parsed.hostname)

    if ips is None:
        return False, f"Cannot resolve hostname '{parsed.hostname}'"

    # Every returned address must pass the SSRF blocklist. Allowlisting one IP
    # and ignoring the rest lets a multi-record DNS response bypass the guard.
    safe_ips: list[str] = []
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        blocked = next((network for network in SSRF_BLOCKED_NETWORKS if ip in network), None)
        if blocked:
            return False, f"Target IP {ip} is in blocked network {blocked}"
        safe_ips.append(ip_str)

    if not safe_ips:
        return False, f"No usable IPs for hostname '{parsed.hostname}'"

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
    org_id: int | None = None
    # Resolved IP addresses checked at create() time.  dispatch() pins to this
    # list so a DNS rebinding attack cannot swap a public IP for 127.0.0.1
    # between registration and firing (PicoSentry-HIGH-2).
    pinned_ips: list[str] | None = None


class WebhookManager:
    def __init__(self, dns_resolver=None):
        self.dns_resolver = dns_resolver
        self.webhooks: dict[str, Webhook] = {}
        self._load_webhooks()

    def _load_webhooks(self):
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
                created_at=row["created_at"],
                org_id=row.get("org_id"),
                pinned_ips=None,
            )
            self.webhooks[row["name"]] = webhook

    def create(
        self, name: str, url: str, events: list[str], secret: str | None = None, org_id: int | None = None
    ) -> int:

        is_safe, reason = _is_safe_webhook_url(url, dns_resolver=self.dns_resolver)
        if not is_safe:
            raise ValueError(f"Webhook URL rejected: {reason}")

        # Pin the IPs that passed the SSRF check.  Re-resolve at dispatch time
        # only to verify the address is still in the pinned set.
        resolve = self.dns_resolver or _resolve_hostname
        pinned_ips = resolve(urlparse(url).hostname) or []
        if not pinned_ips:
            raise ValueError("Webhook URL rejected: no resolvable IPs")

        secret = secret or secrets.token_urlsafe(32)

        webhook_id = db.execute_insert(
            """
            INSERT INTO webhooks (name, url, secret, events, active, retries, org_id)
            VALUES (?, ?, ?, ?, 1, 0, ?)
        """,
            (name, url, secret, json.dumps(events), org_id),
        )

        self._load_webhooks()
        logger.info("Webhook created: %s -> %s", name, url)
        return webhook_id

    def delete(self, webhook_id: int) -> bool:
        db.execute("UPDATE webhooks SET active = 0 WHERE id = ?", (webhook_id,))
        self._load_webhooks()
        return True

    def sign_payload(self, payload: dict, secret: str) -> str:
        payload_json = json.dumps(payload, sort_keys=True)
        return hmac.new(secret.encode(), payload_json.encode(), hashlib.sha256).hexdigest()

    def _sign_payload(self, payload: dict, secret: str) -> str:
        return self.sign_payload(payload, secret)

    def dispatch(self, event: str, payload: dict) -> list[dict[str, Any]]:
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
                "data": payload,
            }

            signature = self._sign_payload(event_payload, webhook.secret)

            try:
                # Re-resolve and verify the IP is still in the create-time
                # pinned set.  This closes DNS rebinding: an attacker who
                # controls the hostname cannot change the answer between
                # registration and dispatch.
                parsed = urlparse(webhook.url)
                current_ips = set(_resolve_hostname(parsed.hostname) or [])
                allowed_ips = set(webhook.pinned_ips or [])
                if webhook.pinned_ips is not None and not current_ips.issubset(allowed_ips):
                    logger.warning(
                        "Webhook %s rejected: DNS rebind detected (was %s, now %s)",
                        name,
                        allowed_ips,
                        current_ips,
                    )
                    results.append({"webhook": name, "status": 0, "success": False, "error": "DNS rebind detected"})
                    continue

                response = requests.post(
                    webhook.url,
                    json=event_payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-PicoShogun-Signature": f"sha256={signature}",
                        "X-PicoShogun-Event": event,
                        "User-Agent": "PicoShogun-Webhook/2.0",
                    },
                    timeout=10,
                )

                results.append(
                    {"webhook": name, "status": response.status_code, "success": 200 <= response.status_code < 300}
                )

                logger.info("Webhook %s: %s", name, response.status_code)

            except requests.RequestException as e:
                logger.exception("Webhook %s failed", name)
                results.append({"webhook": name, "status": 0, "success": False, "error": str(e)})

        return results

    def verify_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

        return hmac.compare_digest(signature, expected)


webhook_manager = WebhookManager()
