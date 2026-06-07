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
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private
    ipaddress.ip_network("172.16.0.0/12"),     # Private
    ipaddress.ip_network("192.168.0.0/16"),     # Private
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local (AWS metadata)
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 private
]


def _resolve_hostname(hostname: str) -> list[str] | None:
    try:
        results = socket.getaddrinfo(hostname, None)
        return [str(addr[4][0]) for addr in results]
    except socket.gaierror:
        return None


def _is_safe_webhook_url(url: str, dns_resolver=None) -> tuple:
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"


    if parsed.scheme not in ("http", "https"):
        return False, f"Scheme '{parsed.scheme}' not allowed. Only http/https."


    if not parsed.hostname:
        return False, "URL must have a hostname"


    resolve = dns_resolver or _resolve_hostname
    ips = resolve(parsed.hostname)

    if ips is None:


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
                created_at=row["created_at"]
            )
            self.webhooks[row["name"]] = webhook

    def create(self, name: str, url: str, events: list[str], secret: str | None = None) -> int:

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
        db.execute("UPDATE webhooks SET active = 0 WHERE id = ?", (webhook_id,))
        self._load_webhooks()
        return True

    def sign_payload(self, payload: dict, secret: str) -> str:
        payload_json = json.dumps(payload, sort_keys=True)
        return hmac.new(
            secret.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()

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
        expected = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()


        return hmac.compare_digest(signature, expected)


webhook_manager = WebhookManager()
