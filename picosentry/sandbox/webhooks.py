from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar

logger = logging.getLogger("picodome.webhooks")


class WebhookEvent(str, Enum):
    SCAN_COMPLETE = "scan_complete"
    SCAN_ALERT = "scan_alert"
    POLICY_CHANGE = "policy_change"
    BASELINE_DRIFT = "baseline_drift"
    DAEMON_EVENT = "daemon_event"


@dataclass(frozen=True)
class WebhookConfig:
    url: str
    secret: str = ""  # HMAC signing secret
    events: list[str] = field(default_factory=lambda: ["scan_alert"])
    min_severity: str = "high"  # minimum severity to trigger
    enabled: bool = True
    timeout_seconds: float = 10.0
    max_retries: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "events": list(self.events),
            "max_retries": self.max_retries,
            "min_severity": self.min_severity,
            "secret": "***" if self.secret else "",
            "timeout_seconds": self.timeout_seconds,
            "url": self.url,
        }


@dataclass(frozen=True)
class WebhookPayload:
    event: str
    timestamp: str
    data: dict[str, Any]
    signature: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {"data": self.data, "event": self.event, "signature": self.signature, "timestamp": self.timestamp},
            sort_keys=True,
            default=str,
        )


def _sign_payload(payload_json: str, secret: str) -> str:
    if not secret:
        return ""
    mac = hmac.new(secret.encode(), payload_json.encode(), hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


class WebhookDispatcher:
    SEVERITY_ORDER: ClassVar[dict[str, int]] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    BLOCKED_URL_PATTERNS = (
        "169.254.",  # cloud metadata (AWS/GCP/Azure)
        "100.64.",  # CGNAT / private
        "10.",  # RFC1918
        "192.168.",  # RFC1918
        "172.16.",  # RFC1918
        "127.",  # loopback
        "0.",  # all-zeros
        "localhost",  # localhost
        "::1",  # IPv6 loopback
        "fc00:",  # IPv6 unique-local
        "fe80:",  # IPv6 link-local
        "fd",  # IPv6 unique-local
    )

    def __init__(self) -> None:
        self._webhooks: list[WebhookConfig] = []
        self._active_threads: list[threading.Thread] = []

    def add_webhook(self, config: WebhookConfig) -> None:

        if self._is_blocked_url(config.url):
            logger.error("Webhook URL blocked (SSRF protection): %s", config.url)
            return
        self._webhooks.append(config)
        logger.info("Webhook registered: %s (events=%s)", config.url, config.events)

    @classmethod
    def _is_blocked_url(cls, url: str) -> bool:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        hostname_lower = hostname.lower()
        for pattern in cls.BLOCKED_URL_PATTERNS:
            if hostname_lower.startswith(pattern.lower()) or hostname_lower == pattern.lower():
                return True
        return False

    def remove_webhook(self, url: str) -> None:
        self._webhooks = [w for w in self._webhooks if w.url != url]

    def list_webhooks(self) -> list[dict[str, Any]]:
        return [w.to_dict() for w in self._webhooks]

    def notify(
        self,
        event: WebhookEvent,
        data: dict[str, Any],
        severity: str | None = None,
    ) -> dict[str, Any]:
        delivered = 0
        failed = 0
        skipped = 0
        details: list[dict[str, str]] = []

        for wh in self._webhooks:
            if not wh.enabled:
                skipped += 1
                continue

            if event.value not in wh.events and "*" not in wh.events:
                skipped += 1
                continue

            if severity and wh.min_severity:
                sev_level = self.SEVERITY_ORDER.get(severity.lower(), 99)
                min_level = self.SEVERITY_ORDER.get(wh.min_severity.lower(), 99)
                if sev_level > min_level:
                    skipped += 1
                    continue

            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            payload = WebhookPayload(
                event=event.value,
                timestamp=timestamp,
                data=data,
            )
            payload_json = payload.to_json()
            signature = _sign_payload(payload_json, wh.secret)

            success = self._deliver(wh, payload_json, signature)
            if success:
                delivered += 1
                details.append({"url": wh.url, "status": "delivered"})
            else:
                failed += 1
                details.append({"url": wh.url, "status": "failed"})

        return {
            "delivered": delivered,
            "failed": failed,
            "skipped": skipped,
            "details": details,
        }

    def notify_async(
        self,
        event: WebhookEvent,
        data: dict[str, Any],
        severity: str | None = None,
    ) -> None:
        threading.Thread(
            target=self._notify_sync,
            args=(event, data, severity),
            daemon=True,
        ).start()

    def _notify_sync(self, event: WebhookEvent, data: dict[str, Any], severity: str | None = None) -> None:
        for wh in self._webhooks:
            if not wh.enabled:
                continue
            if event.value not in wh.events and "*" not in wh.events:
                continue
            if severity and wh.min_severity:
                sev_level = self.SEVERITY_ORDER.get(severity.lower(), 99)
                min_level = self.SEVERITY_ORDER.get(wh.min_severity.lower(), 99)
                if sev_level > min_level:
                    continue
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            payload = WebhookPayload(event=event.value, timestamp=timestamp, data=data)
            payload_json = payload.to_json()
            signature = _sign_payload(payload_json, wh.secret)
            self._deliver(wh, payload_json, signature)

    def _deliver(self, config: WebhookConfig, payload_json: str, signature: str) -> bool:
        for attempt in range(config.max_retries):
            try:
                req = urllib.request.Request(
                    config.url,
                    data=payload_json.encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-PicoDome-Event": "webhook",
                        "X-PicoDome-Signature": signature,
                        "User-Agent": "PicoDome-Webhook/1.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=config.timeout_seconds) as resp:
                    if resp.status < 400:
                        logger.info("Webhook delivered to %s (status=%d)", config.url, resp.status)
                        return True
                    logger.warning("Webhook %s returned %d", config.url, resp.status)
            except (urllib.error.URLError, OSError, TimeoutError) as e:
                logger.warning(
                    "Webhook delivery attempt %d/%d to %s failed: %s",
                    attempt + 1,
                    config.max_retries,
                    config.url,
                    e,
                )
                if attempt < config.max_retries - 1:
                    backoff = 2**attempt  # 1s, 2s, 4s
                    time.sleep(backoff)

        logger.error("Webhook delivery to %s failed after %d attempts", config.url, config.max_retries)
        return False

    @classmethod
    def from_config(cls, config_data: dict[str, Any]) -> WebhookDispatcher:
        dispatcher = cls()
        for wh in config_data.get("webhooks", []):
            dispatcher.add_webhook(
                WebhookConfig(
                    url=wh.get("url", ""),
                    secret=wh.get("secret", ""),
                    events=wh.get("events", ["scan_alert"]),
                    min_severity=wh.get("min_severity", "high"),
                    enabled=wh.get("enabled", True),
                    timeout_seconds=wh.get("timeout_seconds", 10.0),
                    max_retries=wh.get("max_retries", 3),
                )
            )
        return dispatcher
