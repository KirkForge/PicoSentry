import logging
from typing import Any

from picosentry.serve.services.plugin_manager import PluginInterface

logger = logging.getLogger("picoshogun.Plugin.DiscordNotifier")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def _get_webhook_url() -> str | None:
    import os
    return os.environ.get("DISCORD_WEBHOOK_URL") or None


class DiscordNotifier(PluginInterface):

    def initialize(self, config: dict[str, Any]) -> bool:
        self.webhook_url = config.get("webhook_url") or _get_webhook_url()
        if not self.webhook_url:
            logger.warning(
                "DiscordNotifier initialized WITHOUT webhook URL — "
                "alerts will be logged but NOT sent to Discord. "
                "Set DISCORD_WEBHOOK_URL to enable delivery."
            )
        else:
            logger.info("DiscordNotifier initialized with webhook URL")
        return True

    def on_project_complete(self, project_id: str, result: dict) -> None:
        status = result.get("status", "unknown")
        duration = result.get("duration", 0)
        severity = "info" if status == "success" else "warning"
        message = f"Project {project_id} completed: {status} in {duration:.1f}s"
        self._send(severity, message, {"project": project_id, "status": status, "duration": duration})

    def on_alert(self, alert: dict) -> dict | None:
        severity = alert.get("severity", "info")
        msg = alert.get("message", "")
        self._send(severity, msg, alert)
        return alert

    def health_check(self) -> dict:
        return {
            "status": "healthy",
            "version": "1.0.1",
            "webhook_configured": bool(self.webhook_url),
        }

    def _send(self, severity: str, message: str, metadata: dict | None = None) -> None:
        if not self.webhook_url or not HAS_REQUESTS:
            logger.info("[DiscordNotifier] %s — %s", severity.upper(), message)
            return

        colors = {
            "critical": 15158332,
            "high": 16711680,
            "medium": 16776960,
            "low": 65280,
            "info": 3447003,
            "warning": 16776960,
        }

        fields = [
            {"name": "Severity", "value": severity.upper(), "inline": True},
        ]
        if metadata:
            for key, value in metadata.items():
                if key not in ("severity", "message") and len(str(value)) < 1000:
                    fields.append({"name": key, "value": str(value)[:1000], "inline": True})

        payload: dict[str, Any] = {
            "embeds": [{
                "title": "🛡️ PicoShogun Alert",
                "description": message[:2000],
                "color": colors.get(severity, 3447003),
                "fields": fields,
            }]
        }

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            logger.debug("[DiscordNotifier] Delivered %s alert", severity)
        except Exception as exc:
            logger.exception("[DiscordNotifier] Delivery failed: %s", exc)
