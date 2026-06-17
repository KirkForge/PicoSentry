import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import db

logger = logging.getLogger("picoshogun.Alerts")

class AlertHub:

    def __init__(self):
        self.recent_alerts = defaultdict(list)
        self.cooldown_seconds = settings.alerts.cooldown_seconds
        self.max_retries = settings.alerts.max_retries
        self._lock = threading.Lock()

    def send(self, project_id: str, alert_type: str, severity: str,
             message: str, channels: list[str] | None = None,
             metadata: dict | None = None) -> bool:

        if channels is None:
            channels = self._get_default_channels()


        with self._lock:
            now = datetime.now(timezone.utc)
            key = f"{project_id}:{alert_type}"


            self.recent_alerts[key] = [
                t for t in self.recent_alerts.get(key, [])
                if (now - t).total_seconds() < self.cooldown_seconds * 2
            ]


            for prev in self.recent_alerts.get(key, []):
                if (now - prev).total_seconds() < self.cooldown_seconds:
                    logger.debug("Alert suppressed: %s", key)
                    return False

            self.recent_alerts[key].append(now)


        alert_ids = []
        for channel in channels:
            alert_id = db.execute_insert("""
                INSERT INTO alerts (project_id, alert_type, severity, message, channel)
                VALUES (?, ?, ?, ?, ?)
            """, (project_id, alert_type, severity, message, channel))
            alert_ids.append(alert_id)


        success = False
        for i, channel in enumerate(channels):
            try:
                if channel == "discord":
                    self._discord_notify(project_id, severity, message, metadata)
                elif channel == "slack":
                    self._slack_notify(project_id, severity, message, metadata)
                elif channel == "email":
                    self._email_notify(project_id, severity, message)
                elif channel == "syslog":
                    self._syslog_notify(project_id, severity, message)


                db.execute("""
                    UPDATE alerts SET sent = 1 WHERE id = ?
                """, (alert_ids[i],))
                success = True
            except Exception as e:
                logger.error("Alert delivery failed (%s): %s", channel, e)

                db.execute("""
                    UPDATE alerts SET retry_count = retry_count + 1 WHERE id = ?
                """, (alert_ids[i],))

        logger.info("ALERT [%s] %s: %s", severity.upper(), project_id, message[:100])
        return success

    def _get_default_channels(self) -> list[str]:
        channels = ["syslog"]  # Always log to syslog

        if settings.alerts.discord_webhook:
            channels.append("discord")
        if settings.alerts.slack_webhook:
            channels.append("slack")
        if settings.alerts.email_smtp_host:
            channels.append("email")

        return channels

    def _discord_notify(self, project_id: str, severity: str, message: str,
                       metadata: dict | None = None):
        if not HAS_REQUESTS or not settings.alerts.discord_webhook:
            return

        colors = {
            "critical": 15158332,  # Red
            "high": 16711680,      # Dark red
            "medium": 16776960,    # Yellow
            "low": 65280,          # Green
            "info": 3447003        # Blue
        }

        embed: dict[str, Any] = {
            "title": "🛡️ PicoShogun Alert",
            "description": message,
            "color": colors.get(severity, 3447003),
            "fields": [
                {"name": "Project", "value": project_id, "inline": True},
                {"name": "Severity", "value": severity.upper(), "inline": True},
                {"name": "Time", "value": datetime.now(timezone.utc).isoformat(), "inline": True}
            ],
            "footer": {"text": "PicoShogun"}
        }

        if metadata:
            for key, value in metadata.items():
                if len(str(value)) < 1000:
                    embed["fields"].append({
                        "name": key,
                        "value": str(value)[:1000],
                        "inline": True
                    })

        payload = {"embeds": [embed]}

        try:
            requests.post(
                settings.alerts.discord_webhook,
                json=payload,
                timeout=5,
                headers={"Content-Type": "application/json"}
            )
        except Exception as e:
            logger.error("Discord webhook failed: %s", e)

    def _slack_notify(self, project_id: str, severity: str, message: str,
                     metadata: dict | None = None):
        if not HAS_REQUESTS or not settings.alerts.slack_webhook:
            return

        colors = {
                "critical": "#FF0000",
                "high": "#FF6600",
                "medium": "#FFCC00",
                "low": "#00FF00",
                "info": "#0066FF"
            }

        payload: dict[str, Any] = {
            "attachments": [{
                "color": colors.get(severity, "#808080"),
                "title": f"PicoShogun Alert: {project_id}",
                "text": message,
                "fields": [
                    {"title": "Severity", "value": severity.upper(), "short": True},
                    {"title": "Time", "value": datetime.now(timezone.utc).isoformat(), "short": True}
                ]
            }]
        }

        if metadata:
            for key, value in metadata.items():
                payload["attachments"][0]["fields"].append({
                    "title": key,
                    "value": str(value)[:1000],
                    "short": True
                })

        try:
            requests.post(
                settings.alerts.slack_webhook,
                json=payload,
                timeout=5
            )
        except Exception as e:
            logger.error("Slack webhook failed: %s", e)

    def _email_notify(self, project_id: str, severity: str, message: str):
        import smtplib
        from email.mime.text import MIMEText

        if not settings.alerts.email_smtp_host or not settings.alerts.email_to:
            return

        try:
            msg = MIMEText(f"""
PicoShogun Alert

Project: {project_id}
Severity: {severity.upper()}
Time: {datetime.now(timezone.utc).isoformat()}

{message}
            """)

            msg["Subject"] = f"[PicoShogun] {severity.upper()}: {project_id}"
            msg["From"] = settings.alerts.email_from or "picoshogun@localhost"
            msg["To"] = ", ".join(settings.alerts.email_to)


            if settings.alerts.email_smtp_use_ssl:
                server: smtplib.SMTP_SSL | smtplib.SMTP = smtplib.SMTP_SSL(
                    settings.alerts.email_smtp_host,
                    settings.alerts.email_smtp_port
                )
            else:
                server = smtplib.SMTP(
                    settings.alerts.email_smtp_host,
                    settings.alerts.email_smtp_port
                )


            if settings.alerts.email_smtp_starttls and not settings.alerts.email_smtp_use_ssl:
                server.starttls()


            if settings.alerts.email_smtp_user and settings.alerts.email_smtp_password:
                server.login(
                    settings.alerts.email_smtp_user,
                    settings.alerts.email_smtp_password
                )

            server.send_message(msg)
            server.quit()
            logger.info("Email alert sent to %s recipients", len(settings.alerts.email_to))

        except Exception as e:
            logger.error("Email notification failed: %s", e)

    def _syslog_notify(self, project_id: str, severity: str, message: str):
        import sys


        _logging_levels = {
            "critical": 50,   # logging.CRITICAL
            "high": 40,       # logging.ERROR
            "medium": 30,     # logging.WARNING
            "low": 20,        # logging.INFO
            "info": 20,       # logging.INFO
        }

        if sys.platform != "win32":
            try:
                import syslog
                levels = {
                    "critical": syslog.LOG_CRIT,
                    "high": syslog.LOG_ERR,
                    "medium": syslog.LOG_WARNING,
                    "low": syslog.LOG_NOTICE,
                    "info": syslog.LOG_INFO
                }
                syslog.syslog(
                    levels.get(severity, syslog.LOG_INFO),
                    f"PicoShogun[{project_id}]: [{severity.upper()}] {message[:500]}"
                )
                return
            except ImportError:
                pass  # Fall through to logging fallback


        log_level = _logging_levels.get(severity, 20)
        logger.log(log_level, "PicoShogun[%s]: [%s] %s", project_id, severity.upper(), message[:500])

    def get_alert_stats(self, hours: int = 24) -> dict[str, Any]:
        rows = db.execute(f"""
            SELECT
                severity,
                channel,
                sent,
                COUNT(*) as count
            FROM alerts
            WHERE created_at > {db.dialect.date_add_hours('now', -hours)}
            GROUP BY severity, channel, sent
        """)

        stats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for row in rows:
            stats[row["severity"]]["total"] += row["count"]
            if row["sent"]:
                stats[row["severity"]]["sent"] += row["count"]
            else:
                stats[row["severity"]]["pending"] += row["count"]

        return dict(stats)
