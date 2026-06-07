
from __future__ import annotations

import logging
import socket
import time

from picosentry.sandbox.audit.logger import AuditEvent
from picosentry.sandbox.audit.sinks.base import AuditSink, SinkConfig

logger = logging.getLogger("picodome.audit.sink.syslog")


FACILITY_USER = 1  # user-level messages
FACILITY_LOCAL0 = 128  # local use 0
FACILITY_LOCAL1 = 136  # local use 1


SEVERITY_INFORMATIONAL = 6
SEVERITY_WARNING = 4
SEVERITY_ERROR = 3
SEVERITY_NOTICE = 5


PRIORITY_INFO = FACILITY_USER * 8 + SEVERITY_INFORMATIONAL  # 14
PRIORITY_WARNING = FACILITY_USER * 8 + SEVERITY_WARNING  # 12
PRIORITY_ERROR = FACILITY_USER * 8 + SEVERITY_ERROR  # 11


_EVENT_SEVERITY: dict[str, int] = {
    "scan_start": PRIORITY_INFO,
    "scan_complete": PRIORITY_INFO,
    "scan_alert": PRIORITY_WARNING,
    "policy_create": PRIORITY_INFO,
    "policy_update": PRIORITY_INFO,
    "policy_rollback": PRIORITY_WARNING,
    "policy_delete": PRIORITY_WARNING,
    "baseline_create": PRIORITY_INFO,
    "baseline_update": PRIORITY_INFO,
    "baseline_delete": PRIORITY_WARNING,
    "daemon_start": PRIORITY_INFO,
    "daemon_stop": PRIORITY_INFO,
    "auth_success": PRIORITY_INFO,
    "auth_failure": PRIORITY_ERROR,
    "command_denied": PRIORITY_ERROR,
    "rate_limited": PRIORITY_WARNING,
    "data_retention_cleanup": PRIORITY_INFO,
    "data_export": PRIORITY_INFO,
    "data_delete": PRIORITY_WARNING,
}

_DEFAULT_SYSLOG_HOST = "127.0.0.1"
_DEFAULT_SYSLOG_PORT = 514
_DEFAULT_APP_NAME = "picodome"


class SyslogSink(AuditSink):

    def __init__(
        self,
        config: SinkConfig | None = None,
        host: str = _DEFAULT_SYSLOG_HOST,
        port: int = _DEFAULT_SYSLOG_PORT,
        app_name: str = _DEFAULT_APP_NAME,
        facility: int = FACILITY_USER,
    ) -> None:
        super().__init__(config)
        self._host = host
        self._port = port
        self._app_name = app_name
        self._facility = facility
        self._sock: socket.socket | None = None


    def start(self) -> None:
        super().start()
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            logger.info("SyslogSink: UDP socket created for %s:%d", self._host, self._port)
        except OSError as exc:
            logger.error("SyslogSink: failed to create socket: %s", exc)
            self._record_failure(str(exc))

    def stop(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


    def send(self, event: AuditEvent) -> None:
        if self._sock is None:
            self._record_failure("socket not initialized")
            self._record_dropped()
            return

        try:
            msg = self._format_message(event)
            self._sock.sendto(msg.encode("utf-8"), (self._host, self._port))
            self._record_success()
        except OSError as exc:
            self._record_failure(str(exc))
            self._record_dropped()
            logger.debug("SyslogSink: UDP send failed: %s", exc)


    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port


    def _format_message(self, event: AuditEvent) -> str:
        priority = _EVENT_SEVERITY.get(event.event_type.value, PRIORITY_INFO)
        timestamp = event.timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        hostname = socket.gethostname()
        procid = event.event_id[:36]  # truncate to reasonable length
        msgid = f"picodome.{event.event_type.value}"


        sd_pairs = [
            f'actor="{event.actor}"',
        ]
        if event.detail:
            sd_pairs.append(f'detail="{event.detail}"')
        if event.target:
            sd_pairs.append(f'target="{event.target}"')
        for k, v in event.metadata.items():
            sd_pairs.append(f'{k}="{v}"')

        sd = f"[{self._app_name} {' '.join(sd_pairs)}]"


        msg = f"{event.event_type.value} by {event.actor}"
        if event.detail:
            msg += f": {event.detail}"


        return f"<{priority}>1 {timestamp} {hostname} {self._app_name} {procid} {msgid} {sd} {msg}"
