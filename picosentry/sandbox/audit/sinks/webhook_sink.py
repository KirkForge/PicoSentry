from __future__ import annotations

import json
import logging
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from picosentry.sandbox.audit.sinks.base import AuditSink, SinkConfig
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.sandbox.audit.logger import AuditEvent

logger = logging.getLogger("picodome.audit.sink.webhook")


class WebhookSink(AuditSink):
    def __init__(
        self,
        config: SinkConfig | None = None,
        url: str = "",
        headers: dict[str, str] | None = None,
        auth_token: str | None = None,
    ) -> None:
        super().__init__(config)
        if not url:
            raise ValueError("WebhookSink requires a non-empty URL")
        self._url = url
        self._headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if headers:
            self._headers.update(headers)
        self._auth_token = auth_token

    def start(self) -> None:
        super().start()

        try:
            req = Request(
                self._url,
                method="HEAD",
                headers=self._build_headers(),
            )
            urlopen(req, timeout=self._config.timeout)
            logger.info("WebhookSink: endpoint reachable at %s", self._url)
        except Exception as exc:
            logger.warning("WebhookSink: endpoint not reachable at %s: %s", self._url, exc)

    def send(self, event: AuditEvent) -> None:
        payload = event.to_dict()
        body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        headers = self._build_headers()

        last_error = ""
        for attempt in range(self._config.max_retries + 1):
            try:
                req = Request(
                    self._url,
                    data=body,
                    method="POST",
                    headers=headers,
                )
                response = urlopen(req, timeout=self._config.timeout)

                if 200 <= response.status < 300:
                    self._record_success()
                    return
                last_error = f"HTTP {response.status}"
                logger.warning(
                    "WebhookSink: non-2xx response %d for event %s (attempt %d/%d)",
                    response.status,
                    event.event_id[:8],
                    attempt + 1,
                    self._config.max_retries + 1,
                )
            except (URLError, OSError) as exc:
                last_error = str(exc)
                logger.debug(
                    "WebhookSink: request failed for event %s (attempt %d/%d): %s",
                    event.event_id[:8],
                    attempt + 1,
                    self._config.max_retries + 1,
                    exc,
                )

            if attempt < self._config.max_retries:
                backoff = self._config.retry_backoff * (2**attempt)
                time.sleep(min(backoff, 30.0))  # cap at 30s

        self._record_failure(last_error)
        self._record_dropped()
        logger.error(
            "WebhookSink: dropped event %s after %d attempts: %s",
            event.event_id[:8],
            self._config.max_retries + 1,
            last_error,
        )

    @property
    def url(self) -> str:
        return self._url

    def _build_headers(self) -> dict[str, str]:
        headers = dict(self._headers)
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return headers
