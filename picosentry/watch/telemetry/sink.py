from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from picosentry.watch import __version__
from picosentry.watch.telemetry.metrics import PrometheusMetrics
from picosentry.watch.types import HealthStatus, PromptScanResult, ValidationResult

logger = logging.getLogger("picowatch")


@dataclass
class TelemetryConfig:
    audit_db_path: Path = field(default_factory=lambda: Path("picowatch_audit.db"))
    audit_retention_days: int = 30
    otel_endpoint: str | None = None
    admin_port: int = 9091
    enable_otel: bool = False


class TelemetrySink:
    def __init__(self, config: TelemetryConfig | None = None) -> None:
        self._config = config or TelemetryConfig()
        self._start_time = time.monotonic()
        self._prometheus = PrometheusMetrics()
        self._metrics: dict[str, int | float] = {
            "picowatch_requests_total": 0,
            "picowatch_prompt_blocked_total": 0,
            "picowatch_prompt_score_sum": 0.0,
            "picowatch_output_violations_total": 0,
            "picowatch_scan_duration_ms_sum": 0.0,
        }
        self._init_audit_db()

        self.cleanup_audit()

    def _init_audit_db(self) -> None:
        conn = sqlite3.connect(str(self._config.audit_db_path))
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    request_id TEXT,
                    score REAL,
                    verdict TEXT,
                    rules TEXT,
                    details TEXT,
                    checksum TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)
            """)

            with contextlib.suppress(sqlite3.OperationalError):
                conn.execute("ALTER TABLE audit_log ADD COLUMN checksum TEXT")
            conn.commit()
        finally:
            conn.close()

    _cached_audit_key: bytes | None = None

    @classmethod
    def _audit_key(cls) -> bytes:
        if cls._cached_audit_key is not None:
            return cls._cached_audit_key
        key = os.environ.get("PICOWATCH_AUDIT_HMAC_KEY")
        if key and len(key) >= 32:
            cls._cached_audit_key = key.encode("utf-8")
            return cls._cached_audit_key
        if key and len(key) >= 16:
            logger.warning(
                "PICOWATCH_AUDIT_HMAC_KEY is shorter than 32 chars — "
                "cryptographic strength reduced; recommend ≥32 chars"
            )
            cls._cached_audit_key = key.encode("utf-8")
            return cls._cached_audit_key
        if key:
            logger.warning("PICOWATCH_AUDIT_HMAC_KEY is set but shorter than 16 chars — ignoring")
        cls._cached_audit_key = os.urandom(32)
        logger.warning(
            "PICOWATCH_AUDIT_HMAC_KEY not set — using random per-process key; "
            "audit checksums will NOT survive restarts. "
            "Set PICOWATCH_AUDIT_HMAC_KEY for persistent verification.",
        )
        return cls._cached_audit_key

    def _compute_checksum(
        self, timestamp: str, event_type: str, request_id: str | None, score: float, verdict: str, rules: str
    ) -> str:
        msg = f"{timestamp}|{event_type}|{request_id or ''}|{score}|{verdict}|{rules}"
        return hmac.new(self._audit_key(), msg.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    def record_prompt_scan(self, result: PromptScanResult, request_id: str | None = None) -> None:
        self._metrics["picowatch_requests_total"] += 1
        self._metrics["picowatch_prompt_score_sum"] = float(self._metrics["picowatch_prompt_score_sum"]) + result.score
        self._metrics["picowatch_scan_duration_ms_sum"] = (
            float(self._metrics["picowatch_scan_duration_ms_sum"]) + result.duration_ms
        )

        if result.blocked:
            self._metrics["picowatch_prompt_blocked_total"] = int(self._metrics["picowatch_prompt_blocked_total"]) + 1

        model = result.details.get("model") if result.details else None
        labels = {"model": model} if model else None
        self._prometheus.inc_counter("picowatch_requests_total", labels=labels)
        if result.blocked:
            self._prometheus.inc_counter("picowatch_prompt_blocked_total", labels=labels)
        self._prometheus.observe_histogram("picowatch_prompt_score", result.score, labels=labels)
        self._prometheus.observe_histogram(
            "picowatch_scan_duration_seconds",
            result.duration_ms / 1000.0,
            labels={"guard_type": "prompt"},
        )

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": "warn" if result.blocked else "info",
            "event": "prompt.blocked" if result.blocked else "prompt.scanned",
            "request_id": request_id,
            "score": result.score,
            "verdict": result.verdict.value,
            "rules": result.rules_matched,
            "corpus_hash": result.corpus_hash,
            "latency_ms": result.duration_ms,
        }
        logger.info(json.dumps(log_entry))

        self._audit_write(
            event_type="prompt_scan",
            request_id=request_id,
            score=result.score,
            verdict=result.verdict.value,
            rules=json.dumps(result.rules_matched),
            details=json.dumps(result.details) if result.details else None,
        )

    def record_validation(self, result: ValidationResult, request_id: str | None = None) -> None:
        if result.violations:
            self._metrics["picowatch_output_violations_total"] = (
                int(self._metrics["picowatch_output_violations_total"]) + 1
            )
        self._metrics["picowatch_scan_duration_ms_sum"] = (
            float(self._metrics["picowatch_scan_duration_ms_sum"]) + result.duration_ms
        )

        self._prometheus.inc_counter("picowatch_requests_total")
        if result.valid:
            self._prometheus.inc_counter("picowatch_output_validated_total")
        else:
            self._prometheus.inc_counter("picowatch_output_violations_total")
        self._prometheus.observe_histogram(
            "picowatch_scan_duration_seconds",
            result.duration_ms / 1000.0,
            labels={"guard_type": "output"},
        )

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": "warn" if not result.valid else "info",
            "event": "output.violated" if result.violations else "output.validated",
            "request_id": request_id,
            "score": result.score,
            "verdict": result.verdict.value,
            "violations": result.violations,
            "corpus_hash": result.corpus_hash,
            "latency_ms": result.duration_ms,
        }
        logger.info(json.dumps(log_entry))

        self._audit_write(
            event_type="output_validation",
            request_id=request_id,
            score=result.score,
            verdict=result.verdict.value,
            rules=json.dumps(result.violations),
            details=json.dumps(result.details) if result.details else None,
        )

    def _audit_write(
        self,
        event_type: str,
        request_id: str | None,
        score: float,
        verdict: str,
        rules: str,
        details: str | None,
    ) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        checksum = self._compute_checksum(timestamp, event_type, request_id, score, verdict, rules)
        conn = None
        try:
            conn = sqlite3.connect(str(self._config.audit_db_path))
            conn.execute(
                """
                INSERT INTO audit_log
                    (timestamp, event_type, request_id, score, verdict, rules, details, checksum)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    event_type,
                    request_id,
                    score,
                    verdict,
                    rules,
                    details,
                    checksum,
                ),
            )
            conn.commit()
        except sqlite3.Error:
            logger.warning("Failed to write audit log entry")
        finally:
            if conn:
                conn.close()

    def verify_audit_integrity(self) -> list[int]:
        invalid_rows: list[int] = []
        conn = None
        try:
            conn = sqlite3.connect(str(self._config.audit_db_path))
            rows = conn.execute(
                "SELECT id, timestamp, event_type, request_id, score, verdict, rules, checksum FROM audit_log"
            ).fetchall()
            for row in rows:
                row_id, timestamp, event_type, request_id, score, verdict, rules, stored_checksum = row
                expected = self._compute_checksum(timestamp, event_type, request_id, score, verdict, rules)
                if stored_checksum != expected:
                    invalid_rows.append(row_id)
        except sqlite3.Error:
            logger.warning("Failed to verify audit log integrity")
        finally:
            if conn:
                conn.close()
        return invalid_rows

    def render_prometheus(self) -> str:
        lines: list[str] = []

        lines.append("# HELP picowatch_requests_total Total requests processed")
        lines.append("# TYPE picowatch_requests_total counter")
        lines.append(f"picowatch_requests_total {self._metrics['picowatch_requests_total']}")

        lines.append("# HELP picowatch_prompt_blocked_total Total prompts blocked")
        lines.append("# TYPE picowatch_prompt_blocked_total counter")
        lines.append(f"picowatch_prompt_blocked_total {self._metrics['picowatch_prompt_blocked_total']}")

        lines.append("# HELP picowatch_prompt_score_sum Cumulative prompt scores")
        lines.append("# TYPE picowatch_prompt_score_sum counter")
        lines.append(f"picowatch_prompt_score_sum {self._metrics['picowatch_prompt_score_sum']}")

        lines.append("# HELP picowatch_output_violations_total Total output violations")
        lines.append("# TYPE picowatch_output_violations_total counter")
        lines.append(f"picowatch_output_violations_total {self._metrics['picowatch_output_violations_total']}")

        lines.append("# HELP picowatch_scan_duration_ms_sum Cumulative scan duration in ms")
        lines.append("# TYPE picowatch_scan_duration_ms_sum counter")
        lines.append(f"picowatch_scan_duration_ms_sum {self._metrics['picowatch_scan_duration_ms_sum']}")

        if self._prometheus._histograms:
            lines.append("")
            lines.append(self._prometheus.render())

        return "\n".join(lines) + "\n"

    def health(
        self,
        rules_loaded: int,
        corpus_hash: str,
        corpus_version: str,
        rules_expected: int = 0,
        load_errors: list[str] | None = None,
    ) -> HealthStatus:
        return HealthStatus(
            healthy=True,
            version=__version__,
            rules_loaded=rules_loaded,
            corpus_hash=corpus_hash,
            corpus_version=corpus_version,
            uptime_seconds=round(time.monotonic() - self._start_time, 2),
            rules_expected=rules_expected,
            load_errors=load_errors or [],
        )

    def cleanup_audit(self) -> int:
        if self._config.audit_retention_days <= 0:
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(days=self._config.audit_retention_days)
        conn = None
        try:
            conn = sqlite3.connect(str(self._config.audit_db_path))
            cursor = conn.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff.isoformat(),))
            deleted = cursor.rowcount
            conn.commit()
            return deleted
        except sqlite3.Error:
            return 0
        finally:
            if conn:
                conn.close()
