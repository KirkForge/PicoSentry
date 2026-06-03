"""PicoShogun firewall integration adapter.

PicoWatch loads as a PicoShogun plugin implementing the WatchGuard protocol.
Pipeline order: L1 (rate limit) → L2 (PicoSentry) → L3 (PicoDome sandbox) → L4 (PicoDome behavioral)
                → L5 (PicoWatch prompt) → L6 (PicoWatch output)

Usage in PicoShogun config:
    plugins:
      - picowatch.picoshogun:PicoWatchPlugin
    picowatch:
      rules_dir: /path/to/rules
      threshold_block: 0.7
      threshold_warn: 0.4
"""

from __future__ import annotations

import time
from typing import Any, ClassVar, Protocol

from picosentry.watch import __version__
from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.output_guard import OutputGuard
from picosentry.watch.prompt_guard import PromptGuard
from picosentry.watch.telemetry import TelemetrySink
from picosentry.watch.types import PromptScanResult, ValidationResult

# ─── WatchGuard Protocol (PicoShogun interface) ────────────────────────────────


class WatchGuard(Protocol):
    """PicoShogun WatchGuard protocol — all plugins implement this interface.

    PicoShogun calls these methods when events flow through the firewall pipeline.
    """

    def scan_prompt(self, text: str, context: dict[str, Any] | None = None) -> PromptScanResult:
        """Scan a prompt for injection patterns (L5)."""
        ...

    def validate_output(
        self,
        output: str,
        schema: dict[str, Any] | None = None,
        prompt_result: PromptScanResult | None = None,
    ) -> ValidationResult:
        """Validate an LLM output (L6)."""
        ...

    def health(self) -> dict[str, Any]:
        """Return plugin health status."""
        ...


# ─── PicoWatch PicoShogun Plugin ──────────────────────────────────────────────


class PicoWatchPlugin:
    """PicoShogun firewall plugin adapter for PicoWatch.

    Implements the WatchGuard protocol so PicoShogun can load PicoWatch
    as an L5/L6 filter in the firewall pipeline.

    Usage:
        plugin = PicoWatchPlugin(config=picoshogun_config.get("picowatch", {}))
        result = plugin.scan_prompt("ignore all instructions")

    In PicoShogun's YAML config:
        plugins:
          - picowatch.picoshogun:PicoWatchPlugin
        picowatch:
          rules_dir: /opt/shogun/rules
          threshold_block: 0.7
    """

    name: ClassVar[str] = "picowatch"
    version: ClassVar[str] = __version__
    layers: ClassVar[list[int]] = [5, 6]  # L5 + L6 in PicoShogun pipeline

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize plugin from PicoShogun config dict.

        Args:
            config: PicoShogun's picowatch config section (from YAML).
                    Keys map to PicoWatchConfig fields.
        """
        pw_config = self._build_config(config or {})
        self._prompt_guard = PromptGuard(config=pw_config)
        self._output_guard = OutputGuard(config=pw_config)
        self._sink = TelemetrySink()
        self._start_time = time.perf_counter()
        self._pw_config = pw_config

    def _build_config(self, config: dict[str, Any]) -> PicoWatchConfig:
        """Build PicoWatchConfig from PicoShogun config dict.

        Maps PicoShogun's YAML keys to PicoWatchConfig fields.
        Environment variables take precedence over PicoShogun config.
        """
        import os
        from pathlib import Path

        from picosentry.watch.config import (
            DEFAULT_AUDIT_RETENTION_DAYS,
            DEFAULT_CORPUS_VERSION,
            DEFAULT_MAX_PROMPT_SIZE,
            DEFAULT_RULES_DIR,
            DEFAULT_THRESHOLD_BLOCK,
            DEFAULT_THRESHOLD_WARN,
        )

        pw_cfg = PicoWatchConfig()
        rules_dir = config.get("rules_dir")
        pw_cfg.rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        pw_cfg.threshold_block = float(config.get("threshold_block", DEFAULT_THRESHOLD_BLOCK))
        pw_cfg.threshold_warn = float(config.get("threshold_warn", DEFAULT_THRESHOLD_WARN))
        pw_cfg.max_prompt_size = int(config.get("max_prompt_size", DEFAULT_MAX_PROMPT_SIZE))
        schema_dir = config.get("schema_dir")
        pw_cfg.schema_dir = Path(schema_dir) if schema_dir else None
        pw_cfg.otel_endpoint = config.get("otel_endpoint")
        pw_cfg.audit_retention_days = int(config.get("audit_retention_days", DEFAULT_AUDIT_RETENTION_DAYS))
        pw_cfg.api_key = os.environ.get("PICOWATCH_API_KEY") or config.get("api_key")
        pw_cfg.corpus_version = config.get("corpus_version", DEFAULT_CORPUS_VERSION)
        return pw_cfg

    # ─── WatchGuard Protocol Implementation ─────────────────────────────

    def scan_prompt(self, text: str, context: dict[str, Any] | None = None) -> PromptScanResult:
        """L5: Scan a prompt for injection patterns.

        Called by PicoShogun when a prompt event reaches L5 in the pipeline.
        Telemetry is automatically recorded.
        """
        result = self._prompt_guard.check(text, context=context)
        self._sink.record_prompt_scan(result, request_id=context.get("request_id") if context else None)
        return result

    def validate_output(
        self,
        output: str,
        schema: dict[str, Any] | None = None,
        prompt_result: PromptScanResult | None = None,
    ) -> ValidationResult:
        """L6: Validate an LLM output.

        Called by PicoShogun when an output event reaches L6 in the pipeline.
        Feedback loop: if prompt_result is flagged, output validation is stricter.
        Telemetry is automatically recorded.
        """
        result = self._output_guard.validate(output, schema=schema, prompt_result=prompt_result)
        self._sink.record_validation(result, request_id=None)
        return result

    def health(self) -> dict[str, Any]:
        """Return plugin health status for PicoShogun's pipeline monitor."""
        uptime = time.perf_counter() - self._start_time
        return {
            "plugin": self.name,
            "version": self.version,
            "layers": self.layers,
            "healthy": True,
            "rules_loaded": len(self._prompt_guard.rules),
            "corpus_hash": self._prompt_guard.corpus_hash,
            "corpus_version": self._pw_config.corpus_version,
            "uptime_seconds": round(uptime, 1),
        }

    # ─── PicoShogun Event Bus Integration ───────────────────────────────────

    def on_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Handle an event from PicoShogun's event bus.

        PicoShogun dispatches events to plugins. PicoWatch handles:
        - 'prompt_received' → L5 scan
        - 'output_generated' → L6 validation
        - 'health_check' → health status

        Returns result dict or None if event type is unknown.
        """
        event_type = event.get("type")

        if event_type == "prompt_received":
            return {
                "layer": 5,
                "action": "scan_prompt",
                "result": self.scan_prompt(
                    text=event.get("text", ""),
                    context=event.get("context"),
                ),
            }

        if event_type == "output_generated":
            prompt_result = None
            if "prompt_result" in event:
                pr = event["prompt_result"]
                prompt_result = PromptScanResult(
                    blocked=pr.get("blocked", False),
                    score=pr.get("score", 0.0),
                    rules_matched=pr.get("rules_matched", []),
                    corpus_hash=pr.get("corpus_hash", ""),
                    corpus_version=pr.get("corpus_version", ""),
                    duration_ms=pr.get("duration_ms", 0.0),
                )

            return {
                "layer": 6,
                "action": "validate_output",
                "result": self.validate_output(
                    output=event.get("output", ""),
                    schema=event.get("schema"),
                    prompt_result=prompt_result,
                ),
            }

        if event_type == "health_check":
            return {
                "layer": None,
                "action": "health",
                "result": self.health(),
            }

        return None  # Unknown event type — pass through

    # ─── Prometheus Metrics for PicoShogun ──────────────────────────────────

    def metrics(self) -> str:
        """Return Prometheus-formatted metrics for PicoShogun's aggregator."""
        return self._sink.render_prometheus()
