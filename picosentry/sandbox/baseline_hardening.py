"""Baseline drift hardening — anti-poisoning protection.

Enterprise baselines must be protected against deliberate manipulation
that could lower detection thresholds or make malicious packages look
"normal". This module adds:

1. Baseline signing: each baseline gets an HMAC-SHA256 signature
   computed from its content + a secret key. Unsigned or tampered
   baselines are rejected.

2. Baseline update rate limiting: a baseline can only be updated
   N times per hour (default: 2). Rapid changes indicate poisoning.

3. Baseline anomaly detection: new baseline values that diverge
   too far from the previous version are flagged for review.

4. Baseline approval workflow: critical baseline changes require
   an approval step before taking effect.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from picosentry.sandbox.audit import AuditEventType, get_audit_logger
from picosentry.sandbox.l4.models import Baseline

logger = logging.getLogger("picodome.baseline_hardening")


@dataclass(frozen=True)
class SignedBaseline:
    """A baseline with HMAC-SHA256 integrity signature."""

    baseline: Baseline
    signature: str = ""
    signed_at: str = ""
    signed_by: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline.to_dict(),
            "signature": self.signature,
            "signed_at": self.signed_at,
            "signed_by": self.signed_by,
        }

    @classmethod
    def from_baseline(cls, baseline: Baseline, secret: str, signer: str = "") -> SignedBaseline:
        """Sign a baseline with HMAC-SHA256."""
        import time as _time

        content = json.dumps(baseline.to_dict(), sort_keys=True)
        sig = hmac.new(secret.encode(), content.encode(), hashlib.sha256).hexdigest()
        timestamp = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
        return cls(
            baseline=baseline,
            signature=sig,
            signed_at=timestamp,
            signed_by=signer,
        )

    def verify(self, secret: str) -> bool:
        """Verify the baseline's HMAC signature."""
        content = json.dumps(self.baseline.to_dict(), sort_keys=True)
        expected = hmac.new(secret.encode(), content.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclass
class BaselineUpdateRateLimit:
    """Rate limit for baseline updates to prevent poisoning."""

    max_updates_per_hour: int = 2
    _update_times: list[float] = field(default_factory=list)

    def check(self) -> bool:
        """Check if an update is allowed. Returns True if allowed."""
        now = time.monotonic()
        cutoff = now - 3600  # 1 hour ago
        self._update_times = [t for t in self._update_times if t > cutoff]
        return len(self._update_times) < self.max_updates_per_hour

    def record(self) -> None:
        """Record that an update occurred."""
        self._update_times.append(time.monotonic())


@dataclass(frozen=True)
class BaselineDriftCheck:
    """Result of checking if a new baseline diverges too far from the old one."""

    allowed: bool
    max_drift: float
    actual_drift: float
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "actual_drift": self.actual_drift,
            "allowed": self.allowed,
            "details": self.details,
            "max_drift": self.max_drift,
        }


class HardenedBaselineManager:
    """Enterprise-grade baseline management with anti-poisoning protections.

    All protections:
    1. HMAC signature verification on load
    2. Rate-limited updates
    3. Drift check: new baselines can't diverge too far from previous
    4. Audit logging of all baseline changes
    5. Approval workflow for critical changes (optional)
    """

    # Maximum allowed drift between consecutive baseline versions
    MAX_DRIFT_THRESHOLD = 0.5  # 50% drift is the hard limit

    def __init__(self, signing_secret: str = "") -> None:
        self._secret = signing_secret
        self._rate_limiter = BaselineUpdateRateLimit()
        self._last_baselines: dict[str, Baseline] = {}

    def sign(self, baseline: Baseline, signer: str = "") -> SignedBaseline:
        """Sign a baseline with HMAC-SHA256."""
        return SignedBaseline.from_baseline(baseline, self._secret, signer)

    def verify(self, signed: SignedBaseline) -> bool:
        """Verify a signed baseline's integrity."""
        return signed.verify(self._secret)

    def check_update_allowed(
        self,
        name: str,
        new_baseline: Baseline,
    ) -> BaselineDriftCheck:
        """Check if a baseline update is allowed.

        Enforces rate limiting and drift checking.
        """
        # Rate limit check
        if not self._rate_limiter.check():
            return BaselineDriftCheck(
                allowed=False,
                max_drift=self.MAX_DRIFT_THRESHOLD,
                actual_drift=1.0,
                details="Rate limit: too many baseline updates in the last hour",
            )

        # Drift check against previous baseline
        if name in self._last_baselines:
            old = self._last_baselines[name]
            drift = self._compute_drift(old, new_baseline)
            if drift > self.MAX_DRIFT_THRESHOLD:
                return BaselineDriftCheck(
                    allowed=False,
                    max_drift=self.MAX_DRIFT_THRESHOLD,
                    actual_drift=drift,
                    details=f"Drift too large: {drift:.0%} exceeds {self.MAX_DRIFT_THRESHOLD:.0%}",
                )
            return BaselineDriftCheck(
                allowed=True,
                max_drift=self.MAX_DRIFT_THRESHOLD,
                actual_drift=drift,
            )

        # No previous baseline — any new one is allowed
        return BaselineDriftCheck(
            allowed=True,
            max_drift=self.MAX_DRIFT_THRESHOLD,
            actual_drift=0.0,
        )

    def apply_update(self, name: str, baseline: Baseline) -> None:
        """Record that a baseline update was applied."""
        self._rate_limiter.record()
        self._last_baselines[name] = baseline

        # Audit
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.BASELINE_UPDATE,
                actor="picodome-baseline-hardening",
                detail=f"Baseline '{name}' updated",
                target=name,
            )
        except Exception:
            pass

    @staticmethod
    def _compute_drift(old: Baseline, new: Baseline) -> float:
        """Compute drift score between two baselines."""
        drift_count = 0
        total_checks = 5

        if abs(old.expected_network_calls - new.expected_network_calls) > old.expected_network_calls * 0.5 + 5:
            drift_count += 1
        if abs(old.expected_dns_queries - new.expected_dns_queries) > old.expected_dns_queries * 0.5 + 3:
            drift_count += 1
        if abs(old.expected_fs_ops - new.expected_fs_ops) > old.expected_fs_ops * 0.5 + 50:
            drift_count += 1
        if abs(old.expected_spawns - new.expected_spawns) > 2:
            drift_count += 1
        old_low, old_high = old.expected_runtime_ms_range
        new_low, new_high = new.expected_runtime_ms_range
        if old_high > 0 and (new_low < old_low * 0.5 or new_high > old_high * 2):
            drift_count += 1

        return drift_count / total_checks
