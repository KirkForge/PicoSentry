from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from picosentry.sandbox.audit import AuditEventType, get_audit_logger

if TYPE_CHECKING:
    from picosentry.sandbox.l4.models import Baseline

logger = logging.getLogger("picodome.baseline_hardening")


@dataclass(frozen=True)
class SignedBaseline:
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
        content = json.dumps(self.baseline.to_dict(), sort_keys=True)
        expected = hmac.new(secret.encode(), content.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclass
class BaselineUpdateRateLimit:
    max_updates_per_hour: int = 2
    _update_times: list[float] = field(default_factory=list)

    def check(self) -> bool:
        now = time.monotonic()
        cutoff = now - 3600  # 1 hour ago
        self._update_times = [t for t in self._update_times if t > cutoff]
        return len(self._update_times) < self.max_updates_per_hour

    def record(self) -> None:
        self._update_times.append(time.monotonic())


@dataclass(frozen=True)
class BaselineDriftCheck:
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
    MAX_DRIFT_THRESHOLD = 0.5  # 50% drift is the hard limit

    def __init__(self, signing_secret: str = "") -> None:
        self._secret = signing_secret
        self._rate_limiter = BaselineUpdateRateLimit()
        self._last_baselines: dict[str, Baseline] = {}

    def sign(self, baseline: Baseline, signer: str = "") -> SignedBaseline:
        return SignedBaseline.from_baseline(baseline, self._secret, signer)

    def verify(self, signed: SignedBaseline) -> bool:
        return signed.verify(self._secret)

    def check_update_allowed(
        self,
        name: str,
        new_baseline: Baseline,
    ) -> BaselineDriftCheck:

        if not self._rate_limiter.check():
            return BaselineDriftCheck(
                allowed=False,
                max_drift=self.MAX_DRIFT_THRESHOLD,
                actual_drift=1.0,
                details="Rate limit: too many baseline updates in the last hour",
            )

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

        return BaselineDriftCheck(
            allowed=True,
            max_drift=self.MAX_DRIFT_THRESHOLD,
            actual_drift=0.0,
        )

    def apply_update(self, name: str, baseline: Baseline) -> None:
        self._rate_limiter.record()
        self._last_baselines[name] = baseline

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
