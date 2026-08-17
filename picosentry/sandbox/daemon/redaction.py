"""Withhold exfiltrated secret material from scan responses (WO4.0.0-010).

SUS-003/008/009 detect secret exfiltration (sensitive files, /proc
introspection, SSH keys) — but the detection used to ship the exfiltrated
bytes right back to the caller in stdout/stderr, and the job store + retention
persisted them verbatim. On a hit we replace the output with a redaction
marker plus sha256 and length, and flag the redaction for callers.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from picosentry.sandbox.l3.models import SandboxEvent

# L3 rules whose pattern hit means the captured output likely CONTAINS secret
# material, not just mentions it.
_SECRET_EXFIL_RULES = frozenset({"L3-SUS-003", "L3-SUS-008", "L3-SUS-009"})

_REDACTED_MESSAGE = "[redacted by picodome: suspected secret exfiltration]"


def output_was_redacted(sandbox_dict: dict[str, Any]) -> bool:
    return bool(sandbox_dict.get("stdout_redacted") or sandbox_dict.get("stderr_redacted"))


def redact_sandbox_output(sandbox_dict: dict[str, Any], events: list[SandboxEvent]) -> dict[str, Any]:
    """Mutate *sandbox_dict* in place: on a secret-exfil pattern hit, replace
    stdout/stderr with a marker + sha256 + length. Returns the same dict."""
    if not any(getattr(e, "rule_id", "") in _SECRET_EXFIL_RULES for e in events):
        return sandbox_dict

    for key in ("stdout", "stderr"):
        value = sandbox_dict.get(key)
        if isinstance(value, str) and value:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            sandbox_dict[f"{key}_sha256"] = digest
            sandbox_dict[f"{key}_len"] = len(value)
        sandbox_dict[key] = _REDACTED_MESSAGE
        sandbox_dict[f"{key}_redacted"] = True
    return sandbox_dict
