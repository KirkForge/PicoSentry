# PicoSentry Extension Guide

This guide shows how to extend PicoSentry without touching its core engine. Each
extension type is self-contained and has a well-defined contract.

- [Add a scan detection rule](#add-a-scan-detection-rule)
- [Add a PicoWatch rule](#add-a-picowatch-rule)
- [Add a sandbox L3 backend](#add-a-sandbox-l3-backend)

---

## Add a scan detection rule

Scan rules live in `picosentry/scan/rules/` and are invoked by the scan engine
(`picosentry/scan/engine.py`). A rule is a plain Python callable that returns a
list of `Finding` objects.

### 1. Choose an implementation style

The engine accepts two rule shapes:

| Shape | Signature | Use when |
|-------|-----------|----------|
| Path-only | `fn(target_path: Path) -> list[Finding]` | Static analysis of files/metadata. |
| Path + corpus | `fn(target_path: Path, corpus_dir: Path) -> list[Finding]` | The rule needs the offline corpus (typosquat, IOC index, etc.). |

Rules are registered with a `rule_id` string. The engine groups rules by function
identity and runs them concurrently through a bounded thread pool.

### 2. Implement the rule

Create a new module under `picosentry/scan/rules/`, for example
`network_beacon.py`:

```python
from __future__ import annotations

from pathlib import Path

from picosentry.scan.models import Confidence, Finding, Severity


def detect_network_beacon(target: Path) -> list[Finding]:
    """Flag packages that reference well-known exfiltration endpoints."""
    findings: list[Finding] = []

    suspicious = target.rglob("*.js")
    for path in suspicious:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "attacker.example.com" in text:
            findings.append(
                Finding(
                    rule_id="L2-NETEX-999",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.EXACT,
                    package=target.name,
                    file=str(path.relative_to(target)),
                    message="Hard-coded attacker C2 domain",
                    evidence="attacker.example.com",
                    remediation="Remove the hard-coded domain and report the incident.",
                )
            )

    return findings
```

Best practices:

- Keep rules deterministic: no randomness, no wall-clock timeouts, no
  non-deterministic IDs.
- Respect `MAX_FILE_BYTES` / `MAX_FILES_PER_PACKAGE` limits to avoid blowing up
  on minified bundles.
- Return an empty list when nothing matches.
- Catch and log unexpected I/O errors rather than crashing the whole scan.

### 3. Register the rule

Rules are wired in `picosentry/scan/engine.py` (`create_default_engine`): import
your callable and register it, then add a metadata entry in
`picosentry/scan/rules/__init__.py` (`RULE_INFO`) so the rule is catalogued:

```python
# picosentry/scan/engine.py — inside create_default_engine()
from .rules.network_beacon import detect_network_beacon

engine.register("L2-NETEX-999", detect_network_beacon)
```

```python
# picosentry/scan/rules/__init__.py
"L2-NETEX-999": {
    "name": "network_beacon",
    "description": "Hard-coded attacker C2 domain",
    "severity": "CRITICAL",
    "category": "supply-chain",
},
```

Use a rule ID prefix that matches the existing scheme:

- `L2-*-TYPO-001` — typosquat (per ecosystem)
- `L2-*-DEPC-001` — dependency confusion
- `L2-*-OBFS-*` — obfuscation
- `L2-*-ADV-001` — advisory/CVE
- `L2-IOC-*` / `L2-NETEX-*` / `L2-INTEL-*` — IoC, network exfiltration, package intel

### 4. Add fixtures

Every rule needs a positive fixture (known-bad) and ideally a negative fixture
(known-good). Fixtures live under `tests/scan/fixtures/validation/`:

```text
tests/scan/fixtures/validation/
  positive/
    network_beacon_exfil/
      fixture.json
      package.json
      index.js
  negative/
    network_beacon_legit/
      fixture.json
      package.json
      index.js
```

A `fixture.json` looks like this (`label` must be exactly `positive` or
`negative`; optional keys: `expected_findings`/`unexpected_findings` assertion
objects, `forbidden_rule_ids`, `strict`):

```json
{
  "label": "positive",
  "description": "Reference to a hard-coded C2 domain",
  "expected_rule_ids": ["L2-NETEX-999"],
  "forbidden_rule_ids": []
}
```

Run the validation floor to confirm the new rule is calibrated:

```bash
picosentry scan --validate
python -m pytest tests/scan/test_validation.py -v
```

The CI floor (`test_validation_passes_at_100_percent_on_current_fixtures`) fails
below **85% mean precision / 70% mean recall** — known offline gaps (advisory,
dep-confusion rules) sit under that floor by design; if your rule raises false
positives on existing negative fixtures, adjust the pattern or add more
negatives.

---

## Add a PicoWatch rule

PicoWatch rules are YAML files. They are loaded from:

- `picosentry/watch/rules/prompt_injection/` — L5 prompt guard
- `picosentry/watch/rules/output_policy/` — L6 output guard

### 1. Write the rule YAML

```yaml
# picosentry/watch/rules/prompt_injection/my_new_category.yaml
- id: inj_my_custom
  category: instruction_override
  weight: 0.75
  pattern: "(?i)pretend\s+you\s+are\s+(?:the\s+)?developer"
  description: "Role-play as the system developer"
  normalization: [unicode, whitespace, comments]
```

Fields:

| Field | Meaning |
|-------|---------|
| `id` | Unique rule identifier. |
| `category` | One of the existing categories; used by the classifier for diversity scoring. |
| `weight` | 0.0–1.0 regex contribution to the final score. |
| `pattern` | Python-compatible regex string. Use `(?i)` for case-insensitive. |
| `description` | Human-readable explanation surfaced in results. |
| `normalization` | Which normalizers to apply before matching (`unicode`, `whitespace`, `comments`, `base64`, `url`, `rot13`). |

### 2. Test the rule

Add a unit test in `tests/watch/test_prompt_guard.py` or
`tests/watch/test_output_guard.py`, or simply run:

```bash
python -m pytest tests/watch/ -v -k "prompt"
```

The corpus hash is computed from the rule file contents, so adding a rule
changes the reported `corpus_hash` and `corpus_version`. Update any tests that
assert exact hash values.

### 3. Calibrate the classifier

If the new category changes the lexical classifier behavior, run the
classifier tests and adjust `tests/watch/test_prompt_guard.py` expectations.
The classifier is intentionally conservative: a single ambiguous keyword
should not block benign text.

---

## Add a sandbox L3 backend

The L3 sandbox dispatches commands to a `SandboxBackend` implementation based on
the `--backend` flag. Existing backends are in
`picosentry/sandbox/l3/backends/`.

### 1. Implement `SandboxBackend`

Subclass `picosentry.sandbox.l3.backends.base.SandboxBackend`:

```python
from __future__ import annotations

from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.models import Policy, SandboxResult


class FirejailBackend(SandboxBackend):
    @property
    def name(self) -> str:
        return "firejail"

    @property
    def isolation_level(self) -> str:
        return "namespace"

    @property
    def enforcement_guarantee(self) -> str:
        return "kernel_enforced"

    def is_available(self) -> bool:
        import shutil

        return shutil.which("firejail") is not None

    def run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> SandboxResult:
        # Build the sandboxed command from `policy.rules` and run it.
        # Return a SandboxResult with events and verdict.
        ...
```

Key responsibilities:

- `is_available()` — returns `True` only when the host supports this backend.
- `run(...)` — execute the command under the policy and return a `SandboxResult`.
- `name` — short identifier used by `--backend <name>`.
- `isolation_level` / `enforcement_guarantee` — metadata for reporting.

### 2. Register the backend

Edit `picosentry/sandbox/l3/backends/__init__.py` (`get_backend`):

1. Import the new backend.
2. Add a `if name == "firejail": ...` branch returning it (falling back to an
   available backend when `is_available()` is False).

### 3. Add tests

Add tests in `tests/sandbox/` that exercise the new backend when available and
skip cleanly when it is not. The existing tests use `pytest.mark.skipif` based
on backend availability — follow that pattern.

---

## General checklist

Before opening a PR for any extension:

- [ ] `ruff check picosentry/ tests/ scripts/` passes.
- [ ] `ruff format --check picosentry/ tests/ scripts/` passes.
- [ ] `mypy picosentry/` passes.
- [ ] New code has tests following existing conventions.
- [ ] Determinism is preserved (no randomness, no wall-clock timeouts in rules).
- [ ] Extension is documented in this guide if the pattern is novel.
