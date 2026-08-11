# WO2.0.0-008 — Audit fsync + Crash-Recovery

**Series:** WO2.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/2.0.0/audit-fsync`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/serve/ -m "not slow"`

## Objective
Close the audit-trail crash-recovery window. The review flags: "No `fsync` after write (crash-recovery window)."

## Root cause being addressed
The hash-chained audit log (JSONL + serve SQL) writes without `fsync`, so a crash can lose the most recent entries and break the chain's tamper-evidence guarantee.

## Scope
- `picosentry/serve/middleware/audit.py` — `fsync` the audit file after each write (or a configurable batch)
- `picosentry/serve/services/audit*.py` — same for the SQL audit path
- Add a config knob (e.g. `PICOSHOGUN_AUDIT_FSYNC`) defaulting to on for the audit log
- Verify the hash-chain reseed still works after a forced crash (re-open + append)

## Done-condition
- Audit writes are `fsync`'d (or batched with a documented ceiling)
- Chain integrity survives a simulated crash (re-open + append + verify)
- All gates green

## Notes
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
