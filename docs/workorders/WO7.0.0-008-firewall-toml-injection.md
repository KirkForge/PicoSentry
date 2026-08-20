# WO7.0.0-008 — Firewall: TOML injection via URL-path package name

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/firewall-toml-injection`)
**Priority:** P1 · Effort S · Risk M
**Scope:** `picosentry/firewall/scanner.py`, `tests/firewall/`

**Gate:** `bash scripts/test.sh fast` + test: a path whose decoded name contains `'`, `\n`, `]`, `#` produces a `pyproject.toml` that fails to add new sections or keys (rejected or escaped), and the scan still completes.

## Objective
`classify_path` decodes `%27`→`'`, `%0a`→`\n`; `scan_metadata` interpolates the raw name into `f"[project]\nname = '{name}'"`. A name containing `'` closes the TOML string, a newline starts a new section — attacker controls synthetic pyproject.toml.

## Evidence (verified 2026-08-20, explorer SA-watch; file:line chain)
- `scanner.py:158-164`: `scan_metadata` builds the TOML string by f-string interpolation of the decoded path name.
- `scanner.py:75-93`: `classify_path` calls `urllib.parse.unquote` before the name reaches `scan_metadata`.
- Injecting `evil%27%0a[tool.evil]%0acmd` yields a pyproject.toml with a new `[tool.evil]` section.

## Deliverables
1. Sanitize the name before writing (strip/escape `'`, `\n`, `]`, `#`, `\r`); reject names that can't be made safe.
2. Regression test per the gate.