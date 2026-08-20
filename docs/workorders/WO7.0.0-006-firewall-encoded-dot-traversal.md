# WO7.0.0-006 — Firewall: encoded-dot path traversal bypasses `_safe_upstream_path` (SSRF on upstream)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/firewall-encoded-dot`)
**Priority:** P0 · Effort S · Risk M
**Scope:** `picosentry/firewall/proxy.py`, `picosentry/firewall/scanner.py`, `tests/firewall/`

**Gate:** `bash scripts/test.sh fast` + test: `/foo/%2e%2e/bar` and `/foo/..%2fbar` are rejected by `_safe_upstream_path` identically to literal `/foo/../bar`; no upstream path outside the allowlist is reachable.

## Objective
`_safe_upstream_path` rejects literal `..` but never percent-decodes; `classify_path` unquotes BEFORE matching. A client sending `%2e%2e` reaches arbitrary paths on the upstream — SSRF.

## Evidence (verified 2026-08-20, explorers SA-scan AND SA-watch — deduped; file:line chain)
- `proxy.py:45-54`: `_safe_upstream_path` checks for `..` on the raw path; no `urllib.parse.unquote`.
- `scanner.py:75-93`: `classify_path` unquotes the path first, then matches — so the classifier and the guard see different strings.
- Live: `/pkg/%2e%2e/admin/metrics` reaches upstream `/admin/metrics` while the guard records a clean path.

## Deliverables
1. `unquote` the path in `_safe_upstream_path` before the `..` check (and any other traversal pattern); reject on match.
2. Regression test per the gate covering `%2e`, `%2E`, `%2f`, mixed-encoding.