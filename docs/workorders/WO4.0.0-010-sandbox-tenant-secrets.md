# WO4.0.0-010 — Sandbox: tenant wiring + secret hygiene

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/4.0.0/sandbox-tenant-secrets`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/sandbox/tenant/**`, `picosentry/sandbox/daemon/{daemon.py,handler_routes_*.py}`, `picosentry/sandbox/l3/engine.py`, `picosentry/sandbox/l3/backends/_env_defaults.py` (new shared module), `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + new tests: cross-tenant daemon read denied (job + stdout); planted-secret regression extended to daemon path; env allowlist parity test across all backends.

## Objective
Enforce the tenancy the code already implements, stop returning exfiltrated secrets to callers, and make the sandbox env contract an allowlist.

## Evidence (verified 2026-08-17)
1. `TenantAwareScanJobStore` (tenant/store.py, full cross-tenant checks) has ZERO production callers — daemon uses the raw store (daemon.py:56-64); `_handle_get_scan` + `/scans` list have no tenant scoping; tenant_id resolved for audit metadata only, never persisted (column exists). Any scan:read token reads any tenant's job incl. full stdout.
2. Exfiltrated secrets flow back: seccomp SAFE baseline grants global open/read (syscall-level only, paths ignored) → `cat ~/.ssh/id_ed25519` succeeds; SUS-009 *detects* it but the response/job store/retention contain the key verbatim.
3. `engine.py:321` env=None → child gets daemon env minus a suffix denylist (`_SECRET|_PASSWORD|_TOKEN|_KEY$` only — `SECRET_KEY_FILE`, `*_APIKEY`, `KUBECONFIG`, `SSH_AUTH_SOCK` pass). Backends' curated 4-var allowlists are dead code on this path; subprocess backend's 18-var list diverges — env parity inverted (fallback richest).

## Deliverables
1. Wire `TenantAwareScanJobStore` into the daemon; persist tenant_id on add; scope get/list.
2. Redact/withhold stdout on SUS-003/008/009 pattern hits (store hash + length, return flag).
3. Env ADR decision: default allowlist (one shared module, subprocess's 18-var set) on the env=None path, documented exceptions; parity test across backends.
