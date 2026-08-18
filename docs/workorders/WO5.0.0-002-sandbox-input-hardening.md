# WO5.0.0-002 — Sandbox: untrusted-input hardening (NaN timeout, traversal, names, header charset)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** DONE (2026-08-18, merge `0846f177`, worker SA-W) — shared `sanitize_scan_timeout()` (isfinite + clamp, None=reject) at all 3 entry points (HTTP 400 `ErrorCodes.INVALID_TIMEOUT`, gRPC INVALID_ARGUMENT, `sandbox_run` pre-spawn ValueError; non-numeric now 400); retention `_package_slug()` (basename+slug, both callers); all-dot policy names rejected (write + read paths); X-Request-ID `[A-Za-z0-9_-]{1,128}`; 16 tests incl. real-daemon NaN POST (engine canary never fired, no job persisted) + raw-socket obs-fold repro.
**Owner:** (unassigned — worktree `wo/5.0.0/sandbox-input`)
**Priority:** P0 · Effort M · Risk L
**Scope:** `picosentry/sandbox/daemon/{handler_routes_post.py,handler_mixins.py}`, `picosentry/sandbox/grpc_transport/_servicer.py`, `picosentry/sandbox/retention/manager.py`, `picosentry/sandbox/policy_versioned/store.py`, `picosentry/sandbox/l3/**` (timeout consumers), `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + new tests: `{"timeout": NaN}` POST → clean 400 (child never spawned); `package_name` traversal payload writes nothing outside scans dir; policy name `"."` rejected; folded-header `X-Request-ID` rejected.

## Objective
Every value an unauthenticated-or-tokened client controls must be validated once, at the shared entry points — not per-backend.

## Evidence (verified 2026-08-18, explorer SA-S; live repros)
1. **Non-finite `timeout` accepted end-to-end** (HIGH): `handler_routes_post.py:160-163` `float(data.get("timeout", 30.0))` — `json.loads` accepts `NaN`; no `isfinite` anywhere. subprocess backend: `communicate(timeout=nan)` → unhandled `ValueError` (client gets no response, child orphaned unbounded); landlock: `deadline` nan → poll loop forever. Same in `_servicer.py:37-40`. Live: `sandbox_run(["sleep","6"], timeout=nan)` → `ValueError: cannot convert float NaN to integer` from selectors.
2. **Retention path traversal via `command[0]`** (MEDIUM): `handler_routes_post.py:374-377` passes raw `package_name=command[0]`; `retention/manager.py:105-117` builds the filename from it. Live: `"../../sensitive/evil"` wrote outside the scans dir.
3. **`_validate_policy_name` accepts `"."`**: `policy_versioned/store.py:29-34` — `".." in "."` is False → save mkdirs the store root, writes `v1.json`/`latest.json` at top level, `list_policies` polluted; `"latest.json"` becomes a directory.
4. **X-Request-ID obs-fold reflection**: `handler_mixins.py:32-36` accepts any ≤128 chars, no charset check. Live: folded header came back as `X-Request-ID: legit\n\tEvil-Header: injected-value` (bare-LF header continuation).

## Deliverables
1. One shared guard (`math.isfinite` + clamp) applied at all three entry points (HTTP, gRPC servicer, `sandbox_run`).
2. Retention: `Path(package_name).name` + slug.
3. Reject empty/dot components in policy names.
4. `X-Request-ID` restricted to `[A-Za-z0-9-_]`.
