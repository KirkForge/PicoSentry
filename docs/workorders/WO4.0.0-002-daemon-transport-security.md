# WO4.0.0-002 — Sandbox daemon: transport security + availability

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (verified 2026-08-17, shipped in v2.1.2 — TokenAuth+RBAC interceptor + plaintext-bind refusal (grpc_transport/auth.py:77-102, server.py:74-88), servicer validate_command/timeout-clamp/cwd-confine/signature-verified policy (_servicer.py:29-62), ThreadingHTTPServer + scan worker pool (daemon/daemon.py:20,88), SIGTERM/SIGINT via helper thread + SIGHUP raw-socket rebind (daemon.py:355-397), policy-name traversal check in save (policy_versioned/store.py:80), queued webhook sink with drop counter (webhook_sink.py:29-56))
**Owner:** (unassigned — worktree `wo/4.0.0/daemon-transport`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/sandbox/grpc_transport/**`, `picosentry/sandbox/daemon/{daemon.py,handler.py,handler_routes_post.py,handler_mixins.py,webhook_sink.py}`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + new tests: gRPC unauthenticated Scan rejected; long scan in flight → `/health` responds <1s; SIGHUP keeps serving; policy-name traversal rejected.

## Objective
The HTTP daemon must not black out under load, signals must not kill it, and the gRPC transport must not be an auth bypass.

## Evidence (verified 2026-08-17)
1. **gRPC = unauthenticated arbitrary command** (CRITICAL): `grpc_transport/server.py:101` plaintext port by default; `_servicer.py:21-47` Scan RPC has no auth, no `_validate_command`, no timeout clamp, accepts caller-chosen `cwd`. QueryAudit exposes the audit log unauthenticated. `--transport grpc` (cli_commands/daemon.py:94-128) bypasses every HTTP control.
2. **Single-threaded daemon**: `daemon.py:18` plain `HTTPServer`; one 300s scan blocks /health, /metrics, gossip (k8s kills the pod).
3. **SIGTERM/SIGINT deadlock**: `daemon.py:288-293` calls `server.shutdown()` from a signal handler on the `serve_forever` thread.
4. **SIGHUP re-wraps the already-SSL socket** (daemon.py:302) — TLS-in-TLS, listener dead until restart.
5. **Path traversal write**: `handler_routes_post.py:324` + `policy_versioned/store.py:73-75` — user-supplied `policy.name` → `mkdir(parents=True)` + write, no sanitization (read path sanitizes; save doesn't). 5-line P0-hotfix-able.
6. Audit webhook sink synchronous: 4 retries × 10s ≈ 47s stall per audit event on the single thread.
7. `create_app(tokens=…)` is a silent no-op (app.py:22 sets env after TokenAuth built at import).

## Deliverables
1. gRPC: shared TokenAuth+RBAC interceptor, `_validate_command` + timeout clamp + tenant resolution, refuse plaintext bind beyond loopback (mirror serve `assert_secure`); until done, `--transport grpc` fails outside dev env.
2. `ThreadingHTTPServer`; scan execution via worker pool with real job states (store already models queued→running→completed).
3. Signal fixes (shutdown from a helper thread; SIGHUP rebinds raw socket).
4. Traversal fix (reuse load_policy's name check in save).
5. Webhook sink → bounded queue + drop counter (mirror serve audit-writer pattern).
