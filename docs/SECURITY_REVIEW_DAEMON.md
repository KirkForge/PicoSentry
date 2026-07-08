# PicoSentry `sandbox daemon` Security Review

**Scope:** `picosentry sandbox daemon` long-running policy enforcement daemon
(`picosentry/sandbox/daemon/`, `picosentry/sandbox/cli_commands/daemon.py`).
**Date:** 2026-07-06
**Status:** Beta — functional and tested, but missing formal security review
and operational runbook coverage before Enterprise graduation.

## Reviewed areas

| Area | Verdict | Notes |
|------|---------|-------|
| Network binding | PASS | Defaults to `127.0.0.1`; operator must explicitly override. |
| TLS/mTLS | PASS | `picosentry.sandbox.mtls.create_ssl_context()` wraps the HTTPServer when env-configured; mTLS certs verified. |
| Authentication | PASS | `PICODOME_DEV_MODE` disables auth; production uses token validation. Legacy `simple:` tokens rejected. |
| Rate limiting | PASS | Per-actor token bucket + global RPS cap; health/readiness exempt as required. |
| Audit logging | PASS | Audit sinks (null/file/syslog/webhook) are opt-in; daemon start/stop recorded. |
| Job store backends | PASS | JSONL (default) and SQLite backends; backend selected via `PICODOME_STORE_BACKEND`. |
| Signal handling | PASS | `SIGINT`/`SIGTERM` handlers install cleanly for graceful shutdown. |
| gRPC transport | PASS | Optional gRPC server available if grpcio installed; not enabled by default. |

## Honest limitations (Enterprise blockers unless accepted as risk)

- **No dedicated security review.** This document is a self-assessment. A
  professional or adversarial review of the daemon HTTP/gRPC surface has not
  been performed.
- **No operator runbook section.** `docs/ops/runbook.md` does not cover daemon
  deployment, certificate rotation, backup/restore of the job store, or
  disaster recovery.
- **Metrics endpoint has no auth.** The optional separate metrics port logs
  "no auth required". In a shared network this can leak operational data.
- **Audit sink failures are warnings, not fatal.** If the configured sink
  (webhook/syslog/file) cannot start, the daemon logs a warning and continues.
  Fail-closed operation is not available.
- **SQLite job store under concurrency.** SQLite backend has a single writer;
  high-concurrency multi-node deployments should prefer the JSONL backend or
  a future shared store.
- **Cluster token is a single shared secret.** When cluster mode is enabled,
  all peers share one token; there is no token rotation or certificate pinning.

## Regression tests

- `tests/sandbox/test_daemon_handler.py` — routing, lifecycle, cluster manager
  integration.
- `tests/sandbox/test_daemon_hardening.py` — health exemptions, rate limiting,
  secure-boot checks.
- `tests/sandbox/test_daemon_store.py` — job store persistence.

Run the focused suite:

```bash
uv run pytest tests/sandbox/test_daemon_handler.py \
  tests/sandbox/test_daemon_hardening.py tests/sandbox/test_daemon_store.py -q
```

## Graduation criteria to Stable

- Complete an adversarial review of `picosentry/sandbox/daemon/` and the gRPC
  transport surface.
- Add a daemon operations section to `docs/ops/runbook.md` covering deployment,
  cert rotation, job-store backup/restore, and incident response.
- Decide the metrics endpoint security model: either require auth/mTLS or
  document it as intentionally internal-only.
- Add a fail-closed audit-sink mode or document accepted risk.
- Optionally implement token rotation / certificate pinning for cluster mode,
  or keep cluster mode Beta while daemon itself graduates.
