# WO9.0.0-108 — Scan daemon: SIGTERM handler calls `server.shutdown()` from the thread running `serve_forever()` — deadlock

**Series:** WO9.0.0 (found 2026-10-21 while investigating the CI 3.13 hang; unrelated to that hang)
**Status:** OPEN
**Owner:** (unassigned)
**Priority:** P1 · Effort S · Risk M
**Scope:** `picosentry/scan/daemon/__init__.py` (100-106, 124-128), `tests/scan/test_daemon*.py`

**Gate:** `bash scripts/test.sh fast` + a test that starts a REAL daemon on a loopback port, sends SIGTERM, and asserts the process exits (bounded by a timeout) instead of hanging.

## Objective

`run_daemon` registers a signal handler that calls `server.shutdown()`, and runs
`server.serve_forever()` **on the main thread**:

```python
# picosentry/scan/daemon/__init__.py:100
def shutdown(signum: int, _frame: Any) -> None:
    logger.info("Received signal %d, shutting down daemon...", signum)
    audit("daemon.stop", target=f"{host}:{port}", metadata={"signal": signum})
    server.shutdown()          # <-- blocks until serve_forever() returns

signal.signal(signal.SIGTERM, shutdown)   # :105
signal.signal(signal.SIGINT, shutdown)    # :106
...
server.serve_forever()                     # :124  (main thread)
```

`socketserver.BaseServer.shutdown()` documents that it "must not be called from the
same thread running `serve_forever()`" — it waits on `__is_shut_down`, an event only
`serve_forever()`'s own exit path can set. A signal handler runs on the main thread,
and the main thread is by definition the one inside `serve_forever()`. So the handler
blocks inside `shutdown()` while the thread that would set the event is the handler
itself. The daemon never exits, and the `finally: server.server_close()` at line 128
is never reached either, so the socket is not closed.

The observable effect is the same shape as a hung CI job: `docker stop`, systemd
`stop`, and CI teardown all wait on a process that will not exit, until the kill
timeout. The daemon is what `picosentry daemon` runs, and the container image's
entrypoint is `picosentry`.

## Evidence (verified 2026-10-21, live repro — both directions proven)

- **Deadlock (the daemon's actual shape: `serve_forever()` on the main thread).**
  Repro: a plain `http.server.HTTPServer` with a SIGTERM handler calling
  `server.shutdown()`, served via `serve_forever()` on the main thread. The
  process printed `SIGTERM -> shutdown()` and **never returned** — it was killed
  by the repro's own timeout (`exit=124`). The handler ran TWICE (SIGTERM
  re-entered the handler while the first invocation was still blocked).
- **Not a deadlock in the other shape (control).** Same server, same handler, but
  `serve_forever()` moved to a worker thread: `shutdown()` returned cleanly. This
  isolates the cause to *same-thread*, not to `shutdown()` itself and not to
  signal handling in general.
- `picosentry/scan/daemon/__init__.py:100-106` (handler + `signal.signal`) and
  `:124` (`server.serve_forever()` on the main thread) — file:line chain above.
- **No test exercises this.** `tests/scan/test_daemon_extended.py:331` patches
  `picosentry.scan.daemon.HTTPServer` outright, so the real serve loop and the
  real handler never run. `tests/scan/test_daemon.py` imports `HealthHandler`
  only. Nothing sends a real SIGTERM to a live daemon.

## Deliverables

1. Fix the shutdown path so SIGTERM/SIGINT terminate the daemon. Options:
   - run `serve_forever()` on a worker thread and call `shutdown()` from the
     main thread (the documented-safe shape);
   - set the shutdown flag without waiting (e.g. `server._BaseServer__shutdown_request = True`),
     so the handler returns immediately and `serve_forever()` exits on its next poll;
   - have the handler set a `threading.Event` that the serve loop polls.
   Whichever is chosen, the handler must not BLOCK.
2. Regression test: start a real daemon on a loopback port, send SIGTERM, and
   assert the process exits within a bounded time. It must not mock
   `HTTPServer` — the bug is in the interaction between the handler and the real
   serve loop, so mocking either half hides it.
3. Confirm the container path: `docker stop` on an image running `picosentry daemon`
   must not wait for the kill timeout.

## Notes

- Found while investigating an unrelated 3-hour CI hang on 2026-10-21 (that hang
  was a runner flake — see lessons.md). Left as its own WO rather than folded
  into the WO9.0.0 P0 cluster, whose diff was already scoped and gated.
- Severity is P1 rather than P0: it needs a SIGTERM to a live daemon, it degrades
  to "slow shutdown" rather than data loss, and the kill timeout still reaps the
  process. It is P1 because every container stop and CI teardown of the daemon
  pays the full timeout.
