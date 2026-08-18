# WO6.0.0-009 — Serve: outbox correctness pack — poller dies on postgres (naive timestamps) + N× escalation delivery across workers

**Series:** WO6.0.0 (exploration round 2026-08-18 evening; found independently by TWO explorers — SA-AR and SA-AU)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/outbox-correctness`)
**Priority:** P0 · Effort M-L · Risk M
**Scope:** `picosentry/serve/services/event_bus.py`, `picosentry/serve/services/orchestrator.py` (+ correlation/alert seams as needed for the demux), `picosentry/serve/database/_schema.py` (optional migration 23), `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + tests: two-bus outbox fanout → exactly ONE alert row / ONE webhook per logical run; strict-psycopg2-fake poller test with naive datetimes survives and dispatches; poller survives a held-write-lock prune; liveness surfaced (gauge or health bit) when the thread dies.

## Objective
The WO5-031 outbox (multi-worker fanout) has two fatal flaws found post-landing: the poller thread dies permanently on the natural multi-worker backend (postgres), and when it works it MULTIPLIES side-effect subscribers (every worker re-fires escalation).

## Evidence (verified 2026-08-18)
1. **Poller death on pg** (HIGH; repro /tmp/opencode/sa-au/repro_pg_poller.py + sa-ar fakes): migration 22 declares `created_at TIMESTAMP` (no tz, `_schema.py:1012`) → psycopg2 returns naive datetimes; `_drain` compares against tz-aware `_started_at` (`event_bus.py:238,276`) → `TypeError ∉ _POLL_ERRORS` (`:28-32` = OSError/RuntimeError/ValueError only) → escapes `_run`, kills the daemon thread on the FIRST foreign event. Cross-worker fanout 100% dead on pg, silently (no liveness anywhere). Collateral: dead poller stops `_maybe_prune` → unbounded outbox growth. Sqlite sibling: prune DELETE under a ≥15s `BEGIN IMMEDIATE` holder raises `sqlite3.OperationalError` — also not in `_POLL_ERRORS` (contention-gated death).
2. **N× escalation delivery** (CRITICAL for alerting truthfulness; repro sa-au): `_drain` dispatches foreign rows to ALL local subscribers (`event_bus.py:283`) — correct for WS, fatal for the side-effectful orchestrator subscriber (`orchestrator.py:69-78`, registered on EVERY worker) → every worker independently reaches the same escalation decision (pure function of shared DB state) → `_chain_escalated_alert` (AlertHub.send: SMTP/Discord/Slack + alerts rows) ×N with per-process in-memory cooldown (`alert_hub.py:46,70-82`) never suppressing cross-worker. 4 workers = 4 alert rows + 12 channel deliveries per escalation — a false-outage signal generator in a security product. (WO5-033 made wildcard webhooks actually dispatch in the same wave that multiplied dispatchers.)

## Deliverables
1. tz-coercion at the DB boundary (`naive → replace(tzinfo=utc)`) in `_drain`; widen `_POLL_ERRORS` to include `TypeError, sqlite3.Error, psycopg2.Error` (mirror `scheduler.py:31`); liveness gauge/health bit on thread exit. Optional migration 23 rider: `TIMESTAMPTZ`.
2. Side-effect demultiplexing: foreign rows → history + WS only, not side-effect subscribers (fanout-tag `local_only` on the correlation subscriber), OR DB-claimed single-shot side effects (dedupe key unique on alerts + webhook claim row).
3. The two-EventBus regression test from the gate.
