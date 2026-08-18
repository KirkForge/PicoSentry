# WO6.0.0-013 — Serve: transaction discipline — login lock-order inversion (15s stalls) + immediate-default read convoys + execute-in-tx guard

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/tx-discipline`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/serve/services/auth.py`, `picosentry/serve/database/manager.py`, audit of all 13 `transaction()` sites, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + tests: the login pattern under a concurrent writer completes fast (no 15s stall; no OperationalError); `db.execute*()` on a thread with open `_tx_depth` raises an actionable error (opt-in guard); invalid-login burst does not hold the write lock.

## Objective
The WO5-031 `immediate=True` default is right for read-check-then-write — but two call sites weaponize it against the reader/writer lock.

## Evidence (verified 2026-08-18, explorer SA-AR; live repro with real DatabaseManager, two threads)
1. **Lock-order inversion in login** (`auth.py:250` via `webauthn_credentials_for_user`, `:452-457`): thread holds BEGIN IMMEDIATE (sqlite write lock) then needs the ReadWriteLock READ half; a concurrent writer (1s scheduler lease tick, request inserts) negotiates the write half → writer-preferring lock starves the reader until busy_timeout kills the WRITER: `{'writer': OperationalError 15.06s, 'login': 15.16s}`. Only `db.execute*` call inside any transaction (13 sites audited).
2. **Invalid-login convoy** (`auth.py:222-228,251-259`): the whole login incl. the invalid-credential early return (a pure READ) runs inside the immediate transaction — a credential-stuffing burst takes the RESERVED lock per attempt on every worker (DDoS shield admits 50/10s per IP).

## Deliverables
1. `auth.py:250` → `execute_on(conn, …)` (or hoist above the transaction).
2. Login/TOTP restructure: reads via `execute_one` before the tx; `transaction(immediate=True)` only around write branches.
3. Guard: `execute()/execute_one()/execute_insert()` raise a helpful error when `_tx_depth > 0` on the calling thread (the execute_on-only rule is currently a latent trap).
4. Convoy test per the gate.
