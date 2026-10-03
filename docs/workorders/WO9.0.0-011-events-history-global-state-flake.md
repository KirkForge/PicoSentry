# WO9.0.0-011 — Serve: `/events/history` round-trip test depends on process-global `event_bus.event_history`, which app lifespan teardown wipes

**Series:** WO9.0.0 (audit round 2026-08-23; opened 2026-10-02 from CI run `37026978303`)
**Status:** OPEN — **root cause NOT confirmed** (5 reproduction attempts all green; see below)
**Owner:** (unassigned)
**Priority:** P2 · Effort S · Risk L
**Scope:** `picosentry/serve/services/event_bus.py`, `picosentry/serve/api/server.py` (295, 463), `tests/serve/test_wo6_events_history.py`, `tests/serve/test_killchain_tenancy.py` (precedent)

**Gate:** `bash scripts/test.sh integration tests/serve` green on 3.11 **and** 3.10, repeated ≥5×; plus a diagnostic assertion that fails with a named cause rather than `not in []`.

## Objective

`tests/serve/test_wo6_events_history.py::TestEventsHistoryRoundTrip::test_org_stamped_event_round_trips_with_uuid_id` failed once in CI (run `37026978303`, job `test-matrix (3.11)`, `integration` tier, 6002 passed / 1 failed):

```
AssertionError: published event id 'f3fbf073-f1a2-41e6-a1ae-8c0c5a518152' not in []
```

The endpoint returned an **empty list**. The event had just been published successfully (`publish()` returned a real `Event`), so history was empty *after* a successful append — meaning something cleared it in between, or the org filter hid it.

The test asserts against `event_bus`, a **process-global singleton**, while other tests in the same worker tear down the FastAPI app, and app lifespan teardown calls `event_bus.shutdown()`, which clears that global's history. That is a real, verified hazard (below). It is also **already known to this repo for the sibling field** — see precedent. What is *not* established is whether that is what fired here.

## Verified facts (2026-10-02)

- `event_bus.py:86` — `self.event_history: list[Event] = []` on a module-global singleton; `max_history = 1000`.
- **Writers, all under `self._lock`:** `event_bus.py:156` (`_dispatch`, the synchronous `publish()` path) and `event_bus.py:363` (outbox replay, pre-boot rows warm history only).
- **Clear sites — only three:** `event_bus.py:217` (`clear_history()`), `event_bus.py:225` (`shutdown()`), and the test's own autouse fixture at `tests/serve/test_wo6_events_history.py:19-22`.
- **`shutdown()` is called from app lifecycle:** `picosentry/serve/api/server.py:295` (lifespan teardown) and `:463` (SIGTERM handler). It clears `event_history` **and** all subscriber maps.
- **Precedent, same hazard, already worked around:** `tests/serve/test_killchain_tenancy.py:34-41` comments *"An app-lifespan teardown in an earlier test calls `event_bus.shutdown()` which clears ALL subscribers for the rest of the worker's life — re-register the production subscriber deterministically"* and re-registers `EnhancedOrchestrator()` when the subscriber count is 0. **Nobody applies the equivalent defence to `event_history`.** That asymmetry is the gap this WO tracks.
- **Org resolution is self-consistent, so it is NOT the cause.** `admin.py:113-115` computes `org_id = str(org["id"])` from `get_current_org`; `deps.py:144` returns `user_orgs[0]`; `/orgs` (`routers/orgs.py:31`) returns `Organization.list_orgs_for_user(user["id"])` — the *same* query, same `ORDER BY o.created_at DESC`. `_register_and_login` creates exactly one org. Both sides agree on "first org", so the tenant filter cannot explain `[]`.
- `PytestUnhandledThreadExceptionWarning` ("programmer bug — must propagate, kills thread") appears in the failing CI log **and** in healthy local runs (2 occurrences locally). Pre-existing, not specific to the failure.

## Reproduction attempts — all GREEN (why this is still OPEN)

| # | Configuration | Result |
|---|---------------|--------|
| R1 | the single test, 5× consecutive, py3.10 | 5 passed |
| R2 | whole `test_wo6_events_history.py` (autouse `clear_history` active), py3.10 | 3 passed |
| R3 | the single test, py3.11 (interpreter fetched via `uv -p 3.11`, same as failing job) | passed |
| R4 | `tests/serve` with integration-tier markers, `-n auto --dist=loadfile`, py3.11 | **778 passed**, 0 failed |
| R5 | CI re-run of the failed job `test-matrix (3.11)` on the same SHA | **success** |

Per AGENTS.md §6 this is **ESCALATE: root cause unknown** — do not ship a speculative fix. One plausible flake was fixed this session (`test_sandbox_blocks_file_write`, WO9.0.0-010) and one *proposed* fix was wrong; guessing twice more here is how a security suite acquires a test that asserts nothing.

## Why `loadfile` does not save it

`-n auto --dist=loadfile` gives each worker whole files, so two tests never run *simultaneously* in one process. But a worker runs file A's tests, tears A's app down, then runs file B's tests — sequentially, same process, **same global**. Serial execution prevents a data race; it does not prevent *ordering* to matter. Any test ordering that lands an app teardown where this test needs history is sufficient.

## Deliverables

1. **Add a named diagnostic to the test (do this first — it is what makes the next occurrence actionable).** Between `publish()` and the endpoint call, assert the event is actually in the bus:

   ```python
   assert any(e.id == event.id for e in event_bus.get_history(limit=1000)), (
       "history lost between publish() and query() — an app-lifespan teardown "
       "called event_bus.shutdown() (server.py:295), which clears the global history"
   )
   ```

   This is not a threshold change and not a rewrite to force green — it converts an unexplained `[]` into a named cause at the exact moment it happens. Lands in `11843c98`-style docs discipline: the assertion states *why* it can fail.
2. **Decide the ownership model for `event_history`.** Options: (a) stop clearing history in `shutdown()` — history is a query surface, not a resource, and the subscriber clear is the part that actually matters; (b) scope history per-app instead of per-process, so a teardown cannot wipe another tenant's view; (c) keep the clear and make the test file's fixture defensive the way `test_killchain_tenancy.py` is. (a) is the smallest and removes the hazard outright; (c) is the laziest but leaves the trap armed for the next test.
3. **Then** re-run R1–R5 ≥5× each on 3.10 and 3.11 before closing.
4. **Consider** extending the `test_killchain_tenancy.py` precedent into a shared conftest helper (e.g. `ensure_bus_subscribers_registered`) if (c) is chosen, so the workaround stops being copy-pasted per file.

## Traps

1. **Do not "fix" this by adding a retry, `xfail`, or relaxing the assertion.** A flaky failure must leave a name behind — that is why deliverable 1 is a diagnostic, not a skip.
2. **Do not assume the org filter is innocent because it looks suspicious.** It was checked: same query, same order, one org. `[]` is a *history* problem, not a *tenancy* problem.
3. **A green re-run is not a fix.** R5 passed on the identical SHA that failed. Only deliverable 1 turns that into information.
4. **The 500 ms budget test next door is load-sensitive** (`test_all_chains_1000_artifacts_under_500ms`, 0.27–0.31 s measured on an idle box, blew its budget at load average ~10). Do not bundle that flake into this WO — it is a separate wall-clock-budget problem (AGENTS.md: inject the clock, never assert on real sleeps).
5. **Reuse the trap list from WO9.0.0-010** — especially "clean `/tmp` before quoting a green number" and "zero grep hits means wrong needle, not absence". Both cost real conclusions on 2026-10-02.