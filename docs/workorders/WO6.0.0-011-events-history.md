# WO6.0.0-011 — Serve: `GET /events/history` 500s for any org with events (uuid id vs int model) + system-event visibility parity

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/events-history`)
**Priority:** P0 · Effort S · Risk L
**Scope:** `picosentry/serve/api/models.py`, `picosentry/serve/api/routers/admin.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: publish one org-stamped event → history 200 with the row round-tripping (id as str); org admins see `org_id=None` system events (or an `include_system` flag) consistent with WS broadcast semantics.

## Objective
The latent-500 class again: masked by empty histories in every existing test.

## Evidence (verified 2026-08-18, explorer SA-AR; live TestClient repro)
`Event.id` is `str(uuid.uuid4())` (`event_bus.py:108`); `EventHistoryItem.id: int` (`models.py:488`). Live: publish `org_id=str(org)` → GET `/events/history` → **500 ResponseValidationError int_parsing**. Orgs with events get 500; orgs without get `200 []` — which is all tests check (`test_integration_services.py:127-137` asserts only 200 on empty). Additionally `admin.py:106` filters out `org_id=None` system events that the WS manager broadcasts to every org (`websocket_manager.py:157-162`) — admins lose scheduler/backup events from the queryable surface while their WS clients receive them.

## Deliverables
1. `EventHistoryItem.id: str`; content-asserting test (publish → round-trip).
2. System-event visibility parity (include None-org for org admins or a flag), matching WS semantics.
