# WO5.0.0-008 — Serve: alerting truthfulness (sent=1 on failed delivery, webhook clobber, auto-analysis no-op)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/alerting-truth`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/serve/services/{alert_hub.py,webhooks.py,orchestrator.py,correlation/engine.py}`, `picosentry/serve/api/routers/{webhooks,orgs}.py`, `picosentry/serve/database/_schema.py` (webhooks index), `picosentry/serve/api/server.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new tests: unreachable webhook → row `sent=0`, `send()` False, retry counted; two orgs create the same webhook name → both dispatch correctly; auto-analysis either runs the downstream project or its chain/logs are gone.

## Objective
Escalations must not silently fail: delivery failures recorded as failures, webhook identity per-org, and the advertised auto-analysis chain either real or deleted.

## Evidence (verified 2026-08-18, explorer SA-T; live repros)
1. **Failed deliveries recorded sent=1** (HIGH): `_discord_notify`/`_slack_notify`/`_email_notify` catch their own exceptions (`alert_hub.py:170-175,201-204,214-250`), so the outer `except _ALERT_CHANNEL_ERRORS` (`:114-122`) never sees them; row marked `sent=1` (`:107-112`), `send()` → True. Live with unreachable webhook: full traceback logged, row `{'channel':'discord','sent':1,'retry_count':0}`. `pending_alerts`, `get_alert_stats`, `max_retries` machinery dead in practice. Only syslog/DB errors propagate.
2. **Webhook name is a global namespace** (HIGH): no UNIQUE on `webhooks.name` (`_schema.py:347-357`); `_load_webhooks` keys by name (`webhooks.py:109-133`, later row wins); create takes arbitrary names per org. Live: org 1 + org 2 both create `"ops-alerts"` → dict holds org 2's; `dispatch(org_id=1)` returned `[]` — org A's escalation webhook silently never fires; `GET /webhooks` for org A empty despite its DB row.
3. **Auto-analysis is a logged no-op**: `_trigger_cross_layer_analysis` (`correlation/engine.py:243-297`) → `_on_auto_analyze` (`server.py:168-200`) publishes `project.run.requested`; exactly one repo-wide reference (the publish site). No subscriber — "Auto-analyze queued: picosentry → picodome" is a lie; the `_AUTO_ANALYSIS_MAP` chaining never executes.

## Deliverables
1. Channel errors propagate to the sent/retry bookkeeping; bounded retry for unsent alerts.
2. Webhooks keyed by id; per-org unique names (unique index `(org_id, name)`); 409 on cross-org collision.
3. Auto-analysis: implement the `project.run.requested` consumer or delete chain + map + "queued" logs (owner decision — deletion is the lazy default).
