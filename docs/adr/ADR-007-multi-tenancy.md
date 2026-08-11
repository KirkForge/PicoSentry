# ADR-007: Multi-tenancy / org-isolation model

**Status:** Accepted
**Date:** 2026-08

## Context

PicoSentry's serve orchestration API is multi-tenant: users belong to
organizations (`orgs`), and tenant data (project runs, intelligence, alerts,
metrics, webhooks, scheduled jobs, correlation chains, anomaly alerts) is
tagged with an `org_id`. The isolation model was partially implemented — most
data-bearing endpoints carried the `get_current_org` dependency and scoped
their queries by `org_id`, but two gaps remained:

1. **Correlation engine reads were not org-scoped.** The `CorrelationEngine`
   read methods (`kill_chain`, `critical_chains`, `all_artifact_ids`,
   `chains_summary`, `stats`) ignored the `org_id` carried on each
   `CorrelatedEvent`. The kill-chain cache was keyed by `artifact_id` only, so
   two tenants ingesting the same artifact could share a cached timeline — a
   cross-tenant data leak and a cache-collision bug.
2. **`GET /status` was not org-scoped.** It depended only on
   `get_current_user` and called `orchestrator.get_status()` with no `org_id`,
   returning global project-run / intelligence / alert counts to any
   authenticated user.

## Decision

**Every data-bearing serve endpoint is org-scoped, and the service layer
enforces the scope — not just the router.**

- The `get_current_org` dependency resolves the caller's org (from the
  `X-Org-API-Key` header when present, else the user's first org) and rejects
  callers with no org association. It is applied to every endpoint that reads
  or writes tenant data.
- The correlation engine now takes an `org_id` on every read method and
  filters events to those whose `org_id` is `None` (global) or matches the
  caller. The kill-chain cache key is `(org_id, artifact_id)`, so tenants
  never share a cached timeline.
- `GET /status` now depends on `get_current_org` and passes `org_id` into
  `orchestrator.get_status()`, which scopes the project-run, intelligence, and
  alert aggregates.

## Isolation guarantees

- **Default tenant:** `DEFAULT_TENANT` in `picosentry/sandbox/tenant/store.py`
  is the fallback tenant for scan-job store operations that do not specify a
  tenant. `TenantAwareScanJobStore` rejects cross-tenant job access.
- **Org scoping:** DB queries for tenant tables (`project_runs`,
  `intelligence`, `alerts`, `metrics`, `webhooks`, `scheduled_jobs`,
  `anomaly_alerts`, `correlation_events`) filter by `org_id`. The
  `build_filtered_query` helper in `picosentry/serve/database/helpers.py`
  always includes `WHERE org_id = ?`.
- **Project access:** `orchestrator.list_projects` / `get_project` /
  `run_project` / `generate_project_report` take an `org_id` and restrict to
  projects the org owns (`Organization.list_project_ids` / `has_project`).
- **Correlation:** events carry `org_id`; reads filter by it; the cache is
  keyed by `(org_id, artifact_id)`.
- **Admin/audit:** audit stats/purge and event history are scoped by `org_id`.

## Consequences

- A user with no org association is rejected (403) from all org-scoped
  endpoints. Registration creates a viewer; org creation is a separate step.
- `GET /status` now requires an org context. The `projects_total` and
  `threat_score` fields remain global (registry / in-memory intelligence
  engine are not per-tenant), but the DB-backed aggregates are org-scoped.
- The correlation engine's in-memory `_events` store is shared across tenants
  (a single process-wide buffer); reads are filtered per-org. This is a
  deliberate ceiling: per-tenant event buffers would multiply memory use.
  `ponytail: single shared event buffer, per-tenant buffers if memory allows`
  — upgrade path: partition `_events` by `org_id` when tenant event volume
  justifies it.
- Persistence of correlation events/chains does not yet write `org_id` to the
  `correlation_events` / `correlation_chains` tables; the in-memory read path
  is org-scoped. `ponytail: correlation persistence not org-tagged, add org_id
  column + migration when persistence is enabled in production` — upgrade
  path: extend the `add_org_id_to_tenant_tables` migration.
