# ADR-008: Serve orchestration API

**Status:** Accepted
**Date:** 2026-08

## Context

The serve component is the "command centre" for the Pico Security Series: it
coordinates the scanner, sandbox, and watch subsystems, tracks project runs,
extracts intelligence, correlates events, and exposes the result over a
FastAPI surface. The orchestration engine and the HTTP API are the two halves
of this control plane, and their shape is a deliberate architectural decision.

## Decision

**A single `EnhancedOrchestrator` singleton (`picosentry/serve/services/orchestrator.py`)**
is the async execution engine. It:

- loads a project registry from a JSON file (`REGISTRY_PATH`) into
  `ProjectMeta` objects and mirrors them into the `projects` table at startup;
- runs projects as subprocesses (`subprocess.run`) with a validated command
  and a per-argument allowlist regex (`^[a-zA-Z0-9_.-]+$`), under a
  `threading.Semaphore` bounded by `settings.orchestrator.max_concurrent_projects`;
- records each run in `project_runs` (status `running` → `completed`/`failed`/
  `timeout`), extracts intelligence from stdout+stderr, updates per-project
  stats, and emits metrics;
- publishes lifecycle events (`project.run.started`, `project.run.completed`,
  `project.run.failed`) on the in-process `event_bus`, which the correlation
  engine and auto-analysis subscribers consume;
- dispatches to the `plugin_manager` (`project_complete`, `alert`) and sends
  alerts via `AlertHub` on failure/timeout;
- exposes read/query methods (`get_status`, `list_projects`, `get_project`,
  `list_intelligence`, `get_correlations`, `get_threat_score`, `list_alerts`,
  `get_metrics`, `get_health_checks`, `generate_summary_report`,
  `generate_project_report`) — all org-scoped via an optional `org_id`.

**The HTTP surface (`picosentry/serve/api/`) is a thin router layer over the
orchestrator and services.** `server.py` builds the FastAPI app, wires a
defense-in-depth middleware stack (audit, rate-limit, CORS, gzip, DDoS shield,
request-size, request-id, security headers, request-timeout, HTTPS
enforcement, docs restriction, CORS hardening), and includes routers for
`health`, `projects`, `auth`, `orgs`, `plugins`, `webhooks`, `scheduler`,
`admin`, `anomaly`, `correlation`, `metrics`, `ws`, `dashboard`, and `scans`.
Auth is centralized in `deps.py` (`get_current_user`, `require_role`,
`require_permission`, `get_current_org`, `require_org_membership`). The
`lifespan` handler starts the anomaly detector and scheduler, wires the alert
hub and correlation escalation callbacks, and schedules periodic cleanup,
backup, and health-check jobs.

## Rationale

- **One engine, many views:** a single orchestrator keeps run lifecycle,
  intelligence extraction, alerting, and plugin dispatch in one place, so the
  API routers stay thin and consistent rather than each re-implementing run
  logic.
- **Event-driven decoupling:** the `event_bus` lets the correlation engine and
  auto-analysis react to run completion without the orchestrator knowing about
  them, keeping the engine focused on execution.
- **Concurrency bounded by a semaphore** prevents unbounded subprocess
  fan-out while still allowing parallel runs.
- **Command validation is defense-in-depth:** the allowlist regex on CLI args
  and `_validate_project_command` reject unsafe arguments before
  `subprocess.run`, so a compromised registry entry cannot inject shell
  metacharacters.
- **Org scoping is threaded through every query** so the same engine serves
  both single-tenant and multi-org deployments.

## Consequences

- The orchestrator runs subprocesses synchronously under a semaphore; long
  runs block a worker thread, so concurrency is limited by
  `max_concurrent_projects` and the worker pool.
- The project registry is a JSON file loaded at startup; adding a project
  requires a restart (or a registry edit + reload).
- The API surface is broad (14 routers) and each router depends on the shared
  `deps.py` auth model; adding a new endpoint must follow the
  `get_current_org`/`require_role` pattern to stay org-scoped and authorized.
- The middleware stack is order-sensitive; new middleware must be inserted
  with the correct precedence relative to audit and rate limiting.
- `run_batch` runs projects sequentially in a loop, not in parallel, despite
  the semaphore — a known ceiling for batch throughput.
