# PicoSentry Internal API Map

This document maps the key internal entry points per component. It is intended
for contributors who need to navigate the codebase quickly.

## Component index

| Component | Path | Responsibility |
|-----------|------|----------------|
| CLI | `picosentry/cli.py` | Top-level `picosentry` command dispatcher. |
| Scan engine | `picosentry/scan/engine.py` | Runs detection rules against a package path. |
| Scan rules | `picosentry/scan/rules/` | Detection rule implementations. |
| Scan models | `picosentry/scan/models.py` | `Finding`, `ScanResult`, `RuleExecution`, etc. |
| Scan validation | `picosentry/scan/validation.py` | Fixture-based precision/recall floor. |
| Sandbox L3 | `picosentry/sandbox/l3/` | Syscall policy enforcement. |
| Sandbox L4 | `picosentry/sandbox/l4/` | Behavioral analysis of sandbox events. |
| Sandbox models | `picosentry/sandbox/models.py` | Shared sandbox data models. |
| Watch prompt guard | `picosentry/watch/prompt_guard/` | L5 prompt-injection detection. |
| Watch output guard | `picosentry/watch/output_guard/` | L6 output-policy validation. |
| Watch telemetry | `picosentry/watch/telemetry/` | Audit/metrics sink. |
| Serve API | `picosentry/serve/server.py` | FastAPI application factory. |
| Serve services | `picosentry/serve/services/` | Auth, orchestrator, plugin host, webhooks, etc. |
| Serve config | `picosentry/serve/config/` | Settings and JSON schemas. |
| Daemon | `picosentry/sandbox/daemon/` | Sandbox-as-a-service HTTP + gRPC daemon. |
| Correlation | `picosentry/serve/services/correlation/` | Cross-layer kill-chain correlation. |
| Cluster | `picosentry/serve/services/cluster.py` | Gossip-based cluster manager. |
| Plugin system | `picosentry/serve/services/plugin_*.py` | Plugin host, manager, and interface. |
| _core | `picosentry/_core/` | Cross-cutting utilities (security check, version). |

## Scan module

### Entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/scan/engine.py` | `ScanEngine` | Register rules and run scans. |
| `picosentry/scan/engine.py` | `create_default_engine()` | Factory with all bundled rules. |
| `picosentry/scan/engine.py` | `ScanEngine.scan(target, ...)` | Execute a scan and return `ScanResult`. |
| `picosentry/scan/rules/__init__.py` | `RULE_REGISTRY` | Mapping from `rule_id` to rule callable. |
| `picosentry/scan/models.py` | `Finding` | Structured detection result. |
| `picosentry/scan/cli.py` | `scan_command` | CLI entry point for `picosentry scan`. |

### Adding a rule

1. Implement a callable in `picosentry/scan/rules/`.
2. Register it in `picosentry/scan/rules/__init__.py`.
3. Add fixtures in `tests/scan/fixtures/validation/`.
4. Run `picosentry scan --validate`.

See [`EXTENSION_GUIDE.md`](EXTENSION_GUIDE.md) for a worked example.

## Watch module

### Entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/watch/prompt_guard/__init__.py` | `PromptGuard` | L5 prompt scanner. |
| `picosentry/watch/output_guard/__init__.py` | `OutputGuard` | L6 output validator. |
| `picosentry/watch/prompt_guard/rules.py` | `RuleEngine` | Loads and evaluates YAML regex rules. |
| `picosentry/watch/server.py` | `create_app(...)` | FastAPI app for `picosentry watch serve`. |
| `picosentry/watch/config.py` | `PicoWatchConfig` | All-in-one configuration dataclass. |

### Rule file locations

| Type | Directory |
|------|-----------|
| Prompt injection | `picosentry/watch/rules/prompt_injection/` |
| Output policy | `picosentry/watch/rules/output_policy/` |

## Sandbox module

### L3 backend entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/sandbox/l3/engine.py` | `get_backend(...)` | Selects and instantiates a backend. |
| `picosentry/sandbox/l3/backends/base.py` | `SandboxBackend` | Abstract backend interface. |
| `picosentry/sandbox/l3/backends/seccomp_backend.py` | `SeccompBackend` | Linux seccomp-bpf enforcement. |
| `picosentry/sandbox/l3/backends/subprocess_backend.py` | `SubprocessBackend` | Fallback subprocess runner. |
| `picosentry/sandbox/l3/models.py` | `Policy`, `SandboxResult` | Backend data contracts. |

### L4 behavioral engine

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/sandbox/l4/engine.py` | `analyze(...)` | Convert sandbox events into behavioral findings. |
| `picosentry/sandbox/l4/models.py` | `BehavioralFinding` | Structured L4 result. |

## Serve module

### Entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/serve/server.py` | `create_app(...)` | FastAPI app factory. |
| `picosentry/serve/services/auth.py` | `AuthService` | User/token/auth helpers. |
| `picosentry/serve/services/orchestrator.py` | `Orchestrator` | Coordinates scan/sandbox/watch runs. |
| `picosentry/serve/services/plugin_manager.py` | `PluginManager` | Loads and dispatches plugins. |
| `picosentry/serve/services/plugin_host.py` | `PluginHost` | Subprocess wrapper for a plugin. |
| `picosentry/serve/services/correlation/engine.py` | `CorrelationEngine` | Cross-layer kill-chain builder. |
| `picosentry/serve/services/webhooks.py` | `WebhookDispatcher` | Alert webhook delivery. |
| `picosentry/serve/services/websocket_manager.py` | `WebSocketManager` | Live results streaming. |
| `picosentry/serve/services/scheduler.py` | `Scheduler` | Periodic task runner. |
| `picosentry/serve/config/settings.py` | `Settings` | Pydantic settings + env loading. |

### Plugin interface

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/serve/services/plugin_manager.py` | `PluginInterface` | Base class for plugins. |
| `picosentry/serve/services/plugin_host.py` | `PluginHost` | Spawns and communicates with plugin workers. |

## Data and corpus

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/scan/corpus/` | — | Offline malware/IOC/advisory JSON datasets. |
| `picosentry/scan/advisory.py` | `AdvisoryDB` | Parses OSV-style advisories. |
| `picosentry/scan/corpus_index.py` | `CorpusIndex` | BK-tree edit-distance index for typosquat. |
| `datasets/malware/` | — | Larger benchmark malware corpora (not shipped in wheel). |

## CLI dispatch

`picosentry/cli.py` uses subcommands defined in:

- `picosentry/scan/cli_commands/`
- `picosentry/sandbox/cli_commands/`
- `picosentry/watch/cli.py`
- `picosentry/serve/cli.py`

Each subcommand module exposes a `register_*` function that adds its commands
to the main parser.

## Testing helpers

| File | Purpose |
|------|---------|
| `scripts/test_doctor.py` | Unified local CI-quality runner. |
| `tests/conftest.py` | Shared fixtures. |
| `tests/scan/fixtures/validation/` | Regression fixture corpus for scan rules. |

## HTTP API reference

All endpoints require JWT authentication via `Authorization: Bearer <token>`
(unless noted). Role and permission requirements are listed per endpoint.
Org scoping is enforced via the `X-Org-API-Key` header or the user's default
org membership (see `deps.get_current_org`).

Base path: Most endpoints are mounted on the root; scans and dashboard are
under `/api/v1`.

### Authentication and authorization

| Role | Permissions |
|------|-------------|
| `viewer` | `read:*` (projects, intelligence, alerts, metrics, dashboard, health, orgs, plugins, events, webhooks, scheduler, anomaly) |
| `operator` | All `viewer` permissions + `run:projects`, `write:webhooks`, `write:intelligence`, `write:alerts`, `write:scheduler`, `write:anomaly`, `read:logs`, `read:backups` |
| `admin` | All permissions including `admin:users`, `admin:orgs`, `admin:backups`, `admin:audit`, `admin:logs` |

### Correlation API

Correlation endpoints expose the cross-layer kill-chain engine. Source:
`picosentry/serve/api/routers/correlation.py`.

#### `GET /chains`

List kill chains, sorted by chain score descending.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Query params | `threshold` (float 0.0–1.0, default 0.0) — minimum `chain_score` filter; `limit` (int 1–500, default 50) |
| Response | `{ "total": int, "chains": [KillChainTimeline.to_dict(), ...] }` |
| Org scoping | All orgs visible (global correlation state) |

#### `GET /chains/{artifact_id}`

Full kill-chain timeline for a single artifact.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Path params | `artifact_id` (string, max 512 chars) — e.g. `lodash@4.17.21` |
| Response | `KillChainTimeline.to_dict()` — includes `artifact_id`, `chain_score`, `severity`, `confidence`, `narrative`, `phases`, `related_targets`, `event_count`, `phase_count` |
| Errors | 404 if no chain data for artifact |

#### `GET /chains/{artifact_id}/narrative`

Human-readable narrative summary for an artifact's kill chain.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Path params | `artifact_id` (string, max 512 chars) |
| Response | `{ "artifact_id": str, "narrative": str, "chain_score": float, "phase_count": int, "event_count": int }` |
| Errors | 404 if no chain data for artifact |

#### `GET /chains/summary`

Aggregate statistics across all kill chains.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Response | `{ "total_chains": int, "total_events": int, "total_artifacts": int, "layers_active": int, "layer_coverage": [...], "critical_count": int, "high_count": int, "medium_count": int, "low_count": int, "avg_chain_score": float, "phase_distribution": {...}, "top_chains": [...] }` |

#### `POST /events`

Ingest a correlation event from an external integration.

| Field | Value |
|-------|-------|
| Auth | `operator` role |
| Request body | `EventIngestRequest` (see below) |
| Response | `{ "status": "ok", "event": CorrelatedEvent.to_dict() }` |

`EventIngestRequest`:

| Field | Type | Constraints |
|-------|------|-------------|
| `artifact_id` | string | required, max 512 chars |
| `layer` | string | required, one of `scan`, `sandbox_l3`, `sandbox_l4`, `watch` |
| `rule_id` | string | required, max 128 chars |
| `severity` | string | optional, one of `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (default `MEDIUM`) |
| `confidence` | string | optional, one of `LOW`, `MEDIUM`, `HIGH`, `EXACT` (default `MEDIUM`) |
| `target` | string | optional, max 512 chars (defaults to `artifact_id`) |
| `title` | string | optional, max 256 chars (defaults to `layer/rule_id`) |
| `detail` | string | optional, max 4096 chars |

Org scoping: the event's `org_id` is set from the authenticated user's org.

#### `POST /chains/persist`

Persist in-memory correlation state to the database.

| Field | Value |
|-------|-------|
| Auth | `operator` role |
| Response | `{ "status": "ok", "events_persisted": int, "chains_persisted": int, "persist_enabled": bool }` |

Persistence requires the `correlation_events` table (auto-created by
migrations). When `persist_enabled` is `false`, the counts will be 0.

#### `GET /engine/stats`

Correlation engine statistics.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Response | `{ "artifacts": int, "events": int, "cached_chains": int, "avg_events_per_artifact": float }` |

### Anomaly API

Anomaly endpoints expose the metric-based anomaly detector. Source:
`picosentry/serve/api/routers/anomaly.py`.

#### `GET /anomaly/rules`

List all configured anomaly rules.

| Field | Value |
|-------|-------|
| Auth | `read:anomaly` permission (viewer, operator, admin) |
| Response | Array of rule objects: `{ "id", "metric_name", "threshold", "comparison", "duration_seconds", "alert_channel", "description", "labels", "enabled" }` |

#### `GET /anomaly/alerts`

List recent anomaly alerts from the database.

| Field | Value |
|-------|-------|
| Auth | `read:anomaly` permission |
| Query params | `limit` (int 1–200, default 50) |
| Response | Array of alert objects: `{ "rule_id", "metric_name", "value", "threshold", "comparison", "severity", "description", "timestamp" }` |

#### `POST /anomaly/check`

Trigger an immediate anomaly detection cycle.

| Field | Value |
|-------|-------|
| Auth | `write:anomaly` permission (operator, admin) |
| Request body | none |
| Response | `{ "triggered": int, "alerts": [{ "rule_id", "metric", "value", "threshold", "severity" }] }` |

#### `PATCH /anomaly/rules/{rule_id}`

Update an anomaly rule (enable/disable or change threshold).

| Field | Value |
|-------|-------|
| Auth | `write:anomaly` permission (operator, admin) |
| Path params | `rule_id` (string, max 64 chars) |
| Request body | `AnomalyRuleUpdateRequest`: `{ "enabled"?: bool, "threshold"?: float (0.0–1.0) }` |
| Response | `{ "status": "updated", "rule_id": str }` |
| Errors | 400 if no updates provided; 404 if rule not found |

### Scheduler API

Scheduler endpoints manage periodic background jobs. Source:
`picosentry/serve/api/routers/scheduler.py`.

#### `GET /scheduler/jobs`

List scheduled jobs for the authenticated org.

| Field | Value |
|-------|-------|
| Auth | `read:scheduler` permission (viewer, operator, admin) |
| Org scoping | Only jobs belonging to the user's org are returned |
| Response | `{ "jobs": [{ "id", "name", "cron", "command", "enabled", "next_run", "last_run", "last_status", "org_id" }] }` |

#### `POST /scheduler/jobs`

Create a new scheduled job.

| Field | Value |
|-------|-------|
| Auth | `write:scheduler` permission (operator, admin) |
| Request body | `SchedulerJobCreateRequest` (see below) |
| Response | `{ "job_id": int, "status": "scheduled" }` (HTTP 201) |
| Errors | 400 for invalid command or params |

`SchedulerJobCreateRequest`:

| Field | Type | Constraints |
|-------|------|-------------|
| `name` | string | required, 1–200 chars |
| `cron` | string | required, 1+ chars (cron expression or `every N minute/hour/day`) |
| `command` | string | required, one of `batch`, `run`, `report`, `backup`, `cleanup`, `health_check` |
| `params` | object | optional, values must be strings, numbers, or booleans |
| `enabled` | bool | optional, default `true` |

Org scoping: `org_id` is set from the authenticated user's org.

#### `PATCH /scheduler/jobs/{job_id}/enable`

Enable a disabled job.

| Field | Value |
|-------|-------|
| Auth | `write:scheduler` permission |
| Path params | `job_id` (integer) |
| Response | `{ "job_id": str, "status": "enabled" }` |
| Errors | 404 if job not found or not in user's org |

#### `PATCH /scheduler/jobs/{job_id}/disable`

Disable an enabled job.

| Field | Value |
|-------|-------|
| Auth | `write:scheduler` permission |
| Path params | `job_id` (integer) |
| Response | `{ "job_id": str, "status": "disabled" }` |
| Errors | 404 if job not found or not in user's org |

#### `DELETE /scheduler/jobs/{job_id}`

Delete a scheduled job.

| Field | Value |
|-------|-------|
| Auth | `write:scheduler` permission |
| Path params | `job_id` (integer) |
| Response | 204 No Content |
| Errors | 404 if job not found or not in user's org |

### Admin API

Admin endpoints for backup, logs, audit, and event history. Source:
`picosentry/serve/api/routers/admin.py`. All admin endpoints require the
`admin` role.

#### `POST /backup`

Create a database backup (tar.gz of database + optional logs).

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Request body | none |
| Response | `{ "status": "backup_created", "path": str }` |

#### `GET /backups`

List available backups.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Request body | none |
| Response | `{ "backups": [{ "name", "path", "size", "created" }] }` |

#### `GET /logs/stats`

Log directory statistics.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Response | `{ "directory": str, "file_count": int, "total_size_mb": float, "max_size_mb": float, "retention_days": int, "files": [...] }` |

#### `POST /logs/rotate`

Trigger manual log rotation.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Request body | none |
| Response | `{ "status": "rotated" }` |

#### `GET /logs`

Query log entries.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Query params | `level` (string, optional — filter by log level); `source` (string, optional — filter by source); `search` (string, optional — text search); `limit` (int 1–1000, default 100) |
| Response | `{ "entries": [{ "file": str, "line": str }] }` |

#### `GET /audit/stats`

Audit log statistics.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Response | `{ "total_entries": int, "oldest_entry": str|null, "newest_entry": str|null, "top_actions": [...], "retention_policy": {...} }` |

#### `POST /audit/purge`

Purge old audit log entries.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Query params | `retention_days` (int ≥ 1, optional — override default tiered retention); `dry_run` (bool, default false — return count without deleting) |
| Response | If `dry_run`: `{ "would_delete": int, "cutoff": str }`. If not dry_run: `{ "deleted": int, "cutoff": str }` per severity tier, or single count if `retention_days` specified. |

Default retention policy: critical 365 days, high 180 days, medium 90 days,
low 30 days, default 90 days.

#### `GET /events/history`

Event bus history.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Query params | `event_type` (string, optional — filter by event type); `limit` (int 1–1000, default 100) |
| Response | Array of event objects: `{ "id": str, "type": str, "source": str, "payload": dict, "timestamp": str, "priority": str }` |

### WebSocket protocol

Source: `picosentry/serve/api/routers/ws.py`,
`picosentry/serve/services/websocket_manager.py`.

#### `WS /ws`

Authenticated WebSocket fanout for real-time event streaming.

**Connecting:**

- Connect to `ws://host:port/ws` (or `wss://` in production).
- Optional: pass `?token=<jwt>` as a query parameter for connect-time auth.
- If a token is provided and invalid, the server accepts the connection then
  closes with code **4001** and reason `"Invalid authentication token"`.

**In-band authentication:**

If connected without a query-string token, send:

```json
{"action": "auth", "token": "<jwt>"}
```

- On success: `{"type": "auth", "status": "ok", "user_id": "<id>"}`
- On failure: `{"type": "auth", "status": "denied"}` then close with code
  **4001**.

**Unauthenticated connections** are accepted with an **empty channel set**.
They can send messages but receive no broadcasts and cannot `subscribe` until
they authenticate.

**Subscribing to channels:**

After successful auth, send:

```json
{"action": "subscribe", "channels": ["scan.completed", "chain.escalated", "*"]}
```

- `*` subscribes to all event types.
- On success: `{"type": "subscribed", "channels": [...]}`.
- If unauthenticated: `{"type": "error", "message": "Authentication required before subscribe"}`.

**Keepalive:**

```json
{"action": "ping"}
```

Server responds with:

```json
{"type": "pong"}
```

**Broadcasts:**

Subscribed clients receive:

```json
{"type": "<event_type>", "payload": {...}, "timestamp": "<iso8601>"}
```

**Channel semantics:**

- The `*` channel matches all event types.
- Subscribing replaces the previous channel set (not additive).
- Malformed JSON frames are silently ignored.
- Unknown actions are silently ignored (not echoed).

**Close codes:**

| Code | Meaning |
|------|---------|
| 4001 | Invalid authentication token |

## Determinism contract

PicoSentry's scanner and watch guard rely on deterministic behavior. Any code
path that introduces randomness, wall-clock timing, or non-deterministic IDs
must be isolated and documented. See `docs/determinism.md`.
