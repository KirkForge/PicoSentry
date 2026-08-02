# State — KirkForge-PicoSeries-picosentry (PicoSentry)

*Tracked. Updated at session close. What changed, what's pending, what's blocked.*

## Current state
- Head: (current, uncommitted)
- Tests: 1572 pass (22 skipped); ruff/mypy clean; all gates green
- Last updated: 2026-08-02

## Session 2026-08-02 (Round 8): Response Models, Docstrings, DRY Refactors, Cache Eviction

### Task: Add response models to 27 remaining endpoints — DONE
- Added 22 Pydantic response models to `models.py`
- Applied `response_model=` to 27 endpoints across projects, dashboard, scans, webhooks, scheduler, anomaly, orgs, correlation, and metrics routers
- All endpoints now have typed response models except: CSV export (PlainTextResponse), 204 No Content endpoints, and Prometheus metrics (PlainTextResponse)

### Task: Add class docstrings to 11 service classes — DONE
- AuthService, JobScheduler, WebhookManager, EventBus, AnomalyDetector, LogManager, BackupManager, MetricsCollector, IntelligenceEngine, AlertHub, PluginManager

### Task: Extract org-membership dependency — DONE
- Created `require_org_membership()` dependency in `deps.py`
- Replaced 4 inline org-membership checks in `orgs.py`

### Task: Extract SQL WHERE-clause builder — DONE
- Created `picosentry/serve/database/helpers.py` with `build_filtered_query()`
- Replaced 2 duplicated query builders in `projects.py` (list_intelligence, list_alerts)

### Task: Auth rate limiter eviction — DONE
- Added `_AUTH_RATE_MAX_ENTRIES = 10000` cap
- When exceeded, evicts oldest 25% of IP entries
- Prevents unbounded memory growth in long-running deployments

## Session 2026-08-02 (Round 7): Deep Audit Fixes

### Task: P0 — TOCTOU races in create_user and org creation — DONE
- `auth.py:create_user()`: Removed SELECT-then-INSERT race; now does direct INSERT in transaction, catches any exception (including IntegrityError) and returns None
- `orgs.py:create()`: Removed SELECT slug check; both INSERTs (org + org_users) now in single transaction; IntegrityError returns None; org creation is now atomic

### Task: P0 — WebSocket unauthenticated connections — DONE
- `ws.py`: Auth check moved before `websocket.accept()`; unauthenticated connections are closed with code 4001 immediately
- Removed in-band `auth` action since auth is now required at connect time

### Task: P1 — PluginManager thread safety — DONE
- Added `threading.Lock` to `PluginManager`
- `dispatch()`: snapshots hooks list under lock, iterates outside
- `get_status()`: snapshots plugins dict under lock, iterates outside
- `_load_plugins()`: acquires lock for directory reads, releases before I/O
- `unload_all()`: shutdown outside lock, then clears dicts under lock

### Task: P1 — rotate_api_key atomicity — DONE
- Wrapped revoke+insert in single `transaction()`; eliminates window with no valid key

### Task: P1 — authenticate() atomicity — DONE
- Wrapped SELECT+UPDATE last_login in single `transaction()`

### Task: P1 — anomaly.py HTTPException style — DONE
- Converted positional `HTTPException(400, "...")` to keyword args `HTTPException(status_code=400, detail="...")`

### Task: P1 — health.py bare JSONResponse for 503 — DONE
- Replaced `JSONResponse(status_code=503, ...)` with `HTTPException(status_code=503, detail="database unavailable")`

### Task: P1 — Sandbox env denylist — DONE
- Added `PICOSHOGUN_ALLOW_INSECURE_SECRET`, `PICOSHOGUN_SKIP_SECURE_ASSERT`, `PICOSHOGUN_API_KEY` to `_SANDBOX_ENV_DENYLIST`

### Task: P1 — API key creation rate limiting — DONE
- Added `_check_auth_rate_limit()` to `create_api_key` endpoint (5 req/min per IP, same as login/register)

### Task: P1 — webhook_sink.py SSRF guard — DONE
- Replaced raw `urlopen()` with `safe_urlopen()` from `scan._network`
- Added `assert_url_safe()` validation before HEAD request
- Added `InsecureURLError` and `ResponseTooLargeError` to exception handling

## Session 2026-08-02 (Round 6): Input Validation, Thread Safety, Dead Input Cleanup

### Task: Add Pydantic response models to remaining endpoints — DONE
- Added 11 response models: `BackupResponse`, `BackupListResponse`, `LogFileEntry`, `LogStatsResponse`, `LogRotateResponse`, `LogEntry`, `LogQueryResponse`, `AuditStatsResponse`, `AuditPurgeResponse`, `EventHistoryItem`, `PluginsResponse`, `LivenessResponse`, `ReadinessResponse`
- Applied `response_model=` to 12 more endpoints in admin, plugins, and health routers
- `AuditPurgeResponse` uses `extra="allow"` to handle variable return shapes from `purge_audit_logs`
- Total response models: 27 (6 from Round 3 + 15 from Round 4 + 11 from Round 5, minus some overlap)

### Task: SQLite-PostgreSQL parameter count validation — DONE
- Added `_validate_param_count()` method to `DatabaseManager` in `manager.py`
- Validates that `?` placeholder count matches `params` tuple length before executing
- Called at start of `_cursor()` before `_prepare_sql` transforms placeholders
- Prevents silent data corruption from accidental `?` inside string literals

### Task: Fix caplog test failure — DONE
- `test_expected_connection_error_marks_unavailable` failed in full suite due to `picodome` logger having `propagate=False` set by `setup_logging()` in prior test
- Fixed by saving/restoring `picodome_logger.propagate` around the `caplog.at_level()` context

### Task: Final codebase sweep — DONE (no issues found)
- `projects.py`: All SQL uses parameterized queries ✓
- `admin.py`: No SQL in `get_logs`/`get_event_history` (delegates to log_manager/event_bus) ✓
- `orchestrator.py`: All `org_id` SQL uses parameterized `AND org_id = ?` + `params.append()` ✓
- `server.py`: No hardcoded secrets, `secret_key` enforced by `assert_secure()` ✓
- `health.py`: No info leakage in `/` and `/dashboard` ✓
- `print()` in production: None in `picosentry/serve/` ✓

### Task: Input validation P1 fixes — DONE
- `ScanRequest.target`: added `max_length=512`
- `SandboxRunRequest.command`: added `min_length=1` (rejects empty list)
- `SandboxRunRequest.policy_file`: removed (unused dead field)
- `project_id` path params: added `Path(max_length=128)` in 4 handlers
- `scheduler job_id`: changed from `str` to `int` path param (422 on bad input instead of 500)
- Admin log query params: `level` max_length=64, `source` max_length=128, `search` max_length=256
- `_LoginRequest.username/password`: added `min_length=1`

### Task: IntelligenceEngine thread safety — DONE
- Added `threading.Lock` to protect `self.patterns` and `self.threat_scores` dicts
- Wrapped `_load_historical()`, `ingest()`, `get_aggregate_score()` with lock

### Task: PicoDomeHandler thread safety — DONE
- Added class-level `_stats_lock = threading.Lock()` to `PicoDomeHandler`
- Wrapped `_scan_count`, `_scan_total_ms`, `_alert_count` increments in `with self._stats_lock:` in `handler_routes_post.py`
- Wrapped reads in `handler_routes_get.py` metrics and stats endpoints with snapshot pattern

### Task: P2 quality fixes — DONE
- `intelligence.py`: Parameterized `time_window_hours` in SQLite query with `?` placeholder; PostgreSQL kept as f-string with `int()` cast (INTERVAL literals can't be parameterized)
- `log_manager.py`: Added `self._lock` to `query()`, `get_stats()`, and `cleanup()` to prevent file read/write races with `rotate()`
- `auth.py`: Removed dead `check_permission()` method (RBAC module used instead)
- `observability.py`: Removed dead `trace_span` and `trace_async_span` decorators
- `handler_routes_post.py`: Sanitized JSON decode errors — replaced `detail=str(e)` with generic messages ("Invalid JSON", "Invalid policy data")

### Gates verified
```
$ uv run ruff check picosentry/ tests/ scripts/ --quiet
(no output — 0 errors)

$ uv run ruff format --check picosentry/ tests/ scripts/
600 files already formatted

$ uv run mypy picosentry/ --ignore-missing-imports
Success: no issues found in 391 source files

$ uv run pytest tests/sandbox/ -q -o "addopts=" -n0 --timeout=60
1572 passed, 22 skipped in 88.73s
```

## Session 2026-08-02 (Round 5): Response Models, SQL Hardening, Test Fix

### Task: Thread safety — DONE
- `scheduler.py`: Fixed race condition — `self._lock` was declared but never acquired. All `self.jobs` and `self.running` access now synchronized
- `webhooks.py`: Added `threading.RLock` to `WebhookManager`
- `websocket_manager.py`: Added `asyncio.Lock` for connect/subscribe/disconnect/broadcast
- `anomaly_detector.py`: Added `threading.Lock` for rules/alerts access

### Task: PicoWatchConfig simplification — DONE
- Replaced 22 property getter/setter pairs with `__getattr__`/`__setattr__` delegation via `_DELEGATE_MAP`
- Reduced config.py from 596 to 451 lines (145 lines saved)

### Task: SQL hardening — DONE
- `orchestrator.py`: Replaced f-string `org_filter` SQL with parameterized `AND org_id = ?` + `params.append()`
- `sqlite_store.py`: Hardened column name interpolation with `COLUMN_SANITIZER` mapping

### Task: Org filtering — DONE
- Added `org_id` to `Event`, `AnomalyRule`, `AnomalyAlert` dataclasses
- Added org-scoped filtering to `audit_cleanup`, `event_bus`, `anomaly_detector`

### Task: Pydantic response models — DONE
- Added 15 response models for auth, orgs, webhooks, scheduler, correlation, anomaly, health
- Applied `response_model=` to 12 endpoints

## Session 2026-08-02 (Round 3): Org Scoping, Auth, Validation, Dead Code

### Task: Org scoping — DONE
- Added `get_current_org` dependency to 22 endpoints (admin, correlation, anomaly, scans)

### Task: Auth rate limiting + input validation — DONE
- 5 req/min per IP for `/auth/login` and `/auth/register`
- `max_length` on login/API key fields, HTTPS validation for webhooks, Query/Path constraints

### Task: HTTP status codes — DONE
- 5 resource-creation endpoints return 201

### Task: Error sanitization — DONE
- Sandbox and scan target errors no longer leak internal paths

### Task: PicoWatch auth — DONE
- `/v1/rules` and `/metrics` require auth when `api_key` is configured

### Task: Dead code removal — DONE
- Removed `ConnectionPool`, `CorpusPack.sign()`

### Task: CSP/CORS hardening — DONE
- Removed `'unsafe-inline'` from `script-src`, restricted CORS methods/headers

### Task: ScanStats consolidation — DONE
- Merged duplicate dataclass into `_core/models.ScanStats`

### Task: OTEL teardown fix — DONE
- `try/except ImportError` in `tests/watch/conftest.py`

## Session 2026-08-02: Polish, Lint, Harden

### Task: SSRF hardening — DONE
- `sandbox/admission/scanner.py` and `sandbox/webhooks.py` now use `safe_urlopen()`
- Replaced ad-hoc `_is_blocked_url()` with `scan._network.assert_url_safe()`

### Task: BLE001 narrowing — DONE
- Narrowed `except Exception` to specific exception types in 6 scan/CLI modules

### Task: CERT_NONE documentation — DONE
- Documented `ssl.CERT_NONE` is intentional for no-mTLS mode

## Session 2026-08-02: Documentation Audit, Tech Manual, Doctor

### Task: Documentation audit — DONE
- Corrected stale claims: 50 rules, 6495 fixtures, 68.89% recall across 10+ files

### Task: Tech manual — DONE
- Created `docs/TECHNICAL_MANUAL.md` (17 sections)

### Task: Doctor module — DONE
- `picosentry/_core/doctor.py` (10 checks + 1 repair, 22 tests)

### Task: Test simplification — DONE
- Parametrized 4 test files, removed 218 lines

## Session 2026-07-29: Codebase Analysis & Improvement

### Task: Process timeout orphan fix — DONE
- Fixed `workspace.py:220-223` kill() fallback

### Task: Corpus expansion — DONE
- 4163→6495 fixtures (5558 pos / 930 neg / 7 tricky)

## ACTION REQUIRED before next release

**Docker Hub secrets are missing.** The cosign signing step in `.github/workflows/release.yml` will fail at Docker Hub login until these are added:
1. Go to **GitHub repo → Settings → Secrets and variables → Actions**
2. Add `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`
3. Push a new `v*` tag to re-trigger the release workflow

## Pending / blocked
- **Docker Hub secrets**: must be added for cosign Docker signing
- **L2-PYPI-DEPC-001**: Still 0% recall — dep-confusion detector needs private-registry config marker

## Known blockers / ceilings
- arm64 CI runs under QEMU emulation (3-5× slower, documented in `.github/workflows/ci.yml`)