# state.md — LLM scratch for PicoSentry

---

## Current session: 2026-07-02/03 — CI green push: flaky test fix, test doctor upgrade, state.md cleanup

### Done this session (on `dev`)
- **`main` CI green.** The flaky `tests/scan/test_daemon_extended.py::TestRateLimiting`
  tests were driven by wall-clock `time.monotonic()` bursts. Froze the clock at
  `1000.0` and reset `HealthHandler` class-level defaults in `setUp`; fix pushed
  via `no-ci/fix-rate-limit-flake`, merged to `dev` then `main`. Latest `PicoSentry
  CI` run on `main` is **success**.
- **Test doctor upgrade v2.** `scripts/test_doctor.py` now defaults to a full CI-
  equivalent umbrella (`pytest tests/ -x --tb=short -q`) matching the
  `test-core`/`test-matrix` jobs, runs checks concurrently, streams per-check
  results as they finish, and fails fast by default (`--no-fail-fast` to disable).
  Per-area mode (`--areas`) still uses bounded pytest-xdist for fast feedback.
  Fixed the wall-time summary bug (was summing elapsed times instead of measuring
  actual wall time). Verified full-doctor run green locally.
- **xdist test-isolation fix.** The full-umbrella doctor surfaced a real xdist
  flakiness bug: `tests/scan/test_validation.py` and
  `tests/scan/test_malware_benchmark.py` occasionally failed under the default
  scheduler because unrelated tests that share mutable state ran on the same
  worker. Added `--dist=loadfile` to `[tool.pytest.ini_options].addopts` so each
  test file stays on one worker while files still run in parallel. Verified with
  multiple full-suite runs; CI green on `main`.
- **Test doctor.** Added `scripts/test_doctor.py`: unified local CI-quality runner
  that executes ruff, mypy, and per-area pytest suites concurrently with
  configurable workers. Replaces ad-hoc manual commands.
- **Scheduler category allowlist.** Replaced fragile char-blacklist validation in
  `picosentry/serve/services/scheduler.py` with a known-good `ALLOWED_CATEGORIES`
  set; fixed in-memory `last_status` updates on rejection paths. Added
  regression tests in `tests/serve/test_scheduler.py`.
- **Plugin env-var validation.** Added strict format checks for plugin name and
  capability strings before they become subprocess env vars in
  `picosentry/serve/services/plugin_host.py`. Added
  `tests/serve/services/test_plugin_host.py`.
- **Scan symlink handling.** `picosentry/scan/engine.py` now rejects symlinked
  scan targets at entry and catches `RuntimeError`/`OSError` from symlink
  loops. Added `tests/scan/test_symlink_handling.py`.
- **Corpus freshness check.** Added `--check-corpus-age [DAYS]` to
  `picosentry/scan/cli_commands/check.py` (exit 5 if stale) and a public
  `is_corpus_stale()` helper on the engine. Added tests in
  `tests/scan/test_cli_extended.py`.
- **Watch fail-closed.** Added `PICOSENTRY_WATCH_FAIL_CLOSED` flag (default off
  for compatibility) and fail-closed paths in `PromptGuard.check()`: blocks when
  all rules failed to load and catches rule-evaluation exceptions. Added
  regression tests in `tests/watch/test_prompt_guard.py`.
- **Watch rule-engine + rate-limiter tests.** Added
  `tests/watch/test_rule_engine.py` covering YAML/regex/duplicate/unexpected
  errors, plus extra deterministic tests for `RateLimiter` eviction branches.
  Fixed a real bug: periodic eviction ran after creating the client entry,
  causing new clients to be dropped and `active_clients` to undercount.
- **Admission fail-closed default.** `AdmissionHandler` now denies pods when no
  validator is configured instead of allowing everything. Regression test
  updated in `tests/sandbox/test_admission_webhook.py`.
- **Benchmark xdist stability.** Scaled wall-clock targets in
  `tests/scan/test_benchmark.py` under `pytest-xdist` via `_target()` so CI
  contention does not produce false regressions.
- **Docs.** Added `docs/THREAT_MODEL.md` and `docs/ops/runbook.md` covering trust
  boundaries, fail-closed defaults, and operational procedures.
- **P4 multi-tenant project isolation.** `org_projects` junction table now
  scopes project list/get/export and summary-report project counts. Runs claim
  the project for the org on success, timeout, or exception. Added A↔B negative
  integration test in `tests/serve/test_integration.py`.
- **P4 #1 serve auth-bypass/privesc hardening.** Added `WRITE_ALERTS` permission
  (acknowledge alert), changed `POST /anomaly/check` from `READ_ANOMALY` to
  `WRITE_ANOMALY`, and added regression tests for role escalation,
  permission-level enforcement, malformed tokens, query-param auth bypass, and
  a lightweight pathological-input fuzz harness.
- **P4 #10 exception audit (auth.py slice).** Removed the broad `except Exception`
  in `/auth/register` that returned 400 with raw exception text; unexpected
  failures now reach the global 500 handler without leaking internals. Added
  regression test.
- **P4 #12 Postgres live-test CI.** Added a `postgres-live-test` matrix job
  against Postgres 15 and 16 using a GitHub Actions service container,
  exercising migrations, CRUD, and placeholder translation on a real DB.
- **P4 #14/#17 closed by inspection.** Helm memory limits (`resources` blocks in
  both picodome and picodome-admission values + deployment manifest) and SLO
  PrometheusRule alerts (`deploy/monitoring/picodome-alerts.yaml`) already
  exist and are now recorded as closed.
- **P4 #10 exception audit (webhook/alert slice).** Narrowed broad `except
  Exception` blocks in webhook URL parsing, webhook dispatch, and
  discord/slack/email notification paths to specific, expected exceptions.
  Added SSRF and dispatch-tolerance unit tests.
- **P5 #19 cluster experimental warnings.** Added `EXPERIMENTAL` log warnings
  when cluster manager is configured, started, and when a scan is distributed
  across the cluster; added regression tests.
- **Test doctor robustness.** Capped per-area pytest-xdist workers in
  `scripts/test_doctor.py` based on the doctor's own `--workers` setting so
  concurrent areas do not oversubscribe the CPU and create false timing
  regressions. Uses `--dist=loadfile` to keep related tests together.
- **P5 #10 exception audit (daemon route-handler slice).** Converted all broad
  `except Exception: pass` audit swallows in daemon auth, GET, and POST mixins
  to logged `logger.exception("Audit record failed")` so security events are
  not silently lost. Narrowed security-relevant catch sites (policy load,
  backend instantiation, ready check) to expected exception types and return
  sanitized detail strings instead of raw exception text. Kept a logged safety
  net around scan execution and cluster snapshot merge. Added
  `TestDaemonExceptionHandling` regression tests for audit-logging failure,
  sanitized scan errors, sanitized backend/policy errors, and validation-detail
  preservation.
- **Merge to main.** `dev` merged into `main` at `4becf65`; full `test_doctor`
  suite verified green on `main`.
- **GitNexus index.** Reinstalled `gitnexus`; a full rebuild completed once, but
  subsequent incremental runs fail with missing FTS indexes / `Resource
  temporarily unavailable`. The code index is currently stale; tests and lint
  do not depend on it.
- **P4 #10 exception audit (serve middleware/server slice).** Audit middleware
  now logs token/API-key validation failures instead of silently passing;
  `/health/ready` logs the underlying failure before returning a sanitized 503;
  static-files mount logs a warning on failure instead of swallowing. Added
  `TestAuditMiddlewareHardening` and `TestHealthHardening` regression tests.
- **Merge to main.** `dev` merged into `main` at `89f10f7`; full `test_doctor`
  suite verified green on `main`.
- **P4 #10 exception audit (watch slice).** `watch/config.py` now logs config
  parse failures and permission-check failures instead of silently returning
  empty results; `prompt_guard/normalize.py` narrowed base64 decoder catch from
  broad `Exception` to `(ValueError, UnicodeDecodeError)`. Added
  `TestConfigHardening` regression tests and a normalizer invalid-base64 test.
- **Merge to main.** `dev` merged into `main` at `094404a`; full `test_doctor`
  suite verified green on `main`.
- **P4 #10 exception audit (cluster + policy_versioned slice).** Cluster
  orchestrator start/stop/assign_scan/handle_node_failure now log audit failures
  instead of swallowing. `VersionedPolicyStore.save()` refactored to a finally-
  based atomic write helper that logs cleanup failures and eliminates the broad
  `except Exception`. Added regression tests for temp-file cleanup on write failure
  and cluster audit failure logging.
- **Merge to main.** `dev` merged into `main` at `1b7d229`; full `test_doctor`
  suite verified green on `main`.
- **P4 #10 exception audit (serve services slice).** `anomaly_detector` now
  logs config parse failures, DB lookup failures, and schema fallback instead of
  silently swallowing; `scheduler` logs invalid cron expressions; `log_manager`
  logs per-file read failures; `database.manager` logs the `lastval()` fallback.
  Added `TestAnomalyDetectorHardening` and scheduler cron-parse regression tests.
- **Merge to main.** `dev` merged into `main` at `a9c96d2`; full `test_doctor`
  suite verified green on `main`.
- **P4 #10 exception audit (plugin host/manager slice).**
  `picosentry/serve/services/plugin_host.py` now narrows `_reap_orphan` and
  `_terminate` to `(OSError, subprocess.TimeoutExpired)`, logs termination
  failures, returns a sanitized `unhealthy` error from `health_check`, and logs
  shutdown request failures. `plugin_manager.get_status()` logs and returns
  sanitized `"health check failed"` instead of `str(e)`. Added
  `TestPluginHostHardening` regression tests.
- **Merge to main.** `dev` merged into `main` at `9945ff1`; `test_doctor`
  `--areas serve` verified green before push.
- **P4 #10 exception audit (correlation engine slice).**
  `CorrelationEngine.enable_persistence_if_supported()` now logs the underlying
  DB-probe exception at DEBUG instead of silently discarding it. `_notify_escalated`
  already logged callback failures; added regression tests confirming both sites
  capture the exception in logs. `plugin_worker.py` RPC boundary and
  `database/pools.py` deliberate rollback+re-raise are left as intentional.
- **Merge to main.** `dev` merged into `main` at `1b4fa46`; `test_doctor`
  `--areas serve` verified green before push.
- **P5 #23 daemon policy signature verification.** Daemon and CLI policy loads
  now use `verify_signature=True`. Custom policies saved via the daemon are
  auto-signed when `PICODOME_POLICY_KEY` is configured. `load_policy` resolves
  custom policies by name from the versioned store and rejects unsigned/tampered
  policies when a key is present. `VersionedPolicyStore` respects
  `PICODOME_POLICY_STORE_DIR`. Added regression tests for lookup, verification,
  tamper detection, auto-signing, and daemon rejection of unsigned policies.
- **Merge to main.** `dev` merged into `main` at `2877118`; full `test_doctor`
  suite verified green before push.
- **P5 #22 plugin development guide.** Added `docs/PLUGIN_DEVELOPMENT.md`
  covering the PicoShogun lifecycle, manifest, deny-by-default capability
  model, subprocess sandbox boundaries, Ed25519 signing procedure, deployment,
  testing, and security checklist. Listed in `README.md`.
- **Merge to main.** `dev` merged into `main` at `fa08100`; docs-only change.
- **Bundled `test_plugin` signature fix.** The bundled plugin manifest had a
  stale Ed25519 signature that failed verification with the current module
  checksum. Regenerated the key pair, re-signed the manifest, updated
  `BUNDLED_TRUSTED_PUBLIC_KEYS`, and refreshed the test constants so the bundled
  example loads as signed by default again.
- **Merge to main.** `dev` merged into `main` at `072982b`; `test_doctor`
  `--areas serve` verified green before push.
- **P5 #21 architecture overview.** Added `docs/ARCHITECTURE.md` with a Mermaid
  component diagram, trust-boundary table, project-run data flow, subprocess
  isolation summary, multi-tenancy and correlation overviews, plugin trust
  model, and operational interface table. Cross-links to the other docs.
- **Merge to main.** `dev` merged into `main` at `1c40686`; docs-only change.
- **P5 #25 reproducible-build verification.** Added
  `scripts/verify_release.py` to checksum, validate Sigstore bundle structure,
  and parse the CycloneDX SBOM for a published release. Added
  `.github/workflows/verify-release.yml` that runs after each release (or
  manually) and executes the script plus `gh attestation verify` for SLSA
  provenance and `sigstore verify identity` for the keyless OIDC signatures.
- **Merge to main.** `dev` merged into `main` at `b03c2af`; full `test_doctor`
  suite verified green before push.
- **P5 #11 corpus statistical validation / adversarial mutation benchmark.**
  Added `picosentry/scan/adversarial_mutations.py` with deterministic source-
  level mutators, `picosentry/scan/mutation_benchmark.py` harness that copies
  validation fixtures, mutates eligible source files, scans them, and reports
  recall/precision, and `tests/scan/test_mutation_benchmark.py` asserting
  aggregate recall ≥ 85% and precision ≥ 95% under mutation. Added
  `scripts/mutation_benchmark.py` CLI runner and documented the benchmark in
  `docs/BENCHMARKS.md`.
- **P5 #20 seccomp red-team tests + backend hardening.** Added
  `tests/sandbox/test_seccomp_redteam.py` covering network egress, filesystem
  escape, privilege escalation, process injection, kernel-exploit surface, and
  backend integrity/fail-closed behavior. Fixed `SeccompBackend._build_filter`
  so explicit policy DENY rules take precedence over the broad `SAFE_SYSCALLS`
  allowlist and `execve`/`execveat` remain available for command launch. All
  red-team tests and the full `test_doctor` suite pass.
- **P5 #11 mutation benchmark CI robustness.** `run_mutation_benchmark()` now
  auto-detects the bundled `_advisories` directory from the validation root, so
  the mutation benchmark uses the same advisory data as `run_validation()` in
  CI and local runs. This prevents spurious recall drops caused by missing
  advisory DB in the `test-core` matrix job.
- **P5 #2 K8s admission real-cluster matrix.** Added
  `.github/workflows/admission-kind.yml` that runs
  `scripts/live_test_admission.sh` against a kind cluster across K8s v1.28,
  v1.29, and v1.30. Updated the script to build the local `picosentry:local`
  image when `PICOSENTRY_IMAGE` is not set, making CI always test the current
  commit. The live test verifies that privileged, hostPath, hostNetwork, and
  missing-security-context pods are denied while compliant pods are admitted.
- **CONTRIBUTING.md test doctor docs.** Replaced the bare `python -m pytest`
  example with `python scripts/test_doctor.py --workers 4` and an `--areas`
  example so contributors run the same local CI-quality runner that gates CI.
- **P4 #10 exception audit (serve/api middleware + server + rate limiter +
  DB manager slice).** Narrowed broad `except Exception` sites in
  `picosentry/serve/middleware/audit.py` (auth/API-key validation failures),
  `picosentry/serve/api/server.py` (health ready, correlation callback,
  static-files mount), `picosentry/serve/middleware/rate_limit.py`
  (persistence flush), and `picosentry/serve/database/manager.py`
  (`lastval()` fallback, optional `psycopg2`). Unexpected failures now surface
  instead of being swallowed; expected failures are logged with context.
  Updated regression tests so the narrowed exception tuples stay correct.
- **Merge to main.** `dev` merged into `main` at `e631b20`; full
  `test_doctor` suite verified green on the feature branch before push.
- **CI mypy fix.** `picosentry/serve/database/manager.py` now uses
  `typing.cast("Any", None)` for the optional `psycopg2` fallback, which
  satisfies both local mypy 2.1.0 and CI's latest mypy under
  `--ignore-missing-imports` without a `# type: ignore` comment. Work was
  committed on `no-ci/fix-ci-mypy-3` to avoid mailbox-spamming WIP pushes, then
  merged to `dev` and `main`. CI runs for both `dev` and `main` completed
  successfully.
- **P4 #10 exception audit (serve routers slice).** Narrowed broad
  `except Exception` in `picosentry/serve/api/routers/scans.py`
  (`POST /sandboxes`) to `(RuntimeError, OSError, ValueError, TypeError)`
  with logged warning, and in `picosentry/serve/api/routers/health.py`
  (`/health/ready`) to `(OSError, ValueError, RuntimeError)`. Added
  `tests/serve/test_sandbox_router.py` and `tests/serve/test_health_router.py`
  to verify expected failures return sanitized 5xx and unexpected errors are
  left for the global handler.
- **Full `test_doctor` green.** Verified `python scripts/test_doctor.py --workers 4`
  passes (9/9 checks) before committing this slice.
- **P4 #10 exception audit (backup service slice).** Narrowed broad
  `except Exception` in `picosentry/serve/services/backup.py` for both
  `create_backup` and `restore_backup` to
  `(OSError, ValueError, TypeError, tarfile.TarError)`. Added
  `tests/serve/services/test_backup.py` covering happy path, expected failure
  logging, and propagation of unexpected programmer errors.
- **Full `test_doctor` green.** Verified `python scripts/test_doctor.py --workers 4`
  passes (9/9 checks) before committing this slice.
- **CHANGELOG.md forward-facing update.** Reviewed and refreshed `CHANGELOG.md`
  so the latest v2.0.17 security fixes and CI additions are summarized for
  users reading the release notes (not duplicated in detail here).
- **P4 #10 status refresh in Gap Audit.** Updated the broad-exception audit
  summary to reflect all narrowed slices shipped this session (auth, webhook/
  alert, daemon route-handler, serve middleware/server, watch, cluster +
  policy_versioned, serve services, plugin host/manager, correlation engine,
  serve/api middleware/server/rate_limit/DB manager, serve routers, backup
  service). Reduced remaining site count to ~151.
- **state.md cleanup.** Reconciled the current session header, "Still open"
  list, Gap Audit #22, and the 2026-06-24 GPT-5 review roadmap so all sections
  agree that security-relevant exception narrowing is closed, ~151 broad
  safety-net sites remain, and the only repo-admin action is marking
  `postgres-live-test` as a required status check.
- **Test doctor upgrade.** `scripts/test_doctor.py` gained `--fix` (ruff
  auto-fix + format), `--ci` (CI-equivalent commands without pytest-xdist),
  `--verbose`/`-v` (output snippets for passing checks), and `--report`
  (JSON summary). Verified full local-parallel and CI-equivalent runs green.
- **P4 #10 exception audit (daemon route-handler continuation).** Narrowed
  broad `except Exception` in `picosentry/sandbox/daemon/handler_routes_get.py`
  (Redis health fallback, cluster snapshot GET) and
  `picosentry/sandbox/daemon/handler_routes_post.py` (retention save, policy
  creation unexpected errors, cluster snapshot merge). Added regression tests
  in `tests/sandbox/test_daemon_handler.py` verifying sanitized error details
  and fail-safe behavior.
- **P4 #10 exception audit (daemon POST handler safety-net slice).** Narrowed
  the remaining broad `except Exception` guards in
  `picosentry/sandbox/daemon/handler_routes_post.py` for audit-record failures
  (cluster-token mismatch, command-denied, scan-start, scan-complete) and the
  outer scan execution catch to `(OSError, RuntimeError)`. Expected failures are
  logged and sanitized; unexpected programmer errors propagate. Added five
  regression tests covering audit failure logging, scan continuation, and
  unexpected exception propagation. Verified with `python3 scripts/test_doctor.py`
  and `python3 -m pytest tests/ -x --tb=short -q` before updating
  `CHANGELOG.md`.
- **Websocket auth test isolation / main CI hotfix.** The merge to `main`
  surfaced a rare `pytest-xdist` auth flake in
  `tests/serve/test_websocket_auth.py::test_valid_token_query_string_authenticates`
  (invalid password during `fresh_user` setup). Added a module-scoped fixture
  that gives the websocket auth suite its own SQLite DB instead of the shared
  global `picoshogun.db`, removing cross-test DB noise. Verified the fix with
  `python3 scripts/test_doctor.py` and the CI-shaped pytest command; `main`
  CI returned to green after the follow-up merge.
- **SQLite WAL/disk I/O test hardening.** After the websocket-auth fix, the
  next `main` CI flake was `sqlite3.OperationalError: disk I/O error` in
  `tests/serve/test_scans_workspace.py::test_viewer_is_rejected_with_403`.
  Made SQLite `journal_mode` and `synchronous` configurable via environment in
  `picosentry/serve/config/settings.py` (`PICOSHOGUN_DATABASE_JOURNAL_MODE`,
  `PICOSHOGUN_DATABASE_SYNCHRONOUS`) and set `tests/serve/conftest.py` to use
  `DELETE` journal mode. Verified with
  `python3 -m pytest tests/ -x --tb=short -q` and
  `python3 scripts/test_doctor.py --workers 4` (all checks green).
- **P4 #10 exception audit (serve log/alert services slice).**
  `picosentry/serve/services/log_manager.py` narrowed the per-file read catch
  in `query()` to `(OSError, UnicodeDecodeError)`. `alert_hub.py` replaced the
  broad `except Exception` around channel delivery with a targeted
  `_ALERT_CHANNEL_ERRORS` tuple (`OSError`, `RuntimeError`, `ValueError`,
  `TypeError`, `sqlite3.Error`, and `psycopg2.Error` when available) so one
  channel failing still allows the others to run, while unexpected programmer
  errors propagate. Added `tests/serve/services/test_alert_hub.py` and
  `tests/serve/services/test_log_manager.py` regression tests. Verified with
  `python3 scripts/test_doctor.py --workers 4` before merge.
- **P4 #10 exception audit (serve execution/observability slice).**
  `EnhancedOrchestrator.get_health_checks()` narrowed its database/disk/SMTP
  probe catches to expected operational exceptions (`_HEALTH_PROBE_ERRORS` for
  DB, `OSError` for disk, `(OSError, smtplib.SMTPException)` for SMTP).
  `JobScheduler._get_next_run()` narrowed the croniter catch to
  `(ValueError, TypeError, KeyError)`. `observability.py` narrowed OTel
  init/shutdown and FastAPI instrumentation catches to
  `(OSError, RuntimeError, ValueError, TypeError)`, while leaving the
  `trace_span` re-raise patterns untouched. Added regression tests in
  `tests/serve/services/test_orchestrator.py`,
  `tests/serve/test_scheduler.py`, and
  `tests/serve/services/test_observability.py`. Verified with
  `python3 scripts/test_doctor.py --workers 4` before merge.
- **CI observability fixture fix.** `tests/serve/services/test_observability.py`
  injects fake `opentelemetry.*` modules so the narrowed-exception tests reach
  the exporter-setup code paths even when `test-serve`/`test-core` install only
  `[serve]` extras. The fixture now injects the parent `opentelemetry` and
  `opentelemetry.sdk` namespace packages; without them `from opentelemetry import
  metrics` raised `ImportError` and the tests silently hit the disabled-tracing
  branch. Verified by blocking real opentelemetry imports locally.
- **SQLite I/O error flake hardening.** `test-core (3.10)` repeatedly flaked
  with `sqlite3.OperationalError: disk I/O error` inside `AuditMiddleware`.
  `AuditMiddleware` now catches `sqlite3.Error` (and `psycopg2.Error` when
  installed) in addition to `(OSError, RuntimeError, ValueError, TypeError)`,
  so a transient DB hiccup never fails an API request. The `serve` test fixtures
  also set `PICOSHOGUN_DATABASE_SYNCHRONOUS=OFF` alongside the existing
  `DELETE` journal mode to reduce temp-storage contention under `pytest-xdist`.
  Added a regression test for audit DB insert failures.
- **P4 #10 exception audit (plugin manager slice).** `PluginManager` loading
  boundaries now narrow broad `except Exception` to expected operational
  exceptions: `verify_manifest_signature`, `_load_plugins` discovery loop, and
  `_load_plugin` host instantiation catch
  `(OSError, RuntimeError, ValueError, TypeError, json.JSONDecodeError)`.
  Plugin hook dispatch, health checks, and shutdown remain broad safety nets
  so a single misbehaving plugin cannot crash the manager. Added regression
  tests in `tests/serve/services/test_plugin_manager.py`.
- **P4 #10 exception audit (sandbox health slice).** `picosentry/sandbox/health.py`
  now narrows each health/readiness probe catch to
  `(OSError, RuntimeError, ValueError, TypeError, ImportError)`. Operational
  failures are logged and reported as `healthy=False`; unexpected programmer
  errors propagate. Added regression tests in `tests/sandbox/test_health.py`.
- **CHANGELOG.md / state.md forward-facing updates.** Recorded the plugin
  manager and sandbox health exception-narrowing slices and refreshed the
  remaining broad `except Exception` count.
- **P4 #10 exception audit (baseline hardening slice).**
  `HardenedBaselineManager.apply_update()` in
  `picosentry/sandbox/baseline_hardening.py` now catches
  `(OSError, RuntimeError, ValueError, TypeError)` around the audit-log write
  instead of silently swallowing all exceptions. The baseline update still
  succeeds when audit logging fails, but unexpected programmer errors now
  propagate. Added regression tests in `tests/sandbox/test_baseline_hardening.py`.
- **P4 #10 exception audit (event bus slice).** `EventBus.publish()` in
  `picosentry/serve/services/event_bus.py` now catches only
  `(OSError, RuntimeError, ValueError, TypeError, AttributeError)` around
  subscriber callbacks. One misbehaving subscriber still cannot crash the bus,
  but programmer errors such as `NameError` now propagate. Added regression
  tests in `tests/serve/services/test_event_bus.py`.
- **P4 #10 exception audit (anomaly detector background loop slice).**
  `AnomalyDetector._background_loop()` now catches only
  `(OSError, RuntimeError, ValueError, TypeError)` around each check cycle.
  Operational failures are logged every 60 seconds; programmer errors such as
  `NameError` propagate so the background thread fails loudly. Added
  regression tests in `tests/serve/services/test_anomaly_detector.py`.
- **P4 #10 exception audit (plugin host call-boundary slice).**
  `PluginHost.health_check()` and `shutdown()` in
  `picosentry/serve/services/plugin_host.py` now catch only
  `(OSError, RuntimeError, ValueError, TypeError)` instead of swallowing all
  exceptions. Operational failures return sanitized health status or log a
  debug shutdown failure; programmer errors such as `NameError` propagate. Added
  regression tests in `tests/serve/services/test_plugin_host.py`.
- **P4 #10 exception audit (correlation persistence slice).**
  `picosentry/serve/services/correlation/persistence.py` now narrows all
  broad `except Exception` sites in `_persist_events_impl`, `_load_events_impl`,
  and `_persist_chains_cache_impl` to the `_PERSIST_ERRORS` tuple
  (`sqlite3.Error`, `psycopg2.Error` when installed, `OSError`, `RuntimeError`,
  `ValueError`, `TypeError`). Expected DB failures are logged per event/chain;
  unexpected programmer errors propagate. Added regression tests in
  `tests/serve/test_correlation_persistence.py`.
- **P4 #10 exception audit (daemon scan job store slice).**
  `PersistentScanJobStore._ensure_loaded()` in
  `picosentry/sandbox/daemon/store.py` now catches only
  `(OSError, RuntimeError, ValueError, TypeError, json.JSONDecodeError)` when
  loading the on-disk job store. Expected failures log a warning and start with
  an empty in-memory store; unexpected programmer errors propagate. Added
  regression tests in `tests/sandbox/test_daemon_store.py`.
- **P4 #10 exception audit (audit logger plugin boundary slice).**
  `picosentry/sandbox/audit/logger.py` now narrows broad `except Exception`
  around notary submission, sink send, sink start, and sink stop to the
  `_AUDIT_PLUGIN_ERRORS` tuple (`OSError`, `RuntimeError`, `ValueError`,
  `TypeError`, `AttributeError`). A misbehaving notary or sink still cannot
  crash the core audit log, but programmer errors such as `NameError` now
  propagate. Added regression tests in `tests/sandbox/test_audit_sinks.py`.
- **P4 #10 exception audit (scheduler job execution slice).**
  `JobScheduler._execute_job()` in `picosentry/serve/services/scheduler.py`
  now catches only the `_JOB_EXECUTE_ERRORS` tuple (`OSError`, `RuntimeError`,
  `ValueError`, `TypeError`, `ImportError`, `sqlite3.Error`,
  `subprocess.SubprocessError`) instead of swallowing all exceptions. Expected
  operational failures log and mark the job failed; unexpected programmer
  errors propagate. Added regression tests in `tests/serve/test_scheduler.py`.
- **P4 #10 exception audit (Redis job store slice).**
  `RedisScanJobStore._get_client()` in
  `picosentry/sandbox/daemon/redis_store.py` now conditionally imports `redis`
  at module load and narrows the lazy connection-probe catch to
  `_REDIS_CLIENT_ERRORS` (`OSError`, `RuntimeError`, `ValueError`, `TypeError`,
  and `redis.RedisError` when installed). ImportError remains a separate,
  explicit "package not installed" path. Expected connection failures mark the
  store unavailable and log a warning; unexpected programmer errors propagate.
  Added regression tests in `tests/sandbox/test_redis_store.py`.

### Still open (from `picosentry-gaps-plan.md`)
- **P1:** all public-beta blockers closed.
- **P4:** tenant project isolation closed.
- **P4 #10 broad exception audit — SECURITY-RELEVANT SLICES CLOSED.** All
  security-relevant `except Exception` sites in auth, webhook/alert, daemon
  route-handler, serve middleware/server, watch, cluster + policy_versioned,
  serve services, plugin host/manager, correlation engine, serve/api
  middleware/server/rate_limit/DB manager, serve routers, backup service,
  serve log/alert services, serve execution/observability, plugin manager
  loading paths, sandbox health/readiness probes, baseline hardening
  audit logging, the serve event bus subscriber dispatch, and the anomaly
  detector background loop, plugin host call boundaries, correlation
  persistence, daemon scan job store load, audit logger plugin boundaries,
  scheduler job execution, and Redis job store client probe have been narrowed
  to specific exception types with regression tests.
  **Remaining:** ~145 broad `except Exception` sites across the codebase are
  intentional safety nets or lower-risk boundaries; opportunistic narrowing
  continues on `no-ci/*` feature branches.
- **P4 #10 exception audit (orchestrator execution slice).** Narrowed broad
  `except Exception` in `EnhancedOrchestrator._execute_project` to
  `(RuntimeError, OSError, ValueError, TypeError)` and sanitized the returned
  error, alert, and event-bus payloads to "project execution failed"; full
  exception details are logged via `logger.exception`. Added regression tests
  in `tests/serve/services/test_orchestrator.py`.
- **P4 #10 exception audit (anomaly detector DB-boundary slice).** Replaced the
  broad `except Exception` guards in `AnomalyDetector._get_health_value`,
  `_fire_alert`, and `get_alerts` with a targeted `_DB_BOUNDARY_ERRORS` tuple
  (`sqlite3.Error`, `psycopg2.Error` when available, `OSError`, `RuntimeError`,
  `ValueError`, `TypeError`) so transient database problems are handled but
  programmer errors propagate. Fixed a real bug: `_get_health_value` used tuple
  indexing (`r[0]`, `r[1]`) on rows returned as dicts by `DatabaseManager`,
  which the previous broad catch masked. Added regression tests in
  `tests/serve/services/test_anomaly_detector.py`.
- **P4 #12 Postgres live-test required status check — REQUIRES REPO ADMIN.** The
  `postgres-live-test` CI job runs on every push and passes; it needs to be
  marked required in GitHub branch protection to fully close this item. No
  code change remaining.
- **P5 enterprise GA:** all numbered items in the gaps plan are closed.
  Remaining work is opportunistic (test coverage, exception narrowing,
  docs polish) and not gated by the plan.

### Forward-facing action items
1. **Repo admin:** mark `postgres-live-test` as a required status check for
   `main` (and optionally `dev`) in GitHub branch protection.
2. **Continue opportunistic P4 #10 narrowing** on `no-ci/*` branches for the
   remaining ~151 broad `except Exception` sites, prioritizing request-boundary,
   persistence, and plugin/daemon paths.
3. **Refresh `CHANGELOG.md`** on each user-visible slice so release notes stay
   accurate.
4. **Process guard:** all future slices must pass `python scripts/test_doctor.py`
   and the exact CI command shape (`pytest tests/ -x --tb=short -q`) locally
   before merging to `dev`/`main`; WIP stays on `no-ci/*` branches.

---

## Current session: 2026-06-28/29 — v2.0.17 release: plugin fork-bomb fix + signed releases

Folds in and supersedes two loose planning files (now deletable):
`picosentry.txt` (external seed review) and `picosentry-gaps-plan.md` (gaps
remediation plan). The external review's substance lives in `picosentry-gaps.md`;
the plan's *applied* parts are below as done, its *forward* parts are preserved
under "Still open" so nothing is lost on deletion.

### Done this session (shipped in 2.0.17)
- **Plugin worker fork bomb (critical).** `plugin_manager = PluginManager()` ran
  discovery at *import* time; a worker imports that module for `PluginInterface`,
  so each worker spawned a worker per bundled plugin → exponential subprocess
  fork bomb (observed host load 257). The `PICOSHOGUN_PLUGIN_WORKER` marker was
  set but never checked — now honored, so a worker builds an inert manager.
- **Leaked-worker reaper.** `PluginHost` registers `weakref.finalize` so a host
  dropped without `shutdown()` still terminates its subprocess.
- **pytest containment.** `--timeout=60` wired into `addopts` (was declared as a
  dep but never enabled, so a hung test ran unbounded).
- **Supply-chain (audit #4 / plan P3 — DONE).** `release.yml`: SBOM (CycloneDX) +
  SLSA provenance + Sigstore signing via GitHub OIDC on `v*` tags, attached to
  the Release. Published v2.0.17 to PyPI (was stuck at 2.0.13) and the GitHub
  Release with full evidence.
- **Docker image-name bug.** `docker-bake.hcl` built `kirkforge/picosentry`
  (repo never existed); fixed to the published `kirkforge/picodome`, v-prefixed tag.
- **Lint/type debt (plan A3 — DONE).** Cleared the 5 pre-existing ruff findings +
  6 mypy errors that had been failing CI's lint/type-check jobs. CI green.

### Plan items now closed (from picosentry-gaps-plan.md)
- Part 1 (#5, #6, #7, #10a/c, #8 rate limiter): merged earlier — commits
  `bccf42d` `beb5457` `4c95887` `6a6f05d` `07efc68`.
- Part 2 A1 (plugin stdout isolation `2da8102`), A2 (centralized SSRF guard
  `329c598`), A4/A5 (dead duplicate rate-limiter + rule-engine deleted `9f4b592`),
  A3 (lint/type — this session).
- P3 supply-chain — this session.

### Still open (preserved forward roadmap — was only in picosentry-gaps-plan.md)
Ordered by leverage; tracks the 25-gap audit in `picosentry-gaps.md`.
- **P1 public-beta blockers (~1wk):** `THREAT_MODEL.md` #13 + `docs/ops/runbook.md` #16 — **CLOSED** this session (docs exist and are checked in).
- **P4 multi-tenant blockers (~3–5wk):** #9 tenant isolation — **CLOSED** this
  session; #1 serve threat model + auth-bypass/privesc suite + fuzz harness —
  **CLOSED** this session; #12 Postgres migration audit (PG15/16, promote live
  test to required CI) — **CI job added**, set branch-protection required check
  for `postgres-live-test` to fully close; #10 broad — triage 116 `except` sites
  by request/persistence path — **auth.py + webhook/alert slices closed**,
  remainder still open; #14 SLOs — **CLOSED** by inspection; #17 Helm memory
  limits — **CLOSED** by inspection.
- **P5 enterprise GA (~2–4mo):** #3 plugin capability jail (make `plugin_host`
  the only execution path; retire in-process `importlib` in `plugin_manager`)
  — **CLOSED by inspection** this session; #2 K8s admission real-cluster
  matrix — **CLOSED** this session; #11 corpus statistical validation (FP vs
  PyPI top-10k, adversarial mutation, recall ≥85% floor) — **CLOSED** this
  session; #20 seccomp red-team — **CLOSED** this session; #23 daemon policy
  signature verify — **CLOSED** this session;
  #19 cluster-gossip experimental warnings — **CLOSED** this session;
  #21 arch diagram — **CLOSED** this session; #22 plugin dev guide —
  **CLOSED** this session; #25 reproducible-build verification — **CLOSED**
  this session.

---

## Code Audit — 2026-06-24 (haiku static analysis)

1. **[High] Admission webhook defaults fail-open** — `picosentry/sandbox/admission/__init__.py:104–108` ✅ FIXED
   - If `AdmissionHandler.validator` is not set, request is now denied by default (`allowed=False, reason="no validator configured"`). Regression test updated.

2. **[Med] JSON parse in plugin_worker RPC loop unguarded** — `picosentry/serve/services/plugin_worker.py:34` ✅ FIXED
   - `_recv()` now catches `JSONDecodeError`, sends an error response, and continues the loop instead of crashing the worker.

3. **[Med] Plugin subprocess spawned with no timeout** — `picosentry/serve/services/plugin_host.py:123–131` ✅ FIXED
   - Worker reads are guarded by `select()` with `self.timeout`, `_terminate()` uses `terminate()` + `wait(2.0)` then `kill()` + `wait(1.0)`, and a `weakref.finalize` reaps orphans.

4. **[Med] Daemon URL for image scanner not SSRF-checked** — `picosentry/sandbox/admission/scanner.py:85,100` ✅ FIXED
   - `ImageScanner` validates `daemon_url` with `_assert_daemon_url_safe()` (shared SSRF guard) whenever scanning is enabled.

5. **[Low] Corrupted registry JSON silently skips all projects** — `picosentry/serve/services/orchestrator.py:85–90` ✅ FIXED
   - `_load_registry()` now catches `OSError`/`JSONDecodeError`, logs the error with the registry path, and returns without silently emptying the project list.

6. **[Low] Scheduler batch job has no subprocess timeout** — `picosentry/serve/services/scheduler.py:191–197` ✅ FIXED
   - Batch `subprocess.run()` now passes `timeout=3600` and falls back to the per-job `timeout` param (default 300s).

7. **[Low] Category validation uses char-blacklist not allowlist** — `picosentry/serve/services/scheduler.py:179–190` ✅ FIXED
   - Added `ALLOWED_CATEGORIES` allowlist and `_validate_category()`; char-blacklist removed. Regression tests added.

8. **[Low] Plugin stdin closure in bare except swallows errors** — `picosentry/serve/services/plugin_host.py:180–182` ✅ FIXED
   - `_terminate()` closes stdin with an `OSError` guard and logs debug on failure; no bare `except`.

9. **[Low] Plugin name/capabilities passed as env vars without format validation** — `picosentry/serve/services/plugin_host.py:88,91` ✅ FIXED
   - `_validate_env_values()` enforces `^[a-zA-Z0-9_.-]+$` for plugin names and `^[a-zA-Z0-9_]+$` for capabilities before they reach the child env.

---

## External Reviews — 2026-06-24

### GPT-5 Architectural Review

**TL;DR:** Strong scanner, impressive scope, but surface area has grown faster than the trust evidence. "Stop adding capabilities temporarily and invest in proving the ones you already have."

**Strengths:** Honest about limitations, clean architecture separation, offline deterministic scanner is the right product choice, changelog shows mature iteration.

**Gaps (prioritized):**

1. **Independent security validation** — No third-party pentest, no sandbox escape assessment, no threat model doc. This is the biggest missing piece for a tool claiming sandboxing and enforcement.
2. **Detection quality** — 188 fixtures (150 pos / 38 neg) is too small. Need: historical malicious packages, false-positive benchmark, adversarial samples, mutation testing. Example: take `eval(base64_decode(payload))`, create variants, measure recall degradation.
3. **Supply-chain trust of PicoSentry itself** — SBOM, dependency vuln scanning, reproducible builds, signed releases (SLSA + Sigstore).
4. **Plugin capability restrictions** — Ed25519 signing proves authenticity of the manifest author, not safety. Signed malicious code is still malicious code. Need capability restrictions (partially addressed by plugin_host.py / plugin_worker.py — see last commit on main).
5. **Sandbox claims precision** — Separate Enforcement ("prevent dangerous actions") from Observation ("understand what happened"). Currently: more enforcement than observability.
6. **Operational hardening** — Rate limit tests, auth bypass tests, fuzzing, API contract tests, multi-tenant isolation tests. Priority: serve, daemon, cluster, admission.

**Roadmap:**
- 30 days: freeze features, write threat model, expand corpus, add fuzzing, SBOM + signed releases
- 60–90 days: 10k+ samples, precision/recall reporting, false-positive dashboard, GitHub Action
- 6 months: hardened sandbox, enterprise deployment, managed corpus updates

**Product positioning:** Lead with "Offline deterministic supply-chain scanner with optional runtime containment." Drop "complete security platform" framing.

---

### Opus Code-Level Review

**Theme: architecture is careful, enforcement is permissive-by-default.**

**1. Kubernetes admission controller fails OPEN** — `picosentry/sandbox/admission/scanner.py` `_scan_image` ~line 120
- Daemon unreachable or scan throws → returns `(True, "")` → admits the pod — unless `PICODOME_ADMISSION_FAIL_CLOSED` or `PICODOME_ENTERPRISE_MODE` is explicitly set
- `enabled` defaults `False`; `min_severity` defaults `high` → out of the box admits everything and ignores medium/low findings
- **Fix:** flip the default; fail-closed unless explicitly opted out

**2. Plugin signing is self-attested, not authenticated** — `picosentry/serve/services/plugin_manager.py`
- `public_key` read from the plugin's **own manifest** (`meta.get("public_key")`) — no trusted-key allowlist anywhere in the tree
- `require_signed` defaults false; invalid signature with optional mode loads the plugin anyway (`"...INVALID — loading anyway"`)
- **Fix:** external trusted-key allowlist; reject on invalid signature

**3. Plugins are arbitrary in-process Python with full host privileges** — same file
- `sys.path.insert(0, path)` then `importlib.import_module(entry)` — no sandbox, full host env access
- **Fix:** route all plugin dispatch through `plugin_host.py` subprocess isolation (last commit on main is a start)

**4. Prompt-guard normalizer concrete bypasses** — `picosentry/watch/prompt_guard/normalize.py`
- Base64 single-pass: nested base64-of-base64 never re-decoded
- Base64 min match 20 chars: short directives encoding to <15 bytes slip past
- ROT13 only decodes if encoded text already contains specific ROT13 strings — a content allowlist masquerading as a decoder
- **Fix:** recursive base64 with depth limit; lower min match; remove vocab gate from ROT13

**Credit:** no `yaml.load` without `safe_load`, no `shell=True`, no `pickle`/`marshal` usage, `sandbox/auth.py` uses `hmac.compare_digest`. Easy footguns are absent — gaps are in trust-model defaults, not basic hygiene.

---

LLM session notes. Not committed, not pushed. See
`feedback-repo-doc-minimalism` memory.

## Current session: 2026-06-24 — GPT-5 security review roadmap

Resumed `main` after the security-fix commit `ce02e73`. The supplementary
review's concrete PicoSentry code-level bypasses are fixed. The main GPT-5
review has additional PicoSentry-only gaps that are implementable as code,
tests, docs, or CI changes. This section maps them to a sequenced plan so we
can work through them one by one.

### Already shipped in this session (commit `ce02e73`)

| Fix | Files | Verification |
|-----|-------|--------------|
| Admission scanner defaults to fail-closed with explicit opt-out | `picosentry/sandbox/admission/scanner.py`, CLI, Helm | 89 admission tests passed; new CLI parser/env tests passed |
| Plugin Ed25519 signatures use a trusted-public-key allowlist | `picosentry/serve/services/plugin_manager.py`, `picosentry/cli.py` | 7 new plugin trust tests passed |
| Prompt-guard normalizer hardened against base64/ROT13 bypasses | `picosentry/watch/prompt_guard/normalize.py` | 66 prompt-guard tests passed, including 6 new bypass regressions |
| Supplementary review findings added to local graphify graph | `graphify-out/graph.json` | Graph restored + 5 finding nodes / 10 edges |
| GitNexus index refreshed | `.gitnexus/` | 13,324 nodes / 28,271 edges / 581 clusters / 300 flows |

### Remaining PicoSentry-only gaps from the GPT-5 review

> **STATUS: ALL CLOSED as of 2026-07-02.** The original GPT-5 review gaps have
> been implemented, tested, and merged to `main`. The per-item plans below are
> preserved for historical context; see the Gap Audit section for verification.

| # | Gap | Concrete goal | Type | Verdict |
|---|-----|---------------|------|---------|
| 1 | **Plugin capability restrictions / sandboxing** | Plugins must not run as in-process Python with host privileges. Add a capability model + optional subprocess sandbox (no network/files/env unless declared). | Code + tests | **CLOSED** — plugin manager routes all dispatch through `PluginHost` subprocess; deny-by-default capability model in `docs/PLUGIN_DEVELOPMENT.md`. |
| 2 | **Broader fail-open / silent-fallback audit** | Audit all `except Exception:` sites and security-relevant defaults in `serve`, `daemon`, `cluster`, `sandbox`, `watch` for fail-open behavior. Convert swallow sites to specific exceptions or structured logging. | Code + tests | **CLOSED for security-relevant slices** — auth, webhook/alert, daemon route-handler, serve middleware/server, watch, cluster + policy_versioned, serve services, plugin host/manager, correlation engine, serve/api middleware/server/rate_limit/DB manager, serve routers, backup service narrowed with tests. ~151 intentional/lower-risk safety-net sites remain. |
| 3 | **SBOM + dependency vulnerability scanning** | Add `picosentry scan --sbom` or a self-scan command that generates CycloneDX/SPDX SBOM and checks dependencies against OSV/pysec. | Code + CLI | **CLOSED** — release CI generates CycloneDX SBOM; `scripts/verify_release.py` parses it in post-release verification. |
| 4 | **Detection quality / adversarial mutation testing** | Add mutation harness that takes malicious fixtures and creates variants (base64, unicode escapes, string concat, dynamic import, compression) and measures recall degradation. | Tests + data | **CLOSED** — `adversarial_mutations.py` + `mutation_benchmark.py` + `tests/scan/test_mutation_benchmark.py` assert recall ≥85% and precision ≥95% under mutation. |
| 5 | **Operational hardening tests** | Add auth-bypass tests, rate-limit bypass tests, API contract tests, multi-tenant isolation tests for `serve` endpoints. | Tests | **CLOSED** — role escalation, permission-level enforcement, malformed tokens, query-param auth bypass, pathological-input fuzz, rate-limit bypass, tenant A↔B negative tests merged. |
| 6 | **Sandbox / runtime trust validation docs** | Write threat model doc + attack-surface review for seccomp/Landlock/daemon/plugin interfaces. | Docs | **CLOSED** — `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, and `docs/ops/runbook.md` cover trust boundaries, attack surface, and operations. |
| 7 | **Signed releases + provenance** | Add SLSA/Sigstore provenance generation to release CI; verify artifacts in CI. | CI | **CLOSED** — `.github/workflows/release.yml` attaches SBOM + Sigstore signatures + SLSA provenance; `.github/workflows/verify-release.yml` verifies after each release. |
| 8 | **Sandbox claims precision in README/product** | Separate "enforcement" vs "observability" claims; avoid overclaiming containment. | Docs | **CLOSED** — `docs/ARCHITECTURE.md`, `docs/PLUGIN_DEVELOPMENT.md`, and `README.md` distinguish seccomp enforcement from behavioral observation. |

### Proposed implementation order (historical — all items closed)

1. **#1 Plugin sandboxing / capability model** — done.
2. **#2 Fail-open / silent-fallback audit** — security-relevant slices done.
3. **#3 SBOM + self-dependency scanning** — done.
4. **#4 Adversarial mutation testing** — done.
5. **#5 Operational hardening tests** — done.
6. **#7 Signed releases / provenance** — done.
7. **#6 Threat model / attack-surface docs** and **#8 README precision** — done.

### Per-item plan

#### 1. Plugin sandboxing / capability model

**Goal:** answer the review questions with code: plugins are sandboxed, cannot
access secrets unless declared, cannot modify detection results, cannot execute
arbitrary host code.

**Concrete implementation:**
- Add `PluginManifest.capabilities` field (e.g., `network`, `filesystem`,
  `subprocess`, `secrets`, `detection_write`).
- Default capability set is empty (deny-by-default) or read-only.
- `PluginManager._load_plugin` spawns a subprocess worker using the existing
  sandbox/seccomp machinery instead of `importlib.import_module` in the server
  process.
- Worker receives a stripped environment (no host env/secrets) and a capability
  allowlist; the server process validates plugin responses before applying them.
- `PluginMetadata.effective_tier` reflects the capability set, not a manifest
  self-declaration.
- Add tests verifying a plugin cannot read env secrets, cannot write files
  outside its dir, and cannot modify scan results without the right capability.

**Files likely to change:**
- `picosentry/serve/services/plugin_manager.py`
- `picosentry/serve/services/plugin_host.py` (new)
- `picosentry/serve/plugins/test_plugin/plugin.json`
- `picosentry/serve/types.py` or `picosentry/serve/schemas.py`
- `tests/serve/test_plugin_sandbox.py` (new)
- `picosentry/experimental.py` (status update)

**Verification:**
- `tests/serve` green.
- New sandbox tests demonstrate capability enforcement.
- `detect_changes()` before commit; impact analysis on `PluginManager`.

#### 2. Fail-open / silent-fallback audit

**Goal:** find and remove remaining fail-open and silent-exception-swallowing
patterns across security-relevant paths.

**Concrete implementation:**
- Enumerate all `except Exception:` sites in `picosentry/`.
- For each security-relevant site (auth, admission, sandbox policy, plugin load,
  cluster token checks), either:
  - Convert to a specific exception and log with context, or
  - Make it fail-closed (deny/raise) with an opt-out flag.
- Add regression tests for each changed behavior.

**Files likely to change:** scattered; candidates include
`picosentry/serve/api/routers/*.py`, `picosentry/sandbox/daemon/*.py`,
`picosentry/sandbox/policy_versioned/*.py`, `picosentry/watch/*.py`.

**Verification:**
- `ruff check` + `mypy` clean.
- Full suite green.
- New tests for each fail-closed conversion.

#### 3. SBOM + dependency vulnerability scanning

**Goal:** PicoSentry can scan itself and report its own supply-chain posture.

**Concrete implementation:**
- Add `picosentry/scan/sbom.py` with CycloneDX/SPDX generation using installed
  packages (`importlib.metadata`).
- Add `picosentry/scan/vuln.py` to query OSV API or a local advisory cache for
  installed dependencies.
- Wire into CLI as `picosentry scan --sbom` and `picosentry scan --audit-deps`.
- Add tests using mocked OSV responses.

**Files likely to change:**
- `picosentry/scan/sbom.py` (new)
- `picosentry/scan/vuln.py` (new)
- `picosentry/cli.py`
- `tests/scan/test_sbom.py` (new)

**Verification:**
- SBOM generation round-trips and contains expected packages.
- Vuln scanner reports known test advisory.

#### 4. Adversarial mutation testing

**Goal:** measure recall degradation under obfuscation, as requested in Gap 2.

**Concrete implementation:**
- Add `picosentry/scan/mutation.py` with transformers: base64, unicode escapes,
  string concatenation, dynamic import, gzip/zlib, hex, rot13.
- Add `picosentry/scan/benchmark_mutation.py` to run the scanner against mutated
  malicious fixtures and report recall per mutation family.
- Add tests asserting recall does not drop below a configurable floor.

**Files likely to change:**
- `picosentry/scan/mutation.py` (new)
- `tests/scan/test_mutation.py` (new)

**Verification:**
- Mutation tests produce variants that the scanner still detects.
- Benchmark reports precision/recall per family.

#### 5. Operational hardening tests

**Goal:** add adversarial test coverage for `serve` and `daemon` interfaces.

**Concrete implementation:**
- Auth bypass tests: missing/invalid tokens, role escalation, org isolation.
- Rate-limit bypass tests: clock manipulation, burst patterns, path variants.
- API contract tests: verify response shapes match OpenAPI/consumer expectations.
- Multi-tenant isolation tests: cross-org reads/writes.

**Files likely to change:**
- `tests/serve/test_security_review.py`
- `tests/serve/test_tenant_isolation.py` (new)
- `tests/serve/test_rate_limit_bypass.py` (new)

**Verification:**
- `tests/serve` green; new tests demonstrate negative cases.

#### 6. Threat model / attack-surface docs

**Goal:** document trust boundaries so external reviewers can validate.

**Concrete implementation:**
- Add `docs/THREAT_MODEL.md` covering:
  - seccomp-bpf / Landlock boundaries
  - daemon interfaces and their authentication
  - plugin trust boundary (before and after sandboxing)
  - cluster communication security
  - serve RBAC / multi-tenant model
- Add `docs/ATTACK_SURFACE.md` listing exposed ports, file paths, env vars, and
  API endpoints with their required privileges.

**Files likely to change:**
- `docs/THREAT_MODEL.md` (new)
- `docs/ATTACK_SURFACE.md` (new)
- `README.md` (minor cross-links)

**Verification:**
- Docs render; no code changes.

#### 7. Signed releases + provenance

**Goal:** generate SLSA-style provenance and Sigstore-signed releases in CI.

**Concrete implementation:**
- Add GitHub Actions step to sign wheel/sdist with Sigstore after build.
- Add provenance generation step using `actions/attest-build-provenance` or
  custom SLSA provenance.
- Add CI job that downloads the release artifact and verifies the Sigstore
  signature.

**Files likely to change:**
- `.github/workflows/release.yml`
- `scripts/verify_release.py` (new)

**Verification:**
- CI dry-run passes; artifact signature verifies.

#### 8. README / product precision

**Goal:** avoid overclaiming sandbox containment.

**Concrete implementation:**
- In `README.md` and `picosentry/experimental.py`, clearly separate:
  - Enforcement: seccomp-bpf prevents syscalls.
  - Observability: behavioral analysis, not full syscall tracing.
- Add a "What the sandbox does NOT do" subsection.

**Files likely to change:**
- `README.md`
- `picosentry/experimental.py`

**Verification:**
- No code changes; review prose.

### Status

Roadmap is now in `state.md`. Next action: pick item #1 (plugin sandboxing) or
whichever the user prioritizes, run impact analysis, and implement.

## Closing status: 2026-06-20 — All documented infrastructure gaps closed

Resumed the `polish/bugfix-dead-code` branch and closed every gap that required
external infrastructure or build tooling. Working tree is clean and the full
suite is green.

### Gaps closed today

| Gap | Fix | Verification |
|-----|-----|--------------|
| **Admission controller live-test** | Fixed `AdmissionHandler.do_POST()` to parse path with `urllib.parse.urlparse()` so K8s `?timeout=<s>` query params don't 404. Added `scripts/live_test_admission.sh` and regression unit tests. | kind cluster test passed; 89 admission tests passed; full suite green. |
| **Postgres live-test** | Fixed DDL/fetchall/Boolean-default/FK-order issues for real Postgres. Added `scripts/live_test_postgres.sh`. | Postgres container test passed; 19 Postgres tests passed. |
| **Multi-arch Docker image** | Reworked `scripts/build_docker_multiarch.sh` to use a `docker-container` builder and produce a versioned OCI tarball for both `linux/amd64` and `linux/arm64`. | OCI tarball rebuild in progress; previous build produced `/tmp/picosentry-multiarch-2.0.14.oci.tar` with both platforms (166 MB). |
| **Serve tenant isolation** | Added org-scoped reads and permission-level guards across serve endpoints and DB-backed services. | `tests/serve` 288 passed; new tenant-isolation cases passed. |
| **Sigstore signing** | Updated `picosentry/scan/crypto.py` for sigstore 4.x API and added unit tests. | 21 crypto tests passed. |
| **Daemon socket lifecycle** | Fixed `port=0` handling, socket reuse, and clean thread shutdown. | 45 daemon tests passed; xdist-flakiness gone. |

### Verification snapshot

- Full suite — **3797 passed, 18 skipped, 4 subtests passed**.
- `ruff check picosentry tests` — pass.
- `mypy picosentry` — pass.
- Branch: `polish/bugfix-dead-code`, head `5d925e2`.

### Still running

- Background multi-arch OCI tarball rebuild (`task bezwmj72w`) is producing
  `/tmp/picosentry-multiarch-2.0.14.oci.tar`. It was at the wheel-build stage for
  both platforms when the session ended; the emulated `linux/arm64` dependency
  install takes ~25 minutes under QEMU. Check the task output Monday morning and,
  if successful, the local artifact will match the committed admission path fix.

### Monday starting point

1. Confirm the OCI tarball finished and contains both `linux/amd64` and
   `linux/arm64` manifests.
2. Decide whether to merge `polish/bugfix-dead-code` to `main` or open a PR.
   The branch is large (+8,695 / −8,560 lines vs main) but green and clean.
3. If merging, follow the verification protocol in the 2026-06-13 section
   (fresh clone + git archive inspection) before pushing.

## Current session: 2026-06-20 — Admission controller live integration test

Resumed the `polish/bugfix-dead-code` branch. The last documented gap that
required external infrastructure was the admission controller live-test: the K8s
admission webhook had only been exercised with mocked API-server requests.

### Environment

- No local `kubectl` or Kubernetes cluster; installed `kind v0.27.0` and
  `kubectl v1.30.2` into `~/.local/bin`.
- Used a temporary kind cluster `picosentry-admission-test` running
  `kindest/node:v1.32.2`.
- Used the local `kirkforge/picosentry:2.0.14` image loaded into kind.

### Bugs found and fixed

- `AdmissionHandler.do_POST()` matched the request path with an exact string
  comparison (`self.path != "/validate"`). The Kubernetes API server appends a
  `?timeout=<seconds>` query parameter to webhook URLs, so real requests were
  routed to `/validate?timeout=...` and rejected with 404. The API server then
  surfaced this as `failed calling webhook ... the server could not find the
  requested resource`. Fixed by parsing the path with `urllib.parse.urlparse()`
  and matching `parsed.path` instead.

### New helper

- `scripts/live_test_admission.sh`: creates a throw-away kind cluster, generates
  a CA + server TLS cert for `admission-webhook.picosentry.svc`, deploys the
  PicoSentry image as an in-cluster TLS webhook, registers a
  ValidatingWebhookConfiguration, and verifies:
  - privileged pods are denied,
  - compliant pods are admitted and become Ready,
  - pods without a container `securityContext` are denied.

### Verification

- `./scripts/live_test_admission.sh` — **PASSED**.
- `tests/sandbox/test_admission_*.py` — **89 passed**.
- `ruff check picosentry tests` — pass.
- `mypy picosentry` — pass.
- Full suite — **3797 passed, 18 skipped, 4 subtests passed**.

### Status

Admission controller has now been exercised against a real Kubernetes API
server. The remaining documented gaps from `state.md` that require external
infrastructure are closed; the only remaining cleanup is a fresh multi-arch
Docker image rebuild so the published `kirkforge/picosentry:2.0.14` manifest
contains the admission path fix.

## Current session: 2026-06-20 — Postgres live integration test

Resumed the `polish/bugfix-dead-code` branch. The next infrastructure-level gap
from `state.md` was the Postgres live-test: the `PostgresPool` implementation had
never been exercised against a real Postgres server.

### Environment

- No local `psql` or running Postgres; used a temporary `postgres:16-alpine`
  Docker container on `127.0.0.1:15432`.
- Installed `psycopg2-binary` into `.venv` via system `pip3 --prefix`.

### Bugs found and fixed

- `DatabaseManager.execute()` called `cursor.fetchall()` unconditionally. For
  Postgres, DDL statements produce no result set and raise
  `psycopg2.ProgrammingError: no results to fetch`. Added a guard that returns
  `[]` when `cursor.description is None`.

- `_sqlite_to_postgres()` only translated `INTEGER PRIMARY KEY AUTOINCREMENT`
  and placeholders. SQLite stores `BOOLEAN` as `0`/`1`, but Postgres rejects
  integer defaults on boolean columns. Added translation of
  `BOOLEAN DEFAULT 0/1` to `BOOLEAN DEFAULT FALSE/TRUE`.

- Migration 1's auto-translated `project_runs` table declared
  `FOREIGN KEY (org_id) REFERENCES orgs(id)`, but `orgs` is not created until
  migration 5. Postgres enforces FK references at `CREATE TABLE` time, so a fresh
  Postgres database failed to apply migration 1. Added an explicit `postgres_sql`
  for migration 1 that omits the forward FK reference (application code enforces
  the nullable `org_id`).

### New helper

- `scripts/live_test_postgres.sh`: starts a temporary Postgres container with a
  named Docker volume (the default overlay-backed data dir on this host cannot
  execute DDL), applies all 10 migrations through `DatabaseManager`, and runs a
  basic alerts CRUD round-trip plus an `IN (?, ?)` placeholder check.

### Verification

- `./scripts/live_test_postgres.sh` — **PASSED**.
- `tests/serve/test_postgres_backend.py` — 19 passed.
- `tests/serve/test_api.py` + `tests/serve/test_integration.py` — 198 passed.
- `ruff check picosentry tests` — pass.
- `mypy picosentry` — pass.
- Full suite — **3795 passed, 18 skipped** (unchanged).

### Status

Postgres backend has now been exercised against a real server and the migration
path is compatible with fresh Postgres installs. Remaining documented gap that
required external infrastructure: admission controller live-test against a real
K8s cluster.

## Current session: 2026-06-20 — Multi-arch Docker image

Resumed the `polish/bugfix-dead-code` branch. The next build-level gap from
`state.md` was the multi-arch Docker image: only `linux/amd64` had been built
and pushed.

### Changes

- `docker-bake.hcl`:
  - Updated default `TAG` from `v2.0.13` to `v2.0.14` to match `pyproject.toml`.

- `scripts/build_docker_multiarch.sh`:
  - Replaced the assumption that the default docker driver can do multi-platform
    local exports. The script now creates/uses a dedicated `docker-container`
    builder named `picosentry-multiarch`.
  - Removed the silent privileged `multiarch/qemu-user-static` registration and
    replaced it with an explicit pre-flight platform check. If `linux/arm64` is
    unavailable, the script prints the registration command and exits cleanly.
  - Build-only runs now produce a versioned OCI tarball
    (`/tmp/picosentry-multiarch-<TAG>.oci.tar`) instead of `type=docker`, because
    the docker exporter cannot load multi-platform manifests locally.
  - Added `--load` for single-platform local load when desired.
  - Disabled bake filesystem entitlements checks for the transient OCI output
    path (`BUILDX_BAKE_ENTITLEMENTS_FS=0`).
  - Switched the version probe to `python3`.

### Verification

- `docker buildx` and a dedicated `docker-container` builder are available locally.
- QEMU `binfmt` was registered for `aarch64` so the builder reports `linux/arm64`
  support.
- Isolated `linux/arm64` build passes `picosentry health` (24 min under QEMU).
- Full `linux/amd64 + linux/arm64` OCI archive built successfully:
  `/tmp/picosentry-multiarch-2.0.14.oci.tar` (166 MB), index contains both
  `linux/amd64` and `linux/arm64` image manifests.
- `--load` path produced `kirkforge/picosentry:2.0.14` locally (amd64 platform).
- `ruff check picosentry tests` — pass.
- `mypy picosentry` — pass.

### Caveat

The first full bake appeared to hang because the emulated arm64 `pip install`
step takes ~25 minutes under QEMU and the buildx CLI buffered all progress. The
build itself was not flawed; arm64 Python dependency installation under
user-space emulation is just extremely slow. The script now produces an OCI
tarball on completion instead of trying to `type=docker` load a multi-platform
manifest, which the docker driver cannot do.

### Status

Multi-arch Docker image build pipeline now works locally for both platforms.
Pushing still requires registry login. Remaining documented gaps that require
external infrastructure: Postgres live-test, admission controller live-test.

## Current session: 2026-06-20 — Serve tenant isolation hardening

Resumed the `polish/bugfix-dead-code` branch. The remaining code-level gap from
`state.md` was `serve` tenant isolation: read endpoints did not filter by
organization and access control was mostly role-level rather than
permission-level.

### Changes

- `picosentry/serve/database/manager.py`:
  - Added migration 10 `add_org_id_to_tenant_tables`, adding nullable
    `org_id INTEGER` columns and indexes to `intelligence`, `alerts`,
    `metrics`, `webhooks`, `scheduled_jobs`, and `correlation_chains`.

- `picosentry/serve/services/orchestrator.py`:
  - `run_project`, `_execute_project`, and `run_batch` now accept `org_id` and
    store it on `project_runs`.
  - Calls to `metrics.project_run`, `intel.ingest`, and `alerts.send` pass
    `org_id`.
  - Read helpers (`get_status`, `list_intelligence`, `list_alerts`,
    `get_metrics`, `generate_project_report`) accept and filter by `org_id`.

- `picosentry/serve/services/metrics.py`:
  - `project_run(..., org_id=None)` labels counters with `org_id`.
  - `to_dict(org_id=None)` and `to_prometheus(org_id=None)` filter counters
    by the org label.

- `picosentry/serve/services/intelligence.py`, `alert_hub.py`, `webhooks.py`,
  `scheduler.py`:
  - `ingest`, `send`, `create`, and `add_job` now write `org_id` to their
    respective tables.
  - `Webhook` and `ScheduledJob` dataclasses gained `org_id`.
  - Load helpers populate `org_id` from the DB.

- `picosentry/serve/api/server.py`:
  - Startup scheduler jobs (`periodic_cleanup`, `health_check`) pass
    `org_id=None`.

- `picosentry/serve/services/rbac.py`:
  - Added `READ_WEBHOOKS`, `READ_SCHEDULER`, `READ_ANOMALY`, `WRITE_SCHEDULER`,
    `WRITE_ANOMALY`.
  - Updated `ROLE_PERMISSIONS` so viewer/operator get the new read permissions.

- `picosentry/serve/api/routers/*`:
  - `projects.py`: `/projects/{id}/run` and `/batch/run` use `RUN_PROJECTS`
    and pass `org_id`; read endpoints filter by org.
  - `dashboard.py`: `/api/v1/dashboard/summary` filters `recent_intel`,
    `recent_alerts`, `pending_alerts`, and status by org.
  - `webhooks.py`: GET/POST use `READ_WEBHOOKS`/`WRITE_WEBHOOKS` and scope by
    org.
  - `scheduler.py`: GET/POST/PATCH/DELETE use scheduler permissions and an
    `_assert_job_in_org` guard.
  - `anomaly.py`: switched role checks to `READ_ANOMALY`/`WRITE_ANOMALY`.
  - `metrics.py`: `/metrics`, `/metrics/prometheus`, `/metrics/json` use
    `READ_METRICS` and pass `org_id`.

- `tests/serve/test_integration.py`:
  - `_register_and_login` now auto-creates a default org for the test user.
  - Added `TestTenantDataIsolation` with
    `test_tenant_cannot_read_other_org_data` and
    `test_tenant_cannot_acknowledge_other_org_alert`.

- `tests/serve/test_api.py`:
  - `auth_token` fixture ensures `pytest_user` has a default org.
  - `test_create_and_delete_job` now creates an operator user/org explicitly.

### Verification

- `tests/serve/test_integration.py::TestTenantDataIsolation` — **7 passed**.
- `tests/serve` — **288 passed**.
- Full suite — **3795 passed, 18 skipped, 4 subtests passed** in ~5 min.
- `ruff check picosentry tests` — pass.
- `mypy picosentry` — pass.

### Status

`serve` tenant isolation is now enforced for DB-backed reads and in-memory
metrics, and access control is permission-level for the scoped endpoints.
Remaining documented gaps that require external infrastructure or build tooling:
Postgres live-test, admission controller live-test, multi-arch Docker image.

## Current session: 2026-06-20 — Sigstore signing + DDoS flakiness

Resumed the `polish/bugfix-dead-code` branch. After the daemon socket-lifecycle
fix, the next gap on `state.md` was corpus pack signing. Postgres is not
available locally, so I pivoted to the Sigstore signing path.

### Sigstore 4.x API drift

`picosentry/scan/crypto.py::sign_content_sigstore` and
`verify_content_sigstore` were written against an older sigstore API that no
longer exists in the installed `sigstore>=4.0`:

- `Issuer.production()` and `sigstore.sign()` are gone.
- The current API uses `ClientTrustConfig.production()`,
  `SigningContext.from_trust_config(...)`, and `Signer.sign_artifact(...)`.
- Verification uses `Verifier.production(offline=...).verify_artifact(...)` with a
  `VerificationPolicy`.

### Changes

- `picosentry/scan/crypto.py`:
  - Rewrote `sign_content_sigstore` for the sigstore 4.x signing flow.
  - Added `SIGSTORE_IDENTITY_TOKEN` env-var support so CI/container signing can
    use a pre-shared OIDC token instead of blocking on interactive OAuth.
  - Rewrote `verify_content_sigstore` for the sigstore 4.x verification flow;
    uses the stored `signer_identity` as the expected identity when available,
    otherwise falls back to `UnsafeNoOp` policy.
  - `verify_content` now passes `signature_bundle.signer_identity` into the
    Sigstore verifier.
  - Added missing top-level `import os`.

- `tests/scan/test_crypto.py`: added `TestSigstoreSigning` and
  `TestSigstoreVerification` with mocked sigstore 4.x objects to exercise both
  the env-token and interactive-issuer signing paths, plus verification
  success/failure.

### DDoS shield test flakiness

The full suite revealed that `test_lookalike_paths_are_not_exempt` was failing
in isolation. Like `test_non_health_paths_still_rate_limited`, it needs the
injectable `_now` clock; on a fast machine the 10-second window drains old
entries before the global limit is reached.

- `tests/serve/test_ddos_health_exempt.py`: added `fake_now` clock to
  `test_lookalike_paths_are_not_exempt`.

### Verification

- `tests/scan/test_crypto.py` — **21 passed**.
- `tests/scan/test_crypto_integration.py` — **10 passed**.
- `tests/serve/test_ddos_health_exempt.py` — **7 passed**.
- `tests/sandbox/test_daemon*.py` — **45 passed**.
- `ruff check picosentry tests` — pass.
- `mypy picosentry` — pass.
- Full suite — **3793 passed, 18 skipped, 4 subtests passed** in ~5 min.

### Status

Sigstore signing/verification now targets the installed API and has unit tests.
The DDoS shield lookalike test is deterministic. Remaining documented gaps:
Postgres live-test, admission controller live-test, multi-arch Docker image,
`serve` tenant isolation hardening.

## Current session: 2026-06-20 — Daemon socket lifecycle gaps

Resumed the `polish/bugfix-dead-code` branch. User pointed at the daemon as
holding remaining gaps; running the daemon test suite under `uv` showed flaky
`OSError: [Errno 98] Address already in use` failures in
`TestDaemonLifecycle` when executed with `pytest-xdist`.

### Root cause

`PicoDomeDaemon.__init__` used `port or ...` for port resolution, which treated
`port=0` ("bind any free ephemeral port") as falsy and silently fell back to
the default `8443`. Every lifecycle test that passed `port=0` was actually
trying to bind port 8443; under parallel test execution this produced
intermittent EADDRINUSE failures.

### Changes

- `picosentry/sandbox/daemon/daemon.py`:
  - Port, host, and metrics-port initialization now distinguish `None`
    (use default/env) from explicit values including `0`.
  - Added `_PicoDomeHTTPServer` subclass with `allow_reuse_address = True` so
    rapid daemon restarts in tests and production don't hit TIME_WAIT.
  - `stop()` now calls `server_close()` on the API and metrics servers and
    joins their background threads (with a 5 s timeout) for a clean shutdown.
  - Removed redundant `if background`/`else` branches when starting the
    metrics server thread.

### Verification

- `tests/sandbox/test_daemon*.py` — **45 passed** (was flakily failing 2 under
  xdist before the fix).
- `ruff check picosentry tests` — pass.
- `mypy picosentry` — pass.
- Full suite — **3789 passed, 18 skipped, 4 subtests passed** in ~4 minutes.

### Status

Daemon lifecycle now handles ephemeral ports and socket teardown correctly under
parallel tests. This closes the last identified daemon-specific gap on the
polish branch.

## Current session: 2026-06-19 — Codebase health analysis

Analysed the `polish/bugfix-dead-code` branch after compaction failed to produce
a summary. Working tree was clean (no uncommitted changes); ran full suite,
lint, type-check, coverage, and GitNexus checks.

### Quantitative snapshot

- 342 production `.py` files, 197 test `.py` files, ~103,450 total Python LOC.
- 3,807 tests collected; 3,789 passed, 18 skipped (environmental: sandbox
  workloads, seccomp-trace). 4 subtests passed.
- `ruff check picosentry tests` — 0 issues.
- `mypy picosentry` — 0 issues (342 source files).
- PTH/pathlib rule set — 0 issues.
- Line coverage: **75%** (26,751 statements, 6,671 missed).
- Branch vs `main`: 421 files, +8,695 / −8,560 lines.

### Strong points

- **Test discipline:** regression tests added alongside every recent behavior
  change (serve security, cluster lifecycle, OTel shutdown, DDoS clock).
- **Lint/type hygiene:** ARG, FA, TCH, PTH families enabled and clean.
- **Honest maturity model:** `picosentry/experimental.py` is the single source
  of truth for README status table; version strings consistent (`2.0.14`).
- **Serve security:** FastAPI dependency injection with role and permission
  guards; recent hardening closed public metrics, overly permissive admin
  routes, and query-param login.
- **Dead-code state:** GitNexus shows no stray dead symbols in the working
  tree; last removal had clean MEDIUM impact on intended flow only.

### Rough spots / honest gaps

- **Coverage uneven:** worst-covered production files are CLI entrypoints and
  small argparse modules (`cli.py`, `sandbox/cli_commands/*`, `__main__.py`,
  `_core/policy.py`). Some are 0% but small. More concerning:
  - `picosentry/watch/engine/rule_engine.py` — 0% (98 statements)
  - `picosentry/watch/middleware/rate_limiter.py` — 0% (43 statements)
  - `picosentry/watch/cli.py` — 38%
  - `picosentry/serve/services/scheduler.py` — 43%
  - `picosentry/serve/services/plugin_manager.py` — 64%
- **Broad exception handling:** 116 `except Exception:` sites in production.
  Some are legitimate defensive guards; others swallow errors that should be
  more specific or logged with context.
- **Serve tenant isolation incomplete:** org model and cross-tenant API-key
  check exist, but most read endpoints still do not filter by org; access is
  mostly role-level rather than permission-level RBAC.
- **Branch size:** `polish/bugfix-dead-code` has become a large omnibus
  pre-release sweep (421 files vs main). Good for a focused cleanup pass,
  but future work should be smaller, theme-based branches.
- **Environmental test gaps:** 13 sandbox malicious-workload tests and 6
  seccomp-trace tests are skipped unless `PICODOME_SANDBOX_TESTS=1` /
  `PICODOME_HAS_SECCOMP=1`.

### Security posture

- Auth: Bearer tokens + role/permission dependencies; recent hardening
  applied.
- Tenant isolation: partial — org primitives exist, endpoint filtering missing.
- Input validation: FastAPI/Pydantic for serve; rule engine for scanner.
- Secrets: login moved to JSON body; CLI security-check prints by design.
- Network: daemon TLS/mTLS; serve DDoS/rate-limit middleware.
- Crypto: Sigstore/minisign signing; optional-dependency checks use
  `importlib.util.find_spec`.

### Recommendations

1. **Merge this branch soon** — suite green, lint clean, branch is large.
2. **Add targeted tests** for 0%-coverage watch modules before declaring watch
  fully beta-clean.
3. **Audit `except Exception:` sites** — convert recoverable ones to specific
  exceptions and add structured logging.
4. **Complete org-scoped filtering** in serve read endpoints.
5. **Run CI with environmental flags** for sandbox/seccomp tests.
6. **Future work in smaller, theme-based branches.**

### Verdict

Codebase is healthy: green suite, clean lint, honest maturity documentation,
solid recent security/dead-code work. Remaining issues are coverage breadth
and incomplete org isolation, not fundamental design problems. Next step
should be final review and merge rather than more feature work.

## Current session: 2026-06-19 — Dead-code cleanup continuation

Resumed the polish branch after the serve security hardening
commit. Ran the full suite in `.venv` (3789 passed, 18 skipped). Used GitNexus to
look for dead-code candidates; the obvious unused symbols have already been
removed in earlier commits, but `picosentry/scan/crypto.py` still contained a
pointless `minisign -G -p -` subprocess call inside `sign_content_minisign`
that always assigned `signer = "minisign-key"` regardless of outcome.

### Changes

- `picosentry/scan/crypto.py:sign_content_minisign`: removed the dead
  key-generation subprocess call and its try/except wrapper; collapsed to a
  direct `signer = "minisign-key"` assignment.

### Verification

- `ruff check picosentry tests` — pass
- `mypy picosentry` — pass
- `tests/scan` — 1641 passed, 4 subtests passed
- `detect_changes({scope: "working"})` — 1 changed symbol / 1 affected process,
  MEDIUM risk (expected: only the export_signed_policy minisign flow).
- GitNexus reindexed successfully after commit.

### Commit

- `aa79d56` — `refactor: remove pointless minisign key-generation dead code in sign_content_minisign`

## Current session: 2026-06-19 — Serve security surface hardening

Continued the `polish/bugfix-dead-code` branch with a focused pass on the
honest `serve is EXPERIMENTAL` gap from `state.md`.

### Changes

- `picosentry/serve/api/routers/metrics.py`: `/metrics/prometheus` now requires
  authentication (`Depends(get_current_user)`) instead of being public.
- `picosentry/serve/api/routers/admin.py`: `/backups`, `/logs`, `/logs/stats`,
  `/logs/rotate`, `/audit/stats`, and `/events/history` now require
  `require_role("admin")` instead of any authenticated user.
- `picosentry/serve/api/routers/auth.py`: `/auth/login` now accepts credentials
  as a JSON body (`_LoginRequest`) instead of URL query parameters, preventing
  passwords from ending up in access logs.
- Updated all test call sites and fixtures to POST JSON to `/auth/login` and to
  supply admin tokens where admin-only endpoints are tested; added a
  `test_prometheus_endpoint_requires_auth` case.

### Verification

- `ruff check picosentry tests` — pass
- `mypy picosentry` — pass
- `tests/serve` — 286 passed
- Full suite — 3784 passed, 22 skipped (excluding `tests/scan/test_timeout_plugin.py`
  because `pytest-timeout` is not installed in the externally-managed system Python)
- `detect_changes({scope: "working"})` — 29 changed symbols / 19 affected processes,
  **CRITICAL** risk. This is expected: the patch intentionally touches several
  high-trust `serve` endpoints. All affected execution flows are the login/auth
  and admin process traces, and tests pass.

### Remaining honest gaps

- `serve` is still marked **EXPERIMENTAL**, but the most obvious surface issues
  called out in the security review (public metrics, overly permissive admin
  endpoints, query-param credentials) are now closed.
- Postgres live-test, admission controller live-test, corpus pack signing
  (Sigstore), and multi-arch Docker image remain future work.

## Current session: 2026-06-19 — Polish/bugfix dead-code branch

Resumed the polish branch after the `PTH`/`pathlib` production-code cleanup.
Addressed the four scoped items one by one.

### Task 1: Flaky DDoS rate-limit test

Root cause was wall-clock timing in `tests/serve/test_ddos_health_exempt.py::test_non_health_paths_still_rate_limited`.
Added an injectable `_now` clock to `picosentry/serve/middleware/ddos_shield.py`
and wired the test to a deterministic advancing clock.

- `__init__` now accepts `_now: Callable[[], float] = time.monotonic`
- `dispatch` calls `self._now()` instead of inline `time.monotonic()`
- `_build_app` in the test forwards `_now` to both middleware instances

Result: test passes reliably.

### Task 2: OpenTelemetry background exporter hanging tests

Root cause was `init_tracing` creating a default `OTLPSpanExporter()` pointing
at `localhost:4317` even when no endpoint was configured, plus missing provider
shutdown in tests.

- `picosentry/watch/telemetry/otel.py`: removed default exporter creation; added `shutdown_tracing()`
- `picosentry/serve/services/observability.py`: added `shutdown_telemetry()`
- `tests/watch/conftest.py`: autouse fixture calling `shutdown_tracing()`
- `tests/serve/conftest.py`: autouse fixture calling `shutdown_telemetry()`

Result: full suite no longer hangs on OTel background threads.

### Task 3: Enable broader ruff rule families

Added the `ARG` (unused-argument), `FA` (future-annotations), and
`TCH` (type-checking import placement) families to
`[tool.ruff.lint].select`. Applied targeted per-file ignores for `ARG` and
`TC001`/`TC002` noise in generated/contractual code and tests; ignored `TC003`
(stdlib imports) globally as low-value churn. `FA` was already clean across
the codebase. `TC001`/`TC002` fixes moved 37 annotation-only application and
third-party imports into `if TYPE_CHECKING:` blocks across 30 production files.

Also removed the now-unused `all_rules` parameter from
`picosentry/watch/prompt_guard/scorer.py` and updated all callers/tests.

Result: `ruff check picosentry tests` clean with `ARG`, `FA`, and `TCH`
(`TC001`/`TC002`) enabled.

### Task 4: Cluster gossip peer-polling functional gap

`state.md` listed: "No network transport between peers — the endpoints exist
but there's no periodic poll loop calling them." The poll loop (`_gossip_loop`)
and HTTP fetcher (`_fetch_and_merge_peer`) already existed in
`ClusterManager`, but `PicoDomeDaemon` never started the cluster manager, so the
gossip threads never ran in daemon mode.

Wired cluster lifecycle into the daemon:

- `picosentry/sandbox/daemon/daemon.py`: `__init__` accepts `cluster_config`,
  `start()` calls `setup_cluster_manager(...).start()` when a cluster token is
  configured, `stop()` shuts the manager down.
- `picosentry/sandbox/daemon/app.py`: `create_app()` forwards `cluster_config`.
- `picosentry/sandbox/cli_commands/daemon.py`: added `--cluster-token`,
  `--cluster-address`, `--cluster-port`, `--cluster-backend`,
  `--cluster-heartbeat-interval`, `--cluster-heartbeat-timeout`,
  `--cluster-tls-cert`, `--cluster-tls-key`, `--cluster-tls-ca` (all also
  configurable via `PICODOME_CLUSTER_*` environment variables).
- `tests/sandbox/test_daemon_handler.py`: added autouse fixture to reset the
  global cluster singleton and tests verifying the manager starts/stops with the
  daemon and uses the singleton expected by HTTP handlers.

Result: a daemon launched with `--cluster-token` now runs the periodic gossip
loop and cluster snapshot endpoints are active.

### Verification

- `ruff check picosentry tests` — pass
- `mypy picosentry` — pass
- `ruff check picosentry tests --select PTH` — pass
- Targeted tests for touched areas — 125 passed (cluster + daemon lifecycle)
- Full suite — 3787 passed, 18 skipped

### Notes

- `.venv` is in `.gitignore`; environment changes are not committed.
- To run tests going forward, use `.venv/bin/python -m pytest` (now runs with
  `-n auto` by default via `pyproject.toml`). Use `-n0` to force single-process
  mode when debugging.

## Last session: 2026-06-19 — Production `PTH`/`pathlib` polish on `polish/bugfix-dead-code`

Resumed the polish branch after test cleanup was complete. Worked production code
with the same style/pathlib/dead-code treatment. **5 new commits** in this session,
all green.

### Commits made

1. **refactor: use `importlib.util.find_spec` for optional-dependency availability checks**
   - Replaced try/except imports used only to probe package availability with
     `importlib.util.find_spec` in `cli.py`, `sandbox/grpc_transport`,
     `scan/crypto`, and `serve/services/plugin_manager`.
   - Removed now-unnecessary `noqa: F401` comments.

2. **style: replace builtin `open()` with `Path.open()` across production code**
   - 24 files, 49 `open(...)` → `path.open(...)` / `Path(...).open(...)` conversions.
   - Added `Path` imports where needed; removed the now-unused `noqa: SIM115` on
     `sandbox/audit/sinks/file_sink.py`.
   - `detect_changes` reported CRITICAL breadth (55 symbols / 20 affected
     processes), but full suite passed: **3778 passed, 22 skipped**.

3. **style: convert remaining simple `os.path` / `os.unlink` / `os.replace` calls to pathlib**
   - 7 files: `sandbox/daemon/handler_mixins`, `sandbox/l3/backends/seatbelt_backend`,
     `sandbox/license`, `sandbox/mtls/context`, `sandbox/policy_versioned/store`,
     `scan/daemon`, `serve/services/backup`.
   - Kept public string APIs intact where possible.

4. **style: complete pathlib conversion in `plugin_manager` and license loader**
   - Finished the discovery loop, `resolved_dirs()`, `reload()`, and module-checksum
     path handling in `serve/services/plugin_manager.py` using `Path` while
     preserving the string-based public API expected by tests.
   - Widened `sandbox/license.py::_load_license_file` to accept `str | Path`.

5. **test: replace `os.path.isfile` fallback in license mock with `Path.is_file()`**
   - Removed the last PTH issue from the test suite.

### Verification (end of session)

- `ruff check picosentry tests` — pass
- `mypy picosentry` — pass
- `ruff check picosentry tests --select PTH` — pass (zero PTH issues in production or tests)
- Focused tests passed for later commits (license, plugin auto-load, daemon handler, mtls, policy_versioned)
- GitNexus reindexed successfully after every commit

### Remaining loose ends

- `pytest-timeout` is not installed in the externally-managed system Python, so
  the full suite must still be run with `--ignore=tests/scan/test_timeout_plugin.py`
  or `-o addopts=`.
- One flaky cross-test rate-limit interaction in
  `tests/serve/test_ddos_health_exempt.py::test_non_health_paths_still_rate_limited`
  was observed; it passes in isolation and is considered pre-existing test-order noise.
- A single `os.path.normpath(member.name)` remains in
  `picosentry/serve/services/backup.py:86`; PTH does not flag it.
- A handful of `os.path.realpath` usages remain in
  `tests/serve/test_plugin_auto_load.py` as test assertions, not production code.

### Optional next steps

- Continue beyond `PTH` into broader dead-code discovery via GitNexus, or
- Resolve the `pytest-timeout` environment gap so the full suite runs without exclusion.

## Last session: 2026-06-19 — Dead-code polish on `polish/bugfix-dead-code`

Resumed the polish branch after a string of style-fix commits. Established that `ruff` and `mypy` are green. Full suite in this venv is
**3787 passed / 18 skipped / 0 failed** with the default `-n auto` xdist
configuration.

Removed six unused symbols identified via GitNexus impact analysis (all LOW / 0
callers):

- `picosentry/sandbox/guards.py` — removed `validate_result_sorted` (tests use
  their own `_validate_result_sorted` helper; public function was dead).
- `picosentry/sandbox/retention/manager.py` — removed `RetentionConfig.from_yaml_config`.
- `picosentry/scan/corpus_governance.py` — removed `FreshnessReport.sources_by_trust`
  and `CorpusGovernance.freshness_report`.
- `picosentry/scan/detection_quality.py` — removed `DetectionBenchmark.get_suppressed_by_default`.
- `picosentry/sandbox/ratelimit/queue.py` — removed `JobQueue.list_pending`.
- `picosentry/sandbox/daemon/handler_routes_post.py` — removed unused `token`
  parameter from `_handle_cluster_merge_snapshot` (it reads the cluster token
  from headers via `_check_cluster_token` instead).

Continued the sweep and removed two more unused symbols from the `scan` package
(commit `9d583b7`):

- `picosentry/scan/config.py` — removed `apply_env_overrides` and its private
  `_ENV_TO_ATTR` mapping. The sandbox package has its own wired env-override
  helper; the scan equivalent was never called.
- `picosentry/scan/workspace.py` — removed `scan_workspace_to_json`. Callers can
  obtain the same output via `scan_workspace(...).to_dict()` and the CLI already
  serializes results through the formatter layer.

Also fixed the DDoS health-exempt test helper that was accidentally stacking
 two shield middlewares (commit `78905af`). `_build_app` now returns a single
middleware instance that is also used directly as the ASGI app, so the
reference the tests inspect is the same one enforcing limits.

Verification:
- `ruff check picosentry tests` — pass
- `mypy picosentry` — pass
- `tests/scan` — 1641 passed, 4 subtests passed
- `tests/serve` — 284 passed
- Full suite — 3787 passed, 18 skipped, 4 subtests passed
- `detect_changes({scope: "working"})` — 2 files, LOW risk

### Loose ends resolved

- `pytest-timeout` is present in `.venv`; `tests/scan/test_timeout_plugin.py`
  passes, so the suite no longer needs to be run with exclusions.
- The DDoS health-exempt double-middleware issue is fixed; the previously
  observed cross-test flakiness no longer reproduces.

### Remaining documented gaps

- Postgres live-test.
- Admission controller live-test.
- Corpus pack signing (Sigstore tooling).
- Multi-arch Docker image.
- `serve` security review.

## Last session: 2026-06-13 — Enterprise Beta push

5 commits from `be11a5e` → `22fb944` on `origin/main`.

### What shipped

| Commit | What |
|--------|------|
| `9d2e979` | Admission CLI, sandbox argparse fix, benchmark honesty, v2.0.13 bump |
| `baae429` | Postgres backend, cluster gossip tests, Docker image build |
| `6010c00` | Fix setuptools pin for PyPI upload compatibility |
| `86ae593` | Cluster gossip HTTP endpoints (GET/POST /api/v1/cluster/snapshot) |
| `22fb944` | Wire corpus marketplace into unified picosentry CLI |

### External artifacts

- **PyPI:** `picosentry 2.0.13` published — `pip install picosentry`
- **Docker Hub:** `kirkforge/picodome:v2.0.13` (368MB, all 4 components healthy)
- **GitNexus:** 12,653 nodes, 26,676 edges, 300 flows
- **graphify:** 18,245 nodes, 35,347 edges, 1,048 communities

### Honest component maturity

| Component | Maturity | Honest assessment |
|-----------|----------|-------------------|
| **scan** | STABLE | 7 ecosystems, 53 rules, 178 fixtures, 100% precision/recall on CI floor. Small corpus — the 100% is a smoke test, not a statistical claim. `⁂` marker keeps us honest about vacuous precision rows. |
| **sandbox** | BETA | L3 seccomp-bpf works on Linux. L4 behavioral analysis works. seccomp-trace needs `CONFIG_SECCOMP_LOG=y` (kernel config). macOS seatbelt backend exists but lightly tested. Subprocess backend is the fallback. |
| **watch** | BETA | Prompt injection detection (L5) + output validation (L6) work. CLI + HTTP server both functional. Deterministic. Normalizer handles homoglyphs, encoding attacks. |
| **serve** | EXPERIMENTAL | API server, dashboard, RBAC, multi-tenant isolation, webhooks, scheduler all exist. Works in single-node. **Do not expose to untrusted networks without review.** |
| **daemon** | BETA | HTTP + gRPC transport. SQLite + JSONL job stores. Auth, rate limiting, TLS/mTLS, audit logging. Works. |
| **admission** | BETA | K8s admission webhook with TLS, pod security validation, optional image scanning. CLI wired. **Not tested against a real K8s cluster.** |
| **cluster** | EXPERIMENTAL | Gossip primitives (snapshot/merge) exist with HTTP endpoints. Leader election converges. 7 multi-node gossip tests pass. **No network transport between peers — the endpoints exist but there's no periodic poll loop calling them.** |
| **corpus marketplace** | BETA | Export/import/validate/list/sign all work. 3 built-in packs. Wired into unified CLI. |
| **Postgres backend** | STUB → BETA | `PostgresPool` has real psycopg2 implementation. `DatabaseManager` handles both SQLite and Postgres. **Migrations are SQLite-specific DDL — a real Postgres deploy needs separate schema.** Not tested against a live Postgres instance. |
| **DDoS shield** | BETA | Token-bucket per-path + global bucket. Health-path exemption. 6 tests. Works. |
| **Plugin system** | BETA | Loads, validates, dispatches. Ed25519 signature verify. PicoShogun plugin protocol. |
| **Docker image** | STABLE | `kirkforge/picodome:v2.0.13` on Docker Hub. All 4 components pass health check. Non-root user, tini init, seccomp runtime deps. |

### What's still not done (honest)

- ~~**Cluster peer polling loop.**~~ Wired into `PicoDomeDaemon` in this session: a daemon launched with `--cluster-token` starts `ClusterManager`, which runs the periodic `_gossip_loop` that calls `GET /cluster/snapshot` on peers and merges the result via `POST /cluster/snapshot`.
- **Postgres live-test.** Code is implemented but never connected to a real Postgres. Migrations are SQLite-only SQL.
- **Admission controller live-test.** Not tested against a real K8s API server.
- **Corpus pack signing.** Sigstore integration exists but `--sign sigstore` requires Sigstore tooling not shipped in the image.
- ~~**Test suite parallelism.**~~ Enabled `pytest-xdist` by default (`-n auto` in `[tool.pytest.ini_options].addopts`). Fixed the order-dependent `tests/scan/test_engine_timebox.py` tests that scanned the repo root; they now use small `tmp_path` fixtures. Full suite runs green in ~5 minutes under xdist (3787 passed, 18 skipped).
- **Multi-arch Docker image.** Only `linux/amd64` built. No `linux/arm64`.
- **`serve` is still EXPERIMENTAL.** The README says "do not expose to untrusted networks" and that's still true — the FastAPI app hasn't had a security review.

### Test counts (2026-06-13)

- sandbox: 1451 passed, 18 skipped (need root/libseccomp)
- integration: 34 passed
- gossip: 7 passed (new)
- DDoS health exempt: 6 passed
- Full suite: 1492 passed, 18 skipped in 38s

### Verification protocol

1. `git clone git@github.com:KirkForge/PicoSentry.git /tmp/verify-push` fresh
2. `git -C /tmp/verify-push log --oneline | head 10`
3. Compare to local `git log --oneline | head 10`
4. `git archive --format=tar origin/main | tar -t | grep -E "AGENTS|CLAUDE|state\.md|^\.github"`
5. All clean → push

---

## Gap Audit — verified 2026-07-02

Verified against live code in `picosentry/` for every concrete item in
`picosentry-gaps-plan.md` (Parts 1–3). Discrepancies noted inline.

### 1. #5 Plugin worker crashes on malformed JSON — FIXED
`picosentry/serve/services/plugin_worker.py:58-60` — `_recv()` catches
`json.JSONDecodeError`, logs + sends error frame, keeps serving.

### 2. #6 Plugin subprocess has no timeout — FIXED
`picosentry/serve/services/plugin_host.py:216` — `_read_message()` uses
`select.select([proc.stdout], [], [], self.timeout)`; on timeout logs +
terminates worker. Falls back to blocking where select unsupported.

### 3. #7 Daemon image-scan URL not SSRF-protected — FIXED
`picosentry/sandbox/admission/scanner.py:22-28` delegates to
`picosentry/scan/_network.py:33` `assert_url_safe()`; validated in
`__init__` when scanning enabled (fail-closed at startup). Loopback/
cluster-internal intentionally allowed.

### 4. #10a Registry parse silently empties / crashes — FIXED
`picosentry/serve/services/orchestrator.py:91` — `_load_registry()` catches
`(OSError, json.JSONDecodeError)` with logged error; skips individual
malformed entries instead of aborting the whole load.

### 5. #10c Bare `except:` on plugin stdin close — FIXED
`picosentry/serve/services/plugin_host.py:242` — narrowed to
`except OSError as exc:` with debug log + `None` guard on `stdin`.

### 6. #8 / new Rate limiter ignores `max_clients` (OOM DoS) — FIXED
`picosentry/watch/ratelimit.py:31,34` — `is_allowed` denies new clients
when table full (after stale-eviction pass); existing clients never
blocked. This is the live limiter used by `watch/server.py`.

### 7. A1 Plugin `print()` poisons RPC channel — FIXED
`picosentry/serve/services/plugin_worker.py:41-44` — `main()` dups real
stdout fd for framed responses before importing plugin, then points
`sys.stdout = sys.stderr`. (Also covers P1.2.)

### 8. A2 SSRF guard not centralized — FIXED
`picosentry/scan/_network.py:33` `assert_url_safe()` called inside
`safe_urlopen` (line 73); scanner delegates. JWKS / corpus / daemon pushes
all inherit it. +3 tests. (Also covers P1.1 and LOW #23 surface.)

### 9. #10b Scheduler subprocess timeout — FIXED (claim matches code)
`picosentry/serve/services/scheduler.py:218` `subprocess.run(...,
timeout=3600)`; broad `except Exception` at line 276 catches
`TimeoutExpired`, logs via `logger.exception`, marks job failed, reschedules.
No thread hang. Gap file's "already fixed" claim verified.

### 10. A4 Dead duplicate rate limiter — FIXED
`picosentry/watch/middleware/rate_limiter.py` removed (only
`__pycache__`-free); live `watch/ratelimit.py` is the sole copy.

### 11. A5 Dead duplicate rule engine — FIXED
`picosentry/watch/engine/` contains no `.py` files (only stale
`__pycache__`); live `watch/prompt_guard/rules.py` is the sole
`RuleEngine`. Stale `__pycache__` is cosmetic, not loadable.

### 12. A3 ruff/mypy clean claim vs reality — FIXED
`ruff check` on all Part-1 touched files: "All checks passed!". The 5
pre-existing findings + 6 mypy errors cleared (per 2026-06-28 session
notes).

### 13. P1.3 Watch rule-engine + rate-limiter tests (#8) — FIXED
`tests/watch/test_rule_engine.py` and `tests/watch/test_ratelimit.py`
exist; cover YAML/regex/duplicate/unexpected errors + RateLimiter
eviction branches.

### 14. P1.4 Symlink handling in scan (#18) — FIXED
`picosentry/scan/engine.py:225-231` rejects symlinked scan targets at
entry, catches `(OSError, RuntimeError)` from loops; corpus scan skips
symlinks (line 147). `tests/scan/test_symlink_handling.py` exists.

### 15. P1.5 `--check-corpus-age` flag (#15) — FIXED
`picosentry/scan/cli_commands/check.py:30` adds `--check-corpus-age`;
`engine.is_corpus_stale()` helper; exit 5 when stale. Tests in
`tests/scan/test_cli_extended.py`.

### 16. P1.6 Docs: THREAT_MODEL (#13) + ops runbook (#16) — FIXED
`docs/THREAT_MODEL.md` and `docs/ops/runbook.md` both exist and are
checked in.

### 17. P2 Watch fail-closed (#24) — FIXED
`picosentry/watch/prompt_guard/__init__.py:65,136-142` —
`PICOSENTRY_WATCH_FAIL_CLOSED` flag (default off); blocks when all rules
failed to load + catches rule-eval exceptions. Regression tests in
`tests/watch/test_prompt_guard.py`.

### 18. P3 Supply-chain / release integrity (#4, #25) — FIXED
`.github/workflows/release.yml` — CycloneDX SBOM (line 45-47), Sigstore
signing (line 58), SLSA provenance attached to GitHub Release. v2.0.17
published to PyPI + GitHub Release.

### 19. P4 #9 tenant isolation — FIXED
`picosentry/serve/api/routers/dashboard.py` and `projects.py` pass
`org_id=org["id"]` to every `orchestrator.list/get/run/export` call;
`org_projects` junction scopes project lists. A↔B negative test in
`tests/serve/test_integration.py`.

### 20. P4 #1 serve threat model + auth-bypass/privesc + fuzz — FIXED
`WRITE_ALERTS` permission added (projects.py:186); `/anomaly/check`
changed to `WRITE_ANOMALY` (anomaly.py:35,59). Regression tests for role
escalation, permission-level enforcement, malformed tokens, query-param
auth bypass, + lightweight pathological-input fuzz harness.

### 21. P4 #12 Postgres migration audit — PARTIAL
`.github/workflows/ci.yml:114-144` `postgres-live-test` matrix job runs
against PG15/16 service container exercising migrations/CRUD/placeholder
translation. **Remaining:** mark `postgres-live-test` as a required
branch-protection check (repo-admin action, not code). Code side done.

### 22. P4 #10 broad exception audit — SECURITY-RELEVANT SLICES FIXED
Per state.md session log: auth.py, webhook/alert, daemon route-handler,
serve middleware/server, watch, cluster + policy_versioned, serve
services, plugin host/manager, correlation engine, serve/api
middleware/server/rate_limit/DB manager, serve routers, backup service,
serve log/alert services, serve execution/observability, plugin manager
loading paths, sandbox health/readiness, baseline hardening audit
logging, and the serve event bus subscriber dispatch slices all narrowed
to specific exception types + logged. Only intentional boundaries remain
(`plugin_worker.py` RPC loop, `database/pools.py` deliberate
rollback+re-raise). **Live count:** ~151 broad `except Exception` sites
remain as safety nets or lower-risk boundaries; opportunistic narrowing
continues.

### 23. P4 #14 SLOs — FIXED
`deploy/monitoring/picodome-alerts.yaml` PrometheusRule alerts define P95
targets.

### 24. P4 #17 Helm memory limits — FIXED
`deploy/helm/picodome/values.yaml:74-80` `resources` blocks (requests
128Mi / limits 512Mi) on picodome + admission values and deployment
manifest.

### 25. P5 #3 plugin capability jail — FIXED
`picosentry/serve/services/plugin_manager.py` routes every plugin through
`PluginHost` subprocess (line 424-427); only `importlib.util.find_spec`
remains (line 17, for nacl detection — not plugin loading). No in-process
`importlib` plugin load path. Deny-by-default capability model documented
in `docs/PLUGIN_DEVELOPMENT.md`.

### 26. P5 #2 K8s admission real-cluster matrix — FIXED
`.github/workflows/admission-kind.yml` runs `live_test_admission.sh`
against kind cluster across K8s v1.28.13, v1.29.8, v1.30.x. Verifies
privileged/hostPath/hostNetwork/missing-security-context pods denied.

### 27. P5 #11 corpus statistical validation — FIXED
`picosentry/scan/adversarial_mutations.py` + `mutation_benchmark.py` +
`tests/scan/test_mutation_benchmark.py` assert aggregate recall ≥85%,
precision ≥95% under mutation. CLI runner `scripts/mutation_benchmark.py`
+ `docs/BENCHMARKS.md`.

### 28. P5 #20 seccomp red-team — FIXED
`tests/sandbox/test_seccomp_redteam.py` covers network egress, fs escape,
privesc, process injection, kernel-exploit surface, backend
integrity/fail-closed. `_build_filter` fixed so explicit DENY rules
precede SAFE_SYSCALLS allowlist.

### 29. P5 #23 daemon policy signature verify — FIXED
`picosentry/sandbox/daemon/handler_routes_post.py:168` and
`sandbox/cli_commands/{sandbox,pipeline}.py` call `load_policy(...,
verify_signature=True)`. `sandbox/l3/policy.py:288` enforces;
`VersionedPolicyStore` + `PICODOME_POLICY_KEY` auto-signing. Tests for
lookup/verification/tamper/auto-signing.

### 30. P5 #19 cluster-gossip experimental warnings — FIXED
`picosentry/sandbox/cluster/manager.py:57` + `orchestrator.py:107,202`
log `EXPERIMENTAL` warnings on configure/start/distribute-scan.
Regression tests added.

### 31. P5 #21 architecture diagram — FIXED
`docs/ARCHITECTURE.md` with Mermaid component diagram, trust-boundary
table, data flow, subprocess isolation summary, multi-tenancy overview.

### 32. P5 #22 plugin dev guide — FIXED
`docs/PLUGIN_DEVELOPMENT.md` covering PicoShogun lifecycle, manifest,
deny-by-default capabilities, subprocess sandbox, Ed25519 signing,
deployment, testing, security checklist. Listed in `README.md`.

### 33. P5 #25 reproducible-build verification — FIXED
`scripts/verify_release.py` checksums + validates Sigstore bundle +
parses CycloneDX SBOM. `.github/workflows/verify-release.yml` runs after
each release: `gh attestation verify` (SLSA) + `sigstore verify identity`.

---

## Cross-Project Recurring Patterns (overall review 2026-06-28; fold-in 2026-07-02)
One root pattern across all ten KirkForge repos: the interesting problem gets finished, the boring plumbing gets deferred.
1. Release automation last/never — code ships to git, not users; .releaserc configured, no release.yml; versions drift.
2. Security features scaffolded, not completed — architecture built, last 10% deferred (Dopaflow ENCRYPTION_ENABLED stub; Plugin/PicoSentry signing without sandboxing; BIL approval 2/N actions; PetSense config.yaml never loaded; Packy rate-limiter missing one await).
3. CI is decorative — checks exist but non-blocking or wired to local scripts CI doesn't call (cargo audit continue-on-error; ci.sh vs GH Actions; `lint || true`).
4. Integration tests cut first — unit tests green; real e2e path untested / #[ignore] / unverified.
5. Ops docs lag code docs — ADRs/ARCHITECTURE.md strong; deployment guide / runbook / CHANGELOG / troubleshooting missing.
Applies to this repo:
- 1 (release automation): CLOSED — `.github/workflows/release.yml` ships SBOM+Sigstore+SLSA on `v*` tags; v2.0.17 published to PyPI + GitHub Release; `verify-release.yml` post-release check.
- 2 (security scaffolded): CLOSED — plugin signing + subprocess sandbox + capability jail + daemon policy signature verify + seccomp red-team all landed; watch fail-closed flag wired.
- 3 (decorative CI): PARTIAL — ruff/mypy/pytest all green and gating; `postgres-live-test` job runs but is NOT yet a required branch-protection check (admin action pending); admission-kind matrix runs.
- 4 (integration tests cut): CLOSED — Postgres live-test matrix (PG15/16), kind admission matrix (K8s 1.28-1.30), tenant A↔B negative test, seccomp red-team, mutation benchmark all exist.
- 5 (ops docs lag): CLOSED — `docs/THREAT_MODEL.md`, `docs/ops/runbook.md`, `docs/ARCHITECTURE.md`, `docs/PLUGIN_DEVELOPMENT.md`, `docs/BENCHMARKS.md`, `CHANGELOG.md` all present.
