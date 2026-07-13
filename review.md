# PicoSentry Code Review

## Project Summary

**PicoSentry** (v2.0.18) is a unified supply-chain security suite with four major components: a deterministic supply-chain **Scanner** (7 ecosystems, 53 rules), a kernel-level **Sandbox** (seccomp-bpf/seatbelt/subprocess), an LLM **Watch** (prompt injection + output guard), and a **Serve** orchestration API (FastAPI + RBAC + plugins). The codebase is large (~363 source files, ~188 test files) and demonstrates a high degree of engineering discipline.

---

## P0 Issues (Bugs, Security, Correctness)

### 1. Default `secret_key` ships as `"change-me-in-production"` -- will pass `assert_secure()` in development mode but is a trap for production

**File:** `picosentry/serve/config/settings.py:70`

```python
secret_key: str = field(default_factory=lambda: _env("SECRET_KEY", "change-me-in-production"))
```

The `_core/config.py` `assert_secure()` function checks against a denylist that includes `"change-me-in-production"`, but the serve `Settings.validate()` only **logs** a warning in non-production mode (line 266-267). The `assert_secure()` call happens at startup, but only blocks if `PICOSHOGUN_ENV=production`. An operator who deploys without setting `PICOSHOGUN_ENV=production` will silently run with the default weak key. This is a known pattern but is still the single most likely misconfiguration path. The security gate is correct; the gap is that the `ENV` variable must also be set correctly.

**Severity:** P0 -- operator misconfiguration leads to trivially forgeable JWTs.

### 2. `subprocess.run()` in orchestrator executes project commands without sanitization

**File:** `picosentry/serve/services/orchestrator.py:278`

```python
result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=timeout,
    check=False,
)
```

The `cmd` variable comes from `PICO_CLI.get(project_id, [meta.package or project_id])`. While the `project_id` is checked against the registry, the `meta.package` field comes from the database (originally user-supplied). If an admin creates a project with a malicious `package` name, this executes arbitrary commands. The `run_project` method is protected by `require_permission(RUN_PROJECTS)`, so this is an admin-only attack surface, but it is worth noting that the orchestrator trusts the project registry entirely.

**Severity:** P0 -- command injection via malicious `project_id` or `package` field in project registry. Needs allowlist validation.

### 3. Rate limiter `rate_limit_response` may be used before assignment

**File:** `picosentry/serve/middleware/rate_limit.py:250-251`

```python
if rate_limited:
    return rate_limit_response
```

If the `_record_and_check` for org returns `rate_limited=False`, the `rate_limit_response` variable is never assigned. Then if the IP check also returns `rate_limited=False`, this is fine. But if the org check succeeds and the IP check also hits `rate_limited=True`, `rate_limit_response` is correctly set. However, if the org check raises an exception or the variable scoping is wrong, `rate_limit_response` could be uninitialized. In practice the current flow is safe because the variable is set in both rate-limit branches, but this is fragile -- a refactor could introduce an `UnboundLocalError` crash. The variable should be initialized at the top of the function.

**Severity:** P0-adjacent (latent bug); currently safe but brittle.

### 4. `Finding` is frozen but `ScanResult` uses `object.__setattr__` to mutate file paths

**File:** `picosentry/scan/engine.py:385`

```python
object.__setattr__(f, "file", f.file[len(target_prefix) :])
```

This bypasses the frozen dataclass `Finding` to strip the target prefix from file paths. While intentional and correct for the use case, it undermines the immutability guarantee of the frozen dataclass. Any concurrent reader of the finding's `file` attribute during this mutation could see a partially-updated string. Since the scan is single-threaded at the finding-mutation stage (mutations happen after the ThreadPoolExecutor exits), this is safe in practice, but it is a code smell that violates the contract.

**Severity:** P0-adjacent (correctness smell, currently safe due to serialization).

### 5. `auth.py` (serve) stores `secret_key` as a string field that could be empty

**File:** `picosentry/serve/services/auth.py:31`

```python
self.secret_key = settings.security.secret_key
```

If `PICOSHOGUN_SECRET_KEY` is not set and the env override is empty, `secret_key` defaults to `"change-me-in-production"`. JWT tokens signed with this key are trivially forgeable. The `assert_secure()` gate catches this, but only when `PICOSHOGUN_ENV=production`. In development mode, this is accepted silently.

**Severity:** P0 -- same root cause as P0-1.

---

## P1 Issues (Performance, Maintainability, Code Quality)

### 1. `PicoWatchConfig` has 30+ properties that are pure delegation boilerplate

**File:** `picosentry/watch/config.py:105-296`

The `PicoWatchConfig` dataclass has ~190 lines of `@property` / `@property.setter` pairs that simply delegate to `self.prompt_guard`, `self.output_guard`, `self.telemetry`, or `self.server`. This is a massive amount of boilerplate. A cleaner approach would be to use `__getattr__` delegation or a simpler composition pattern. The current code is correct but adds significant maintenance burden.

### 2. `merge_cli()` is a manual field-by-field copy

**File:** `picosentry/scan/config.py:170-239`

The `PicoSentryConfig.merge_cli()` method manually copies every field and then applies argparse overrides. This is error-prone when new fields are added -- a developer could forget to add the new field. Using `dataclasses.replace()` or a reflection-based approach would be more maintainable.

### 3. `_compute_corpus_version()` hashes ALL corpus JSON files on every engine instantiation

**File:** `picosentry/scan/engine.py:132-148`

The corpus version is computed by SHA-256 hashing every `*.json` file in the corpus directory. For a large corpus, this could be slow at startup. The result is not cached to disk, so every `create_default_engine()` call recomputes it.

### 4. `scan_engine.scan()` creates a `ThreadPoolExecutor` per scan call

**File:** `picosentry/scan/engine.py:315-374`

A new `ThreadPoolExecutor` is created for every `scan()` invocation. While the executor is properly used as a context manager, creating and tearing down thread pools on every scan adds overhead. The engine could maintain a long-lived pool.

### 5. DDoS shield does not use `time.monotonic()` consistently

**File:** `picosentry/serve/middleware/ddos_shield.py:63`

The DDoS shield uses `self._now()` which defaults to `time.monotonic()`, which is good. But the `_path_buckets` and `_global_bucket` are plain Python lists that are never evicted for stale entries (only truncated at query time). Over time, with many unique paths, the path buckets dict can grow unbounded.

### 6. `_check_value` in guards.py flags UUIDs and timestamps ANYWHERE in result dicts

**File:** `picosentry/_core/guards.py:197-210`

The `DeterministicGuard._check_value()` recursively walks all values in a result dict and flags any substring that matches a UUID or ISO timestamp pattern. This is overly broad -- legitimate data (e.g., a package named after a UUID, or evidence containing a date string) would trigger false positives. The guard is used for internal determinism validation, so false positives are tolerable, but they add noise to test output.

### 7. Duplicate `ScanStats` class definitions

**Files:** `picosentry/_core/models.py:39` and `picosentry/scan/models.py:29`

Both `_core/models.py` and `scan/models.py` define a `ScanStats` dataclass. The `scan/models.py` version adds `rule_timings_ms` which the core version lacks. The core version is imported in `_core/__init__.py` but the scan version is used in practice. This creates confusion about which is canonical.

### 8. `RateLimiter` in `scan/auth.py` uses `OrderedDict` for bucket eviction

**File:** `picosentry/scan/auth.py:419-473`

The token-bucket rate limiter uses `OrderedDict` with `move_to_end` for LRU eviction. While correct, it is a custom implementation when Python's `cachetools.TTLCache` or similar would be more standard and better tested. The rate limiter is also not thread-safe for the eviction path -- `_evict_stale` modifies the dict while the lock is held, which is correct, but the stale eviction check happens inside the `check()` method, not periodically.

### 9. `_sqlite_to_postgres` is a fragile SQL translation approach

**File:** `picosentry/serve/database/manager.py:65-75`

The `_sqlite_to_postgres()` function uses string replacement to translate SQLite DDL to PostgreSQL. This is inherently fragile -- any SQL containing the literal text `INTEGER PRIMARY KEY AUTOINCREMENT` in a comment or string would be translated. The comment acknowledges this risk, and the approach is bounded by the fact that migration SQL is under project control, but it remains a maintenance hazard.

### 10. `workspace.py` uses `multiprocessing.Process` with `_terminate()` + `join(1)` for timeout

**File:** `picosentry/scan/workspace.py:218-231`

The workspace scanner spawns a new process per project for timeout enforcement, then calls `_p.terminate()` + `_p.join(timeout=1)`. This can leave orphaned processes if `join(1)` times out. A `kill()` after a second timeout would be more reliable.

---

## P2 Issues (Style, Minor Improvements)

### 1. Inconsistent logging module naming

The codebase uses `picoshogun.*` for serve-side loggers and `picosentry.*` / `picodome.*` / `picowatch.*` for their respective components. This is intentional (the serve component was originally "PicoShogun") but creates confusion in log aggregation. Consider renaming to a unified `picosentry.*` namespace.

### 2. No type stubs for the `picosentry.serve.front` HTML/JS assets

The front-end assets are mounted as static files. While this is fine for the product, it means there is no type checking for the front-end integration points.

### 3. `create_default_engine()` registers `detect_obfuscation` under 4 different rule IDs

**File:** `picosentry/scan/engine.py:551-553`

```python
engine.register("L2-OBFS-001", detect_obfuscation)
engine.register("L2-OBFS-002", detect_obfuscation)  # sub-rule: hex obfuscation
engine.register("L2-OBFS-003", detect_obfuscation)  # sub-rule: base64+eval
engine.register("L2-OBFS-004", detect_obfuscation)  # sub-rule: unicode escapes
```

The same function is registered 4 times. While `fn_to_rule_ids` deduplicates by function identity, this means the rule executes once but produces findings tagged with all 4 rule IDs. This is a design choice, not a bug, but it means rule execution count and findings count may not match expectations.

### 4. `check_config_permissions()` in watch config reads all config files on every import

**File:** `picosentry/watch/config.py:557-596`

The `check_config_permissions()` function is called during `from_env()` and reads every config file to check permissions and look for `api_key` entries. This is a good security practice but adds I/O to the startup path.

---

## Overall Design Quality

### Strengths

1. **Security-first architecture.** The `assert_secure()` gate at component startup, weak-secret denylist, constant-time comparisons (`hmac.compare_digest`), SSRF protection (`_network.py`), file permission checks, and fail-closed modes demonstrate strong security engineering.

2. **Deterministic scan guarantees.** The `DeterministicGuard`, `deterministic_hash()`, and `diff_results()` provide a formal framework for ensuring scan reproducibility. The `FORBIDDEN_IN_FINDINGS` check prevents non-deterministic patterns from leaking into results. This is a differentiator for a security scanner.

3. **Clean component separation.** The `_core/` module provides shared primitives (config, models, guards) while `scan/`, `sandbox/`, `watch/`, and `serve/` are cleanly isolated. The dependency graph flows one way (core <- components), and there are no circular imports.

4. **Defense in depth for sandbox.** The `BackendRegistry` pattern with automatic backend detection (seccomp-bpf > seatbelt > subprocess), explicit `allow_degraded` opt-in, and the `BackendUnavailableError` exception hierarchy are well-designed. The subprocess backend is clearly labeled as "observational only."

5. **Multi-tenancy is properly enforced.** The `org_id` scoping in the database, RBAC permission checks via FastAPI dependencies, and the `require_permission()` / `require_role()` pattern are correctly layered.

6. **Watch component is well-layered.** The `Normalizer -> RuleEngine -> Scorer -> PromptClassifier` pipeline is clean, and the classifier is explicitly designed to only elevate (never lower) the regex score, preventing regressions.

7. **Migration system is idempotent.** The `DatabaseManager._init_migrations()` handles `duplicate column` / `already exists` errors gracefully, and migration SQL is backend-aware.

8. **Network safety.** The `safe_urlopen()` function enforces HTTPS, blocks cloud metadata SSRF, and enforces response size limits. This is textbook secure HTTP client design.

### Areas for Improvement

1. **The `PicoWatchConfig` delegation pattern is excessive.** The 190 lines of property delegation should be replaced with a simpler composition mechanism.

2. **The serve component mixes "PicoShogun" naming with "PicoSentry".** The environment variables, loggers, and some code paths still use the legacy "shogun" prefix. A rename pass would reduce confusion.

3. **The workspace scanner's process-per-project model is heavyweight.** For large monorepos, spawning a new Python process per package is expensive. A thread-pool model with per-thread engine instances would be more efficient.

4. **Test coverage is broad but uneven.** The 188 test files cover many scenarios, but some critical paths (e.g., the orchestrator's `subprocess.run` execution, the WebSocket manager, and the correlation engine's persistence path) could benefit from more unit-level coverage. The integration tests are valuable but slower.

---

## Summary

| Category | Count | Key Themes |
|----------|-------|------------|
| P0 (Critical) | 5 | Default secret key trap, command injection in orchestrator, fragile rate limiter variable scoping, frozen-dataclass mutation |
| P1 (Important) | 10 | Config boilerplate, duplicated classes, performance of corpus hashing, process management, SQL translation fragility |
| P2 (Minor) | 4 | Logger naming, rule registration pattern, front-end type safety |

The codebase is well-engineered overall. The security gates are thorough, the determinism framework is unique and valuable, and the multi-component architecture is clean. The P0 issues are primarily around deployment configuration safety (the default secret key) and the orchestrator's trust of user-supplied project data. The P1 issues are maintainability and performance concerns that would benefit from attention before a 1.0 release.
