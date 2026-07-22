# PicoSentry Attack Surface Document

*Generated 2026-07-22. Scope: `serve`, `daemon`, `admission`, `cluster` components. For pentest preparation — enumerate every input, trust boundary, and prior fix.*

## 1. Serve API Routes

### 1.1 Scans Router (`picosentry/serve/api/routers/scans.py`)

| Endpoint | Method | Auth | Input Source | Output Sink | Trust Boundary | Notes |
|----------|--------|------|-------------|-------------|----------------|-------|
| `/scans` | POST | `operator` | body: `ScanRequest.target` (path string), `ScanRequest.rules` (list) | DB + HTTP response | **CRITICAL**: User-supplied filesystem path scanned server-side. Path traversal gated by `scans_workspace_root` (CRITICAL-1 fix). | CRITICAL-1 fix at `scans.py:42-66`: resolves path, checks `relative_to(workspace_root)`, returns 403 on escape. `PICOSHOGUN_SCANS_WORKSPACE_ROOT` must be set or endpoint returns 503. |
| `/scans/rules` | GET | `viewer` | none | HTTP response | Low: read-only enumeration of rule metadata. | |
| `/sandboxes` | POST | `operator` | body: `SandboxRunRequest.command` (str), `timeout` (int), `env` (dict) | Child process + HTTP response | **HIGH**: Operator-controlled command runs in sandbox. Env scrub at `scans.py:17` (`_SANDBOX_ENV_DENYLIST`, 15 keys). CWD bound to workspace root if configured (HIGH-1 fix). | HIGH-1 fix: env denylist strips `PICOSHOGUN_SECRET_KEY`, `DATABASE_URL`, etc. CWD bound via `PICOSHOGUN_SANDBOX_WORKSPACE_ROOT`. |
| `/sandboxes/policies/default` | GET | `viewer` | none | HTTP response | Low: returns default sandbox policy as dict. | |

### 1.2 Webhooks Router (`picosentry/serve/api/routers/webhooks.py`)

| Endpoint | Method | Auth | Input Source | Output Sink | Trust Boundary | Notes |
|----------|--------|------|-------------|-------------|----------------|-------|
| `/webhooks` | GET | org + `READ_WEBHOOKS` perm | none | HTTP response (webhook URLs, secrets masked?) | **MEDIUM**: Secrets may be in response. | Verify `secret` field is masked. |
| `/webhooks` | POST | org + `WRITE_WEBHOOKS` perm | body: `WebhookCreateRequest` (name, url, events, secret) | DB + outbound HTTP (dispatch) | **HIGH**: URL triggers SSRF. DNS-rebinding fix at `webhooks.py:37-60`. | HIGH-2 fix: `_is_safe_webhook_url()` blocks private/link-local IPs and non-HTTP schemes. `create()` pins resolved IPs. `dispatch()` re-resolves and rejects rebinding. |

### 1.3 Auth Router (`picosentry/serve/api/routers/auth.py`)

| Endpoint | Method | Auth | Input Source | Output Sink | Trust Boundary | Notes |
|----------|--------|------|-------------|-------------|----------------|-------|
| `/auth/register` | POST | none (open if enabled) | body: `RegisterRequest` (username, password, email) | DB | **HIGH**: Self-registration creates `viewer` role only; `RegisterRequest` uses `extra="forbid"` to reject client-supplied `role`. | 403 if `settings.security.allow_registration` is false. |
| `/auth/login` | POST | none | body: username + password | JWT token in response | **MEDIUM**: Brute-force target. Rate-limited by DDoS shield (`/api/v1/auth/login` in `HIGH_RISK_PATHS`). | |
| `/auth/api-key` | POST | `get_current_user` | body: name + permissions | API key in response | **MEDIUM**: Key material in response. | |
| `/auth/api-key/{key_id}/rotate` | POST | `get_current_user` | path: key_id | New API key in response | **MEDIUM**: Key rotation. | |
| `/auth/api-key/{key_id}` | DELETE | `get_current_user` | path: key_id | DB | Low. | |

### 1.4 Admin Router (`picosentry/serve/api/routers/admin.py`)

| Endpoint | Method | Auth | Input Source | Output Sink | Trust Boundary | Notes |
|----------|--------|------|-------------|-------------|----------------|-------|
| `/backup` | POST | `admin` | none | Backup tarball on disk (`serve/backups/`) | **MEDIUM**: Triggers disk write of DB + logs. Backup directory is gitignored but file existence may leak. | |
| `/backups` | GET | `admin` | none | List of backup filenames | Low. | |
| `/logs/stats` | GET | `admin` | none | Log statistics | Low. | |
| `/logs/rotate` | POST | `admin` | none | Log rotation on disk | Low. | |
| `/logs` | GET | `admin` | query: level, source, search, limit (1-1000) | Log entries | **MEDIUM**: `search` param passes to log query — verify no injection (ReDoS fix: MEDIUM-2 fix used `re.escape`). | LOW-1 fix at `log_manager.py:130`. |
| `/audit/stats` | GET | `admin` | none | Audit stats | Low. | |
| `/audit/purge` | POST | `admin` | body: retention_days, dry_run | DB purge | **MEDIUM**: Data destruction endpoint, admin-only. | |
| `/events/history` | GET | `admin` | query: event_type, limit (1-1000) | Event history | Low. | |

### 1.5 Projects Router (`picosentry/serve/api/routers/projects.py`)

| Endpoint | Method | Auth | Input Source | Output Sink | Trust Boundary | Notes |
|----------|--------|------|-------------|-------------|----------------|-------|
| `/projects` | GET | org + `READ_PROJECTS` | query: category, status | HTTP response | Low: org-scoped. | |
| `/projects/{project_id}` | GET | org + `READ_PROJECTS` | path: project_id | HTTP response | Low. | |
| `/projects/{project_id}/run` | POST | org + `RUN_PROJECTS` | path: project_id, body: ProjectRunRequest | Orchestrator + DB | **MEDIUM**: Triggers project run (orchestrator subprocess). | |
| `/batch/run` | POST | org + `RUN_PROJECTS` | body: BatchRunRequest (project_ids, timeout) | Orchestrator + DB | **MEDIUM**: Batch project execution. | |
| `/projects/{project_id}/export` | GET | org + `READ_PROJECTS` | path: project_id, query: format (json/csv) | HTTP response | Low. | |
| `/intelligence` | GET | org + `READ_INTELLIGENCE` | query: source_project, intel_type, severity, limit | DB response | Low: org-scoped. | |
| `/intelligence/correlations/{project_id}` | GET | org + `READ_INTELLIGENCE` | path: project_id | DB response | Low. | |
| `/intelligence/threat-score` | GET | org + `READ_INTELLIGENCE` | none | Aggregated DB response | Low. | |
| `/alerts` | GET | org + `READ_ALERTS` | query: severity, project_id, limit | DB response | Low. | |
| `/alerts/{alert_id}/acknowledge` | POST | org + `WRITE_ALERTS` | path: alert_id | DB update | Low. | |
| `/reports/summary` | GET | org + `READ_DASHBOARD` | none | Aggregated response | Low. | |
| `/reports/project/{project_id}` | GET | org + `READ_PROJECTS` | path: project_id | Report response | Low. | |

### 1.6 Correlation Router (`picosentry/serve/api/routers/correlation.py`)

| Endpoint | Method | Auth | Input Source | Output Sink | Trust Boundary | Notes |
|----------|--------|------|-------------|-------------|----------------|-------|
| `/chains` | GET | `viewer` | query: threshold, limit | Correlation engine response | Low. | |
| `/chains/{artifact_id}` | GET | `viewer` | path: artifact_id | Correlation chain | Low. | |
| `/chains/{artifact_id}/narrative` | GET | `viewer` | path: artifact_id | Narrative text | Low. | |
| `/events` | POST | `operator` | query: artifact_id, layer, rule_id, severity, confidence, target, title, detail | Correlation engine ingestion | **MEDIUM**: Operator can inject arbitrary correlation events. Validate `layer` and `rule_id` are from known sets. | |
| `/chains/summary` | GET | `viewer` | none | Summary stats | Low. | |
| `/chains/persist` | POST | `operator` | none | DB write | Low. | |
| `/engine/stats` | GET | `viewer` | none | Engine stats | Low. | |

### 1.7 Scheduler Router (`picosentry/serve/api/routers/scheduler.py`)

| Endpoint | Method | Auth | Input Source | Output Sink | Trust Boundary | Notes |
|----------|--------|------|-------------|-------------|----------------|-------|
| `/scheduler/jobs` | GET | org + `READ_SCHEDULER` | none | Job list (org-scoped) | Low. | |
| `/scheduler/jobs` | POST | org + `WRITE_SCHEDULER` | body: SchedulerJobCreateRequest (name, cron, command, params) | DB | **HIGH**: `command` field is passed to scheduler. Verify command injection is not possible. | |
| `/scheduler/jobs/{job_id}/enable` | PATCH | org + `WRITE_SCHEDULER` | path: job_id | DB update | Low. | |
| `/scheduler/jobs/{job_id}/disable` | PATCH | org + `WRITE_SCHEDULER` | path: job_id | DB update | Low. | |
| `/scheduler/jobs/{job_id}` | DELETE | org + `WRITE_SCHEDULER` | path: job_id | DB delete | Low. | |

### 1.8 Other Routers

| Router | Endpoints | Auth | Key Risks |
|--------|-----------|------|-----------|
| **Health** (`health.py`) | `GET /`, `/health`, `/health/live`, `/health/ready`, `/health/history`, `/status` | Mix: some unauthenticated, some require `get_current_user` | `/health/*` paths bypass DDoS shield. `/health/history` queries DB. `/dashboard` serves static HTML. |
| **Dashboard** (`dashboard.py`) | `GET /dashboard/summary` | org + `READ_DASHBOARD` | Aggregates org-scoped data from DB. |
| **Metrics** (`metrics.py`) | `GET /metrics`, `/metrics/prometheus`, `/metrics/json` | org + `READ_METRICS` | Exposes operational metrics. |
| **Anomaly** (`anomaly.py`) | `GET /rules`, `/alerts`, `POST /check`, `PATCH /rules/{rule_id}` | `READ_ANOMALY` / `WRITE_ANOMALY` | `PATCH /rules/{rule_id}` allows threshold changes — verify no privilege escalation. |
| **Orgs** (`orgs.py`) | `GET /orgs`, `/orgs/{id}`, `/orgs/{id}/members`, `/orgs/{id}/usage`, `POST /orgs`, `POST /orgs/{id}/upgrade` | Mix: `get_current_user` / `admin` | `POST /orgs` creates orgs. `upgrade` requires admin. |
| **Plugins** (`plugins.py`) | `GET /plugins` | `get_current_user` | Read-only plugin status enumeration. |
| **WebSocket** (`ws.py`) | `WS /ws` | Token in query or in-band auth | Auth tightened (P0 fix): unauthenticated clients get empty channel set. In-band auth failure closes connection (code 4001). |

## 2. Daemon / Admission / Cluster

### 2.1 Daemon (`picosentry/sandbox/daemon/`)

- HTTP + gRPC API on configurable host/port
- Auth: `PICODOME_API_TOKENS` environment variable
- Trust boundary: daemon runs sandboxed children; the API accepts commands to execute
- Key risk: command injection via sandbox submissions

### 2.2 Admission (`picosentry/sandbox/admission/`)

- Kubernetes admission webhook (TLS required in production)
- Fail-closed by default (`PICODOME_ADMISSION_FAIL_CLOSED=true`)
- Trust boundary: only the K8s API server should call this
- Key risk: misconfigured webhook denies all pods

### 2.3 Cluster (`picosentry/sandbox/cluster/`)

- Gossip protocol with shared `PICODOME_CLUSTER_TOKEN`
- Trust boundary: peers share a single secret token; mTLS is optional
- Key risk: token compromise allows cluster join; no cert pinning or rotation

## 3. Middleware

| Middleware | File | Purpose | Key Properties |
|-----------|------|---------|----------------|
| **Audit** | `audit.py` | Request audit logging | Records method, path, status, user, org |
| **CORS Hardening** | `cors_hardening.py` | CORS policy enforcement | Restricts origins; warns in enterprise mode if wildcard |
| **DDoS Shield** | `ddos_shield.py` | Rate limiting | `HIGH_RISK_PATHS`: `/api/v1/scans`, `/api/v1/auth/login`, `/projects`. LRU cap at 1000 paths. Health paths exempt. |
| **Docs Restriction** | `docs_restriction.py` | Hides `/docs` in production | Prevents OpenAPI spec leak |
| **HTTPS Enforcement** | `https_enforcement.py` | Redirects HTTP→HTTPS | Production-only |
| **Rate Limit** | `rate_limit.py` | Per-IP rate limiting | In-memory token bucket |
| **Rate Limit Redis** | `rate_limit_redis.py` | Redis-backed rate limiting | For multi-instance deployments |
| **Request ID** | `request_id.py` | Correlation ID tracking | Adds `X-Request-ID` header |
| **Request Size Limit** | `request_size_limit.py` | 10 MB body size cap | Buffers chunked encoding (MEDIUM-1 fix) |
| **Security Headers** | `security_headers.py` | HSTS, X-Content-Type-Options, etc. | Standard hardening headers |

## 4. Prior Security Fixes Cross-Reference

| Finding | Severity | Fix Location | Test Coverage | Status |
|---------|----------|-------------|---------------|--------|
| CRITICAL-1: Operator→Admin via `/sandboxes` arbitrary file write | CRITICAL | `scans.py:42-66` — workspace-root gate; 503 if `PICOSHOGUN_SCANS_WORKSPACE_ROOT` unset, 403 if path escapes root | `tests/serve/test_security_gates.py` | Fixed, re-verify |
| HIGH-1: Sandbox child inherits full server env | HIGH | `scans.py:17` `_SANDBOX_ENV_DENYLIST` (15 keys); `scans.py:114-126` strips env + binds CWD | `tests/serve/test_security_gates.py` | Fixed, re-verify |
| HIGH-2: Webhook DNS-rebinding SSRF | HIGH | `webhooks.py:37-60` `_is_safe_webhook_url()`; `:95` `pinned_ips`; `:132` create pins; `:187-189` dispatch re-checks | `tests/serve/test_security_gates.py` | Fixed, re-verify |
| MEDIUM-1: Chunked transfer bypasses request size limit | MEDIUM | `request_size_limit.py:28-29` buffers `await request.body()` before size check | `tests/serve/test_security_gates.py` | Fixed, re-verify |
| MEDIUM-2: DDoS shield `HIGH_RISK_PATHS` matched zero real routes | MEDIUM | `ddos_shield.py:14` now has `{"/api/v1/scans", "/api/v1/auth/login", "/projects"}` | `tests/serve/test_security_gates.py` | Fixed, re-verify |
| LOW-1: `log_manager` ReDoS via unsanitized `safe_level` | LOW | `log_manager.py:130` uses `re.escape(safe_level)` | `tests/serve/test_security_gates.py` | Fixed, re-verify |

## 5. Self-Red-Team Pass

### 5.1 Path Traversal via `scans_workspace_root`

**What happens if I send `POST /scans` with `target: "../../etc/passwd"`?**
- CRITICAL-1 fix resolves the path and checks `relative_to(workspace_root)`. `../../etc/passwd` resolves outside root → 403.
- **What if `PICOSHOGUN_SCANS_WORKSPACE_ROOT` is unset?** → 503 (endpoint disabled). Cannot bypass.
- **What if `PICOSHOGUN_SCANS_WORKSPACE_ROOT=/`?** → Path traversal succeeds; any file on system is scannable. Operator must not set root to `/`.
- **Re-verify:** Test with `workspace_root=/` and `target=../../etc/passwd` — should this be explicitly rejected?

### 5.2 SSRF via Webhook URL

**What happens if I create a webhook with `url: http://169.254.169.254/latest/meta-data/`?**
- `_is_safe_webhook_url()` blocks link-local (169.254.0.0/16). Returns 400.
- **What about `http://0x7f000001/` (hex-encoded 127.0.0.1)?** → `socket.getaddrinfo` resolves to 127.0.0.1 → blocked by loopback rule.
- **What about `http://127.1/`?** → Resolves to 127.0.0.1 → blocked.
- **What about DNS rebinding: register `evil.com` → 1.2.3.4 (passes SSRF check), then rebind to 127.0.0.1 before dispatch?** → HIGH-2 fix pins IPs at create time and re-checks at dispatch time. If current IPs are not a subset of pinned IPs → 400.
- **What about `http://[::1]/`?** → IPv6 loopback blocked by `::1/128` network.
- **What about TOCTOU between create and first dispatch?** → IPs pinned at create; first dispatch uses pinned IPs.

### 5.3 Environment Variable Leak via Sandbox

**What happens if I `POST /sandboxes` with a command that prints env vars?**
- HIGH-1 fix: `_SANDBOX_ENV_DENYLIST` strips 15 sensitive keys before passing env to child.
- **What about keys not on the denylist?** → Any env var not in the 15-key denylist is visible. If `AWS_SESSION_TOKEN`, `GOOGLE_CREDENTIALS`, etc. are in env, they leak.
- **Re-verify:** Denylist should be audited for completeness. Consider deny-by-default (allowlist) rather than denylist.

### 5.4 Chunked Transfer Size Limit Bypass

**What happens if I send a 50 MB chunked POST body?**
- MEDIUM-1 fix: `RequestSizeLimitMiddleware` buffers the entire body via `await request.body()` then checks length. If > 10 MB → 413.
- **What about slowloris-style attacks?** → No timeout on `request.body()` — a client could send 1 byte/second indefinitely. `RequestTimeoutMiddleware` may help but needs verification.

### 5.5 DDoS Shield Bypasses

**What happens if I send 1000 requests/second to `/api/v1/scans`?**
- DDoS shield limits to 50 per 10-second window (per path) → 429 after burst.
- **What about requests to unlisted paths?** → Only `HIGH_RISK_PATHS` get per-path limits. Global limit is 200 per 10 seconds.
- **What about path obfuscation (`/api/v1/scans/`, `/API/V1/SCANS`)?** → FastAPI is case-sensitive; `/API/V1/SCANS` would not match the route OR the shield pattern. Verify both.

### 5.6 Scheduler Command Injection

**What happens if I `POST /scheduler/jobs` with `command: "rm -rf /"`?**
- The `command` field is stored and later executed by the scheduler. Verify that the scheduler sanitizes or sandbox-commands.
- **Re-verify:** Read `picosentry/serve/services/scheduler.py` to confirm command handling.

### 5.7 WebSocket Auth Bypass

**What happens if I connect to `/ws` without a token?**
- P0 fix: empty channel set. Client can send/receive but gets no broadcasts. `subscribe` is rejected.
- **What if I send `{"action": "subscribe", "channels": ["*"]}` without auth?** → Server responds with `{"type": "error", "message": "Authentication required before subscribe"}`.
- **What about token in query string?** → May appear in server logs and proxy access logs. Consider auth header instead.

### 5.8 Plugin Trust Boundary

**Can an unsigned plugin load?** → Yes, in non-production mode. In production (`PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1`), unsigned plugins fail the `_SignedPluginsCheck` and `assert_secure()` exits with code 7.
- **Can a signed plugin expand capabilities?** → No. Signing proves authenticity, not safety. Capability allowlist is deny-by-default. See ADR-004.

## 6. Trust Boundary Summary

```
Internet / Untrusted Network
         │
    ┌────▼────┐
    │ Reverse │  (HTTPS enforcement, rate limiting)
    │ Proxy   │
    └────┬────┘
         │
    ┌────▼────────────────────────────────────────────┐
    │ FastAPI Application (serve)                     │
    │                                                  │
    │  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │
    │  │ Auth     │  │ DDoS     │  │ Size Limit   │ │
    │  │ (Bearer) │  │ Shield   │  │ (10MB)       │ │
    │  └──────────┘  └──────────┘  └──────────────┘ │
    │                                                  │
    │  ┌──────────────────────────────────────────┐   │
    │  │  Route Handlers (see §1)                  │   │
    │  │  RBAC: viewer / operator / admin          │   │
    │  │  Org scoping: org_id on all DB queries    │   │
    │  └──────────────────────────────────────────┘   │
    │                                                  │
    │  ┌────────────┐  ┌─────────────┐               │
    │  │ Scan Engine │  │ Sandbox L3 │               │
    │  │ (read-only) │  │ (seccomp)  │               │
    │  └────────────┘  └─────────────┘               │
    └──────────────────────────────────────────────────┘
         │                    │
    ┌────▼────┐         ┌─────▼─────┐
    │ SQLite / │         │ Child proc │
    │ Postgres │         │ (sandboxed)│
    └─────────┘         └───────────┘
```