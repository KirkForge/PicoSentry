# PicoSentry `serve` Security Review

**Scope:** `picosentry serve` API server and dashboard (`picosentry/serve/api/`).
**Date:** 2026-07-06
**Status:** Beta — security review complete, honest limitations below are
Enterprise blockers unless explicitly accepted as risk.

## Reviewed areas

| Area | Verdict | Notes |
|------|---------|-------|
| Authentication | PASS | JWT via PyJWT; bcrypt/PBKDF2 password hashes; legacy `simple:` tokens rejected. |
| Username normalization | PASS | Usernames are `strip()`ed and `casefold()`ed on creation and lookup; prevents case/whitespace account squatting. |
| Credential failure messaging | PASS | Authentication failures log a generic `"Auth failed: invalid credentials"` message; no user-existence leak. |
| API key permissions | PASS | `create_api_key` and `validate_api_key` enforce an allowlist of `read`, `write`, `admin`; inactive users cannot use keys. |
| Authorization / RBAC | PASS | `viewer < operator < admin`; `require_role` dependency used on privileged endpoints. |
| Org isolation | PASS | `list_orgs_for_user` filters by membership; org-scoped endpoints verify membership before returning data. |
| Registration self-elevation | PASS | Registration endpoint hard-codes role to `viewer`; extra fields rejected with `extra="forbid"`. |
| CORS | PASS | `CORSHardeningMiddleware` rejects wildcard in production when `block_wildcard_in_production=True`. |
| HTTPS | PASS | `HTTPSEnforcementMiddleware` redirects to HTTPS in production (health paths exempt). |
| API docs | PASS | `DocsRestrictionMiddleware` returns 404 for `/docs` and `/redoc` in production. |
| Secrets | PASS | `_core.config.assert_secure()` blocks weak/short keys unless `ALLOW_INSECURE_SECRET=true`. |
| Host binding | PASS | Default dev bind is `127.0.0.1`; `0.0.0.0` triggers a warning. |
| Request limits | PASS | Rate limit (100/ip/min), DDoS shield, 10 MB body limit, 30 s timeout. |
| `/scans` workspace | PASS | `SCANS_WORKSPACE_ROOT` must be set; resolved paths checked with `Path.relative_to`. |
| Audit logging | PASS | `AuditMiddleware` logs every request with user, path, status, duration. |
| Dependency injection | PASS | No endpoint accepts a user-supplied user/org object directly. |
| Plugin trust | PASS | Ed25519 signature verify against a configured trusted-key allowlist; mandatory signing supported via `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1`. |
| Postgres backend | PASS | Live PG 15/16 CI; runtime placeholder translation; DDL auto-translation. |

## Honest limitations (Enterprise blockers unless accepted as risk)

- **No formal penetration test.** The regression tests cover the obvious
  auth/isolation/config vectors, but a professional pentest has not been
  performed.
- **Admin endpoints trust role claim from JWT.** This is the intended RBAC
  model; token compromise grants the token's role. No global session revocation
  list exists.
- **Rate limiter is in-memory by default.** A Redis-backed distributed backend
  is available via `PICOSHOGUN_RATE_LIMIT_BACKEND=redis`, but it has not yet
  been load-tested in a broad multi-tenant deployment.
- **Password policy is minimal.** Only an 8-character minimum is enforced;
  stronger complexity rules are left to the operator.
- **Serve is Beta.** Cross-tenant isolation has been hardened and tested,
  but `serve` has not been battle-tested in a broad multi-tenant production
  deployment.

## Regression tests

- `tests/serve/test_security_review.py` — direct assertions for the items above.
- `tests/serve/test_auth.py`, `tests/serve/test_server_hardening.py` —
  authentication and hardening.
- `tests/serve/test_postgres_backend.py` — production database backend.
- `tests/serve/test_plugin_signature_trust.py` — plugin signing trust.
- `tests/serve/test_scans_workspace.py` — path scoping and isolation.

Run the focused suite:

```bash
uv run pytest tests/serve/test_security_review.py tests/serve/test_auth.py \
  tests/serve/test_server_hardening.py tests/serve/test_postgres_backend.py \
  tests/serve/test_plugin_signature_trust.py tests/serve/test_scans_workspace.py -q
```

## Graduation criteria to Stable

- (Recommended) Complete a third-party penetration test or adversarial code
  review of `picosentry/serve/`.
- ✅ Add a shared rate-limit backend option (Redis) and document deployment
  procedures. The in-memory default remains acceptable for single-node installs.
- Add optional global token/session revocation list or short-lived access
  tokens with refresh rotation.
- Optionally enforce stricter password complexity in `AuthService` or document
  the operator responsibility clearly.
