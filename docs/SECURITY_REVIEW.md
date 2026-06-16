# PicoSentry `serve` Security Review

**Scope:** `picosentry serve` API server and dashboard (`picosentry/serve/api/`).
**Date:** 2026-06-16
**Status:** Review complete — issues below are either fixed or documented as honest limitations.

## Reviewed areas

| Area | Verdict | Notes |
|------|---------|-------|
| Authentication | PASS | JWT via PyJWT; bcrypt/PBKDF2 password hashes; legacy `simple:` tokens rejected. |
| Authorization / RBAC | PASS | `viewer < operator < admin`; `require_role` dependency used on privileged endpoints. |
| Org isolation | PASS | `list_orgs_for_user` filters by membership; org-scoped endpoints verify membership before returning data. |
| Registration self-elevation | PASS | `RegisterRequest` has `extra="forbid"`; role is hard-coded to `viewer`. |
| CORS | PASS | `CORSHardeningMiddleware` rejects wildcard in production when `block_wildcard_in_production=True`. |
| HTTPS | PASS | `HTTPSEnforcementMiddleware` redirects to HTTPS in production (health paths exempt). |
| API docs | PASS | `DocsRestrictionMiddleware` returns 404 for `/docs` and `/redoc` in production. |
| Secrets | PASS | `_core.config.assert_secure()` blocks weak/short keys unless `ALLOW_INSECURE_SECRET=true`. |
| Host binding | PASS | Default dev bind is `127.0.0.1`; `0.0.0.0` triggers a warning. |
| Request limits | PASS | Rate limit (100/ip/min), DDoS shield, 10 MB body limit, 30 s timeout. |
| `/scans` workspace | PASS | `SCANS_WORKSPACE_ROOT` must be set; resolved paths checked with `Path.relative_to`. |
| Audit logging | PASS | `AuditMiddleware` logs every request with user, path, status, duration. |
| Dependency injection | PASS | No endpoint accepts a user-supplied user/org object directly. |

## Honest limitations (not blockers)

- **No formal penetration test.** The regression tests cover the obvious auth/isolation/config vectors, but a professional pentest has not been performed.
- **Admin endpoints trust role claim from JWT.** This is the intended RBAC model; token compromise grants the token's role.
- **Rate limiter is in-memory.** Distributed deployments need a shared rate-limit backend for cluster-wide enforcement.
- **Password policy is minimal.** Only an 8-character minimum is enforced; stronger complexity rules are left to the operator.
- **Session tokens live server-side.** Rotation can be done via `/auth/api-key/{id}/rotate` but there is no global session revocation list.

## Regression test file

- `tests/serve/test_security_review.py`

Run it with:

```bash
uv run pytest tests/serve/test_security_review.py -q
```
