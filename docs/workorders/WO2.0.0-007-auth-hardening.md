# WO2.0.0-007 — Auth Hardening: MFA/TOTP + JWT JTI Revocation + Account Lockout

**Series:** WO2.0.0 (improvement loop)
**Status:** COMPLETE (CHANGELOG 2026-08-12 "Auth hardening (WO2.0.0-007)")
**Owner:** subagent (worktree `wo/2.0.0/auth-hardening`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/serve/ -m "not slow"`

## Objective
Close the three biggest auth gaps from the review (Auth & AuthZ 6/10):
1. **MFA/2FA** — TOTP for admin/privileged accounts
2. **JWT revocation** — JTI blacklist so a leaked token can be invalidated
3. **Account lockout** — lock a username after N failed logins (brute-force protection)

## Root cause being addressed
The review flags: "No MFA, no JWT revocation, no account lockout." These are the top auth gaps vs Socket/Snyk.

## Scope
- `picosentry/serve/services/auth.py` — add TOTP verification, JTI issuance + revocation check, failed-login tracking + lockout
- `picosentry/serve/api/routers/auth.py` — add MFA setup/verify endpoints, lockout handling
- `picosentry/serve/database/_schema.py` — add `totp_secret`, `jti`, `failed_login_attempts`, `locked_until` columns (migration)
- `picosentry/serve/api/deps.py` — check JTI revocation on token decode

## Done-condition
- TOTP enroll + verify works for a user
- A revoked JTI is rejected on subsequent requests
- A username is locked after N failed logins (configurable threshold)
- All gates green

## Notes
- Do NOT rewrite tests to pass. Fix root causes.
- Use `hmac.compare_digest` for any secret comparison.
- Preserve honest-doc annotations (`ponytail:`, `ceiling:`, `upgrade path:`).
