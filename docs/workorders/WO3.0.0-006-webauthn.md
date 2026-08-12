# WO3.0.0-006 — WebAuthn/FIDO2 MFA

**Series:** WO3.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/3.0.0/webauthn`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/serve/ -m "not slow"`

## Objective
Add WebAuthn/FIDO2 (passkey) as a second MFA factor alongside the existing TOTP.

## Root cause being addressed
Auth & AuthZ 8/10: MFA is TOTP-only; no WebAuthn/passkey (phishing-resistant).

## Scope
- `picosentry/serve/services/` — WebAuthn registration + assertion (use a library if present, else a minimal WebAuthn implementation; prefer stdlib/native if feasible)
- `picosentry/serve/database/_schema.py` — migration for WebAuthn credential storage (`webauthn_credentials` table)
- `picosentry/serve/api/routers/auth.py` — WebAuthn register/authenticate endpoints
- Login flow: if a user has WebAuthn enabled, offer it (alongside TOTP)

## Done-condition
- A user can register a WebAuthn/passkey credential
- Login can authenticate via WebAuthn
- TOTP still works as fallback
- All gates green

## Notes
- Do NOT rewrite tests to pass.
- Consider whether to add a dependency or implement minimal WebAuthn; prefer the smallest correct solution.
- Preserve honest-doc annotations.
