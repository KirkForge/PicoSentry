# WO3.0.0-001 — RS256 JWT + JWK Rotation

**Series:** WO3.0.0 (improvement loop)
**Status:** COMPLETE (verified in code 2026-08 — see workorders/README.md)
**Owner:** subagent (worktree `wo/3.0.0/jwt-rs256`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/serve/ -m "not slow"`

## Objective
Upgrade JWT signing from symmetric HS256 to asymmetric RS256, with a JWKS endpoint and key-rotation support.

## Root cause being addressed
Crypto 6/10: `jwt_algorithm: str = "HS256"` (`picosentry/serve/config/settings.py:79`) — symmetric signing means a leaked secret forges any token, and there's no key rotation or JWK discovery.

## Scope
- `picosentry/serve/config/settings.py` — support RS256 with a private key (PEM path or env), keep HS256 as fallback for backward compat
- `picosentry/serve/services/auth.py` — sign with RS256 using an RSA keypair; add a JWKS endpoint serving the public key
- `picosentry/serve/api/routers/auth.py` — add `GET /auth/.well-known/jwks.json`
- `picosentry/serve/api/deps.py` — decode verifying against RS256 public key (with HS256 fallback for existing tokens)
- Key rotation: support multiple active keys (kid claim), rotation endpoint/config

## Done-condition
- Tokens are signed with RS256 (HS256 fallback decodes legacy tokens)
- `GET /auth/.well-known/jwks.json` serves the public key
- Key rotation works (new kid issued, old key retired)
- All gates green

## Notes
- Do NOT rewrite tests to pass. Fix root causes.
- Preserve honest-doc annotations.
