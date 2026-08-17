# WO2.0.0-010 — Role-Scoped Tokens + CORS Default

**Series:** WO2.0.0 (improvement loop)
**Status:** COMPLETE (CHANGELOG 2026-08-12 "Role-scoped tokens + CORS default")
**Owner:** subagent (worktree `wo/2.0.0/role-scoped-tokens`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/serve/ -m "not slow"`

## Objective
Close the multi-tenancy + API-design gaps: role-scoped tokens and a safe CORS default.

## Root cause being addressed
The review flags: "No role-scoped tokens (all-or-nothing admin)" and "CORS `origins: "*"` default." API keys currently carry a single permission set; there's no way to mint a token scoped to a specific role/org.

## Scope
- `picosentry/serve/services/auth.py` — support minting API keys scoped to a role (e.g. `read-only`, `viewer`) and/or an org
- `picosentry/serve/api/deps.py` — enforce the token's role scope on requests
- `picosentry/serve/config/settings.py` — verify CORS default is NOT `*` (it currently defaults to `http://localhost:8765`); if `*` is ever set with credentials, reject it
- `picosentry/serve/api/routers/auth.py` — add role-scoped key creation

## Done-condition
- A token can be minted with a restricted role and is enforced
- CORS default is safe (no `*` with credentials)
- All gates green

## Notes
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
