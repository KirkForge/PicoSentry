# WO2.0.0 — Workorder Series (docs/workorders)

Improvement loop to push the production review score past 8/10. Each workorder is a scoped task with an owner, a gate, and a done-condition. Work happens in isolated worktrees off `dev`; the orchestrator reviews and merges.

## Workorders

| ID | Title | Status |
|----|-------|--------|
| [WO2.0.0-007](WO2.0.0-007-auth-hardening.md) | Auth Hardening: MFA/TOTP + JWT JTI Revocation + Account Lockout | OPEN |
| [WO2.0.0-008](WO2.0.0-008-audit-fsync.md) | Audit fsync + Crash-Recovery | OPEN |
| [WO2.0.0-009](WO2.0.0-009-reproducible-builds.md) | Reproducible Builds + Hash-Pinned Dependencies | OPEN |
| [WO2.0.0-010](WO2.0.0-010-role-scoped-tokens.md) | Role-Scoped Tokens + CORS Default | OPEN |
| [WO2.0.0-011](WO2.0.0-011-reachability.md) | Reachability Analysis | OPEN |
| [WO2.0.0-012](WO2.0.0-012-package-intel-depth.md) | Package Intelligence: Download Counts + Package Age | OPEN |

## Rules
- Work in isolated worktrees off `dev`. Never touch `main` directly.
- Run the gate before merging. Paste actual output.
- Do NOT rewrite tests to pass. Fix root causes.
- Do NOT commit `picowatch_audit.db`, `*.corpus.json`, `.coverage`, runtime sandbox state.
