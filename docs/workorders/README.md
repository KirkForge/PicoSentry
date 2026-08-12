# Workorder Series (docs/workorders)

Improvement series to push the production review score up. Work happens in isolated worktrees off `dev`; the orchestrator reviews and merges.

## WO3.0.0 — Third series (in progress)

| ID | Title | Status |
|----|-------|--------|
| [WO3.0.0-001](WO3.0.0-001-jwt-rs256.md) | RS256 JWT + JWK Rotation | OPEN |
| [WO3.0.0-002](WO3.0.0-002-namespace-collision.md) | Namespace/Scope Collision Detection | OPEN |
| [WO3.0.0-003](WO3.0.0-003-version-confusion.md) | Version-Confusion Detection | OPEN |
| [WO3.0.0-004](WO3.0.0-004-osv-realtime.md) | Real-Time OSV Advisory Feed | OPEN |
| [WO3.0.0-005](WO3.0.0-005-backup-encryption.md) | Backup Encryption + Offsite (S3/GCS) | OPEN |
| [WO3.0.0-006](WO3.0.0-006-webauthn.md) | WebAuthn/FIDO2 MFA | OPEN |
| [WO3.0.0-007](WO3.0.0-007-rate-limit-failclosed.md) | Distributed Rate Limiting Fail-Closed | OPEN |
| [WO3.0.0-008](WO3.0.0-008-error-hierarchy.md) | Unified Exception Hierarchy + Bare-Except Cleanup | OPEN |
| [WO3.0.0-009](WO3.0.0-009-slowloris-timeout.md) | Slowloris / Header-Read Timeout | OPEN |
| [WO3.0.0-010](WO3.0.0-010-recall-floor.md) | Tighten Detection Recall Floor | OPEN |

## WO2.0.0 — Second series (COMPLETE)

- [WO2.0.0-007](WO2.0.0-007-auth-hardening.md) — Auth hardening: MFA/TOTP, JWT JTI revocation, account lockout
- [WO2.0.0-008](WO2.0.0-008-audit-fsync.md) — Audit fsync + crash-recovery
- [WO2.0.0-009](WO2.0.0-009-reproducible-builds.md) — Reproducible builds + hash-pinned deps
- [WO2.0.0-010](WO2.0.0-010-role-scoped-tokens.md) — Role-scoped tokens + CORS default
- [WO2.0.0-011](WO2.0.0-011-reachability.md) — Reachability analysis
- [WO2.0.0-012](WO2.0.0-012-package-intel-depth.md) — Package intelligence: download counts + package age

## Rules
- Work in isolated worktrees off `dev`. Never touch `main` directly.
- Run the gate before merging. Paste actual output.
- Do NOT rewrite tests to pass. Fix root causes.
- Do NOT lower thresholds to make gates green.
- Do NOT commit `picowatch_audit.db`, `*.corpus.json`, `.coverage`, runtime sandbox state.
