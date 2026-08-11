# WO2.0.0 — Workorder Series

Improvement loop for PicoSentry. Each workorder is a scoped task with an owner, a gate, and a done-condition. Work happens in isolated worktrees off `origin/main`; the orchestrator reviews and merges.

## Workorders

| ID | Title | Status |
|----|-------|--------|
| [WO2.0.0-001](WO2.0.0-001-supply-chain-security.md) | Supply-Chain Security Hardening | OPEN |
| [WO2.0.0-002](WO2.0.0-002-multi-tenancy.md) | Build Out Multi-Tenancy | OPEN |
| [WO2.0.0-003](WO2.0.0-003-error-handling.md) | Improve Error Handling | OPEN |
| [WO2.0.0-004](WO2.0.0-004-package-intelligence.md) | Package Intelligence | OPEN |
| [WO2.0.0-005](WO2.0.0-005-adr-audit-hash-chain.md) | ADR Gap: Audit Hash-Chain | OPEN |
| [WO2.0.0-006](WO2.0.0-006-adr-gaps.md) | ADR Gaps: Multi-Tenancy + Serve + LLM Watch | OPEN |

## Rules
- Work in isolated worktrees off `origin/main`. Never touch `main` directly.
- Run the gate before merging. Paste actual output.
- Do NOT rewrite tests to pass. Fix root causes.
- Do NOT commit `picowatch_audit.db`, `*.corpus.json`, `.coverage`, runtime sandbox state.
