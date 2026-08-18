# Workorder Series (docs/workorders)

**Single source of work-order truth.** Every durable unit of work is a WO file here. `workplan.md` (gitignored) is per-session scratch, never truth. Root `WO/` was consolidated here 2026-08-17 and deleted.

Improvement series to push the production review score up. Work happens in isolated worktrees off `dev`; the orchestrator reviews and merges.

## WO5.0.0 — Fifth series (OPEN — seeded by the 2026-08-18 five-explorer round)

Priorities: P0 = security/correctness, do first. Each WO names its verified evidence (live repros or airtight file:line chains from the explorer round; top claims re-verified by the orchestrator). Worktrees: `wo/5.0.0/<slug>` off `origin/dev`.

| ID | Title | Pri | Effort |
|----|-------|-----|--------|
| [WO5.0.0-001](WO5.0.0-001-sandbox-tenant-production.md) | Sandbox: tenant isolation dead in production (loader unwired, X-Tenant override, audit scope, NULL tenant) | P0 | M |
| [WO5.0.0-002](WO5.0.0-002-sandbox-input-hardening.md) | Sandbox: untrusted-input hardening (NaN timeout, retention traversal, names, header charset) | P0 | M |
| [WO5.0.0-003](WO5.0.0-003-policy-signature-fail-closed.md) | Sandbox: policy signature verification fails open without a key | P0 | S |
| [WO5.0.0-004](WO5.0.0-004-cluster-auth-reconciliation.md) | Sandbox: cluster gossip 401-dead on auth-configured daemons | P0 | S-M |
| [WO5.0.0-005](WO5.0.0-005-serve-killchain-tenancy.md) | Serve: kill-chain escalation reads org from the payload (cross-tenant leak) | P0 | S |
| [WO5.0.0-006](WO5.0.0-006-serve-audit-retention-auto.md) | Serve: scheduler cleanup bypasses severity-aware audit retention | P0 | S |
| [WO5.0.0-007](WO5.0.0-007-serve-metrics-exposition.md) | Serve: /metrics exposition invalid (duplicate samples + label injection) | P0 | M |
| [WO5.0.0-008](WO5.0.0-008-serve-alerting-truthfulness.md) | Serve: alerting truthfulness (sent=1 on failed delivery, webhook name clobber, auto-analysis no-op) | P0 | M |
| [WO5.0.0-009](WO5.0.0-009-scan-advisory-correctness.md) | Scan: advisory pipeline correctness (default no-op, maven keying, multi-package records) | P0 | M |
| [WO5.0.0-010](WO5.0.0-010-scan-cache-parity.md) | Scan: cache input-hash parity with rule read-surface + `--no-cache` | P0 | M |
| [WO5.0.0-011](WO5.0.0-011-watch-decode-completeness.md) | Watch: prompt decode completeness (layered encodings, budget dial, entities) | P0 | M |
| [WO5.0.0-012](WO5.0.0-012-firewall-path-auth.md) | Firewall: path classification bypassed by query strings + auth crash | P0 | S-M |
| [WO5.0.0-013](WO5.0.0-013-output-guard-truthfulness.md) | Watch: output truthfulness (unscanned choices/tool_calls, encoded exfil) | P0 | M |
| [WO5.0.0-014](WO5.0.0-014-docker-truth.md) | Docker truth end-to-end (hub image, helm tag convention, existence gate) | P0 | M |
| [WO5.0.0-015](WO5.0.0-015-scan-selection-honesty.md) | Scan: selection & worker honesty (dropped rules, rules=[], intelligence mode) | P1 | S-M |
| [WO5.0.0-016](WO5.0.0-016-scan-silent-skip.md) | Scan: silent-skip accounting (SBOM unknown dead-end, error paths, validation skips) | P1 | M |
| [WO5.0.0-017](WO5.0.0-017-sandbox-job-store.md) | Sandbox: job-store correctness (prune deletes all, orphans, redis honesty) | P1 | M |
| [WO5.0.0-018](WO5.0.0-018-sandbox-audit-transport-hygiene.md) | Sandbox: audit & transport hygiene sweep (query recency, gRPC, dedup, state) | P1 | M |
| [WO5.0.0-019](WO5.0.0-019-landlock-verdict-parity.md) | Sandbox: landlock verdict parity + degraded honesty | P1 | M |
| [WO5.0.0-020](WO5.0.0-020-serve-loop-remainder.md) | Serve: event-loop hygiene remainder (ready/history/projects/redis) | P1 | M |
| [WO5.0.0-021](WO5.0.0-021-serve-scheduler-correctness.md) | Serve: scheduler correctness (double-fire, SMTP persistence, report scope, name squat) | P1 | M |
| [WO5.0.0-022](WO5.0.0-022-serve-org-scoping.md) | Serve: org-scoping remainder (threat score, anomaly filters, rule mutation surface) | P1 | M |
| [WO5.0.0-023](WO5.0.0-023-gateway-hardening.md) | Watch: gateway production hardening (loop, body, auth, streaming ceiling) | P1 | M |
| [WO5.0.0-024](WO5.0.0-024-watch-metrics-telemetry-sweep.md) | Watch: metrics/telemetry honesty sweep (family render, edge hardening) | P1 | M |
| [WO5.0.0-025](WO5.0.0-025-ci-doctor-gate-truthfulness.md) | CI/doctor gate truthfulness (exit codes, gates that can't fail) | P1 | M |
| [WO5.0.0-026](WO5.0.0-026-ci-path-filter-report.md) | CI: path-filter completion + REPORT.json gating + nightly cancellation | P2 | S |
| [WO5.0.0-027](WO5.0.0-027-docs-tooling-sync.md) | Docs & tooling sync sweep (small truthfulness riders) | P2 | S |

Suggested batch shape: P0 security cluster as 3 parallel subagent worktrees (sandbox 001-004 / serve 005-008 / scan+watch+firewall 009-013), 014 solo before the next release; P1 next; P2 riders last.

## WO4.0.0 — Fourth series (OPEN — seeded by the 2026-08-17 five-explorer round)

Priorities: P0 = security/correctness, do first. Each WO names its verified evidence. Worktrees: `wo/4.0.0/<slug>` off `origin/dev`.

| ID | Title | Pri | Effort |
|----|-------|-----|--------|
| [WO4.0.0-001](WO4.0.0-001-landlock-backend-truth.md) | Landlock backend: make it actually work (syscall numbers wrong on x86_64 — dead everywhere) | P0 | L |
| [WO4.0.0-002](WO4.0.0-002-daemon-transport-security.md) | Sandbox daemon: gRPC auth bypass + single-thread blackout + signals + traversal write | P0 | M |
| [WO4.0.0-003](WO4.0.0-003-serve-pg-tenancy.md) | Serve: postgres org-create/association broken | P0 | S-M |
| [WO4.0.0-004](WO4.0.0-004-serve-audit-lifecycle.md) | Serve: retention permanently breaks the audit-chain verifier | P0 | M |
| [WO4.0.0-005](WO4.0.0-005-serve-correlation-tenancy.md) | Serve: correlation/report/alert org=None leaks | P0 | M |
| [WO4.0.0-006](WO4.0.0-006-scan-cache-correctness.md) | Scan: cache serves wrong results; OSV version-blind | P0 | M |
| [WO4.0.0-007](WO4.0.0-007-watch-guard-integrity.md) | Watch: fail-closed corpus gap, Cyrillic blanket-block, decode-order bypass | P0 | M |
| [WO4.0.0-008](WO4.0.0-008-scan-detection-quality.md) | Scan: recall recovery + metadata FP gating + honest card | P0 | L |
| [WO4.0.0-009](WO4.0.0-009-release-mechanics.md) | Release mechanics (next release ships correct tags/versions) | P0 | M |
| [WO4.0.0-010](WO4.0.0-010-sandbox-tenant-secrets.md) | Sandbox: tenant store unwired; exfil secrets returned to caller; env allowlist ADR | P1 | M |
| [WO4.0.0-011](WO4.0.0-011-sandbox-containment.md) | Sandbox: killpg on timeout, RLIMIT_CPU/NPROC, subprocess-backend hang | P1 | M |
| [WO4.0.0-012](WO4.0.0-012-serve-truthfulness.md) | Serve: scheduler/health/anomaly/status truthfulness | P1 | S-M |
| [WO4.0.0-013](WO4.0.0-013-serve-concurrency.md) | Serve: event-loop hygiene + global DB mutex + /health cost | P1 | M-L |
| [WO4.0.0-014](WO4.0.0-014-scan-perf.md) | Scan: parallel rules, shared walks, daemon responsiveness | P1 | L |
| [WO4.0.0-015](WO4.0.0-015-scan-sbom-monorepo.md) | Scan: SBOM maven artifactId + CycloneDX versions + nested manifests | P1 | S-M |
| [WO4.0.0-016](WO4.0.0-016-watch-perf-metrics.md) | Watch: 14–22s/MB scan cost + invalid /metrics exposition | P1 | M-L |
| [WO4.0.0-017](WO4.0.0-017-ci-tiers-versions.md) | CI: path-filter hole, kind/pg matrices, py3.14, nightly dedupe | P1 | M |
| [WO4.0.0-018](WO4.0.0-018-l4-evidence-fp.md) | Sandbox: L4 evidence blind on enforced backends + FP catalog | P1 | M |
| [WO4.0.0-019](WO4.0.0-019-cluster-trust-healing.md) | Sandbox: cluster gossip ships secrets; partitions never heal | P2 | M |
| [WO4.0.0-020](WO4.0.0-020-serve-multi-worker.md) | Serve: multi-worker/horizontal readiness | P2 | L |
| [WO4.0.0-021](WO4.0.0-021-serve-tenant-product.md) | Serve: tier enforcement, member mgmt, plugin capability phase-1 | P2 | L |
| [WO4.0.0-022](WO4.0.0-022-firewall-productization.md) | Firewall: version-scoped verdicts, tarball decision, surface doc | P2 | M-L |
| [WO4.0.0-023](WO4.0.0-023-watch-gateway-shim.md) | Watch: API-compat gateway shim (prototype) | P2 | L |
| [WO4.0.0-024](WO4.0.0-024-cli-doctor-deploy-hygiene.md) | CLI/doctor/deploy hygiene riders | P2 | S-M |

## WO3.0.0 — Third series (shipped; statuses verified against code 2026-08)

| ID | Title | Status |
|----|-------|--------|
| [WO3.0.0-001](WO3.0.0-001-jwt-rs256.md) | RS256 JWT + JWK Rotation | COMPLETE — `SecurityConfig.jwt_private_key`/`jwt_kid` (`settings.py`), RS256 signing + JWK in `services/auth.py` |
| [WO3.0.0-002](WO3.0.0-002-namespace-collision.md) | Namespace/Scope Collision Detection | COMPLETE — `L2-NSCOL-001` in `RULE_INFO` |
| [WO3.0.0-003](WO3.0.0-003-version-confusion.md) | Version-Confusion Detection | COMPLETE — `L2-VCONF-001` in `RULE_INFO` |
| [WO3.0.0-004](WO3.0.0-004-osv-realtime.md) | Real-Time OSV Advisory Feed | COMPLETE — `OSVClient` (`scan/intelligence.py`), `--intelligence connected` |
| [WO3.0.0-005](WO3.0.0-005-backup-encryption.md) | Backup Encryption + Offsite (S3/GCS) | COMPLETE — AES-GCM backup + S3 config (`services/backup.py`, `BackupConfig`) |
| [WO3.0.0-006](WO3.0.0-006-webauthn.md) | WebAuthn/FIDO2 MFA | COMPLETE — `/auth/webauthn/*` endpoints, `webauthn` extra, `PICOSHOGUN_WEBAUTHN_*` |
| [WO3.0.0-007](WO3.0.0-007-rate-limit-failclosed.md) | Distributed Rate Limiting Fail-Closed | COMPLETE — `PICOSHOGUN_RATELIMIT_REDIS_FAIL_CLOSED` (`settings.py`) |
| [WO3.0.0-008](WO3.0.0-008-error-hierarchy.md) | Unified Exception Hierarchy + Bare-Except Cleanup | OPEN — `ErrorCodes` table exists (`sandbox/errors.py`); full hierarchy/cleanup not verified |
| [WO3.0.0-009](WO3.0.0-009-slowloris-timeout.md) | Slowloris / Header-Read Timeout | COMPLETE at app layer — `PICOSHOGUN_LIMIT_CONCURRENCY`/`LIMIT_MAX_REQUESTS` wired in `api/server.py`; true header-read deadline documented as a reverse-proxy responsibility |
| [WO3.0.0-010](WO3.0.0-010-recall-floor.md) | Tighten Detection Recall Floor | COMPLETE — mutation benchmark + `passes_recall_floor` (`scan/mutation_benchmark.py`, `tests/scan/test_mutation_benchmark.py`) |
| [WO3.0.0-011](WO3.0.0-011-test-quality-dedup.md) | Test-quality dedup (two largest test files) | COMPLETE — merge `54a8b25f`; 210 tests passing |
| [WO3.0.0-012](WO3.0.0-012-overengineering-audit.md) | Over-engineering audit | COMPLETE — report delivered; findings acted on in `42520317` |
| [WO3.0.0-013](WO3.0.0-013-core-consolidation.md) | `_core` constant-time compare consolidation | COMPLETE — merge `50248aec` |

## WO2.0.0 — Second series (COMPLETE)

- [WO2.0.0-001](WO2.0.0-001-supply-chain-security.md) — Supply-chain security hardening — UNVERIFIED (spec predates status tracking)
- [WO2.0.0-002](WO2.0.0-002-multi-tenancy.md) — Multi-tenancy hardening — COMPLETE (CHANGELOG 2026-08-12)
- [WO2.0.0-003](WO2.0.0-003-error-handling.md) — Error handling — UNVERIFIED (spec predates status tracking)
- [WO2.0.0-004](WO2.0.0-004-package-intelligence.md) — Package intelligence — COMPLETE (CHANGELOG, ADR-009)
- [WO2.0.0-005](WO2.0.0-005-adr-audit-hash-chain.md) — ADR audit-hash-chain — UNVERIFIED (spec predates status tracking)
- [WO2.0.0-006](WO2.0.0-006-adr-gaps.md) — ADR gaps — UNVERIFIED (spec predates status tracking)
- [WO2.0.0-007](WO2.0.0-007-auth-hardening.md) — Auth hardening: MFA/TOTP, JWT JTI revocation, account lockout — COMPLETE (CHANGELOG 2026-08-12)
- [WO2.0.0-008](WO2.0.0-008-audit-fsync.md) — Audit fsync + crash-recovery — COMPLETE (CHANGELOG 2026-08-12)
- [WO2.0.0-009](WO2.0.0-009-reproducible-builds.md) — Reproducible builds + hash-pinned deps — COMPLETE (CHANGELOG 2026-08-12)
- [WO2.0.0-010](WO2.0.0-010-role-scoped-tokens.md) — Role-scoped tokens + CORS default — COMPLETE (CHANGELOG 2026-08-12)
- [WO2.0.0-011](WO2.0.0-011-reachability.md) — Reachability analysis — COMPLETE (CHANGELOG 2026-08-12)
- [WO2.0.0-012](WO2.0.0-012-package-intel-depth.md) — Package intelligence: download counts + package age — COMPLETE (CHANGELOG 2026-08-12)

## Rules
- Work in isolated worktrees off `dev`. Never touch `main` directly.
- Run the gate before merging. Paste actual output.
- Do NOT rewrite tests to pass. Fix root causes.
- Do NOT lower thresholds to make gates green.
- Do NOT commit `picowatch_audit.db`, `*.corpus.json`, `.coverage`, runtime sandbox state.
