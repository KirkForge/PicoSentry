# Workorder Series (docs/workorders)

**Single source of work-order truth.** Every durable unit of work is a WO file here. `workplan.md` (gitignored) is per-session scratch, never truth. Root `WO/` was consolidated here 2026-08-17 and deleted.

Improvement series to push the production review score up. Work happens in isolated worktrees off `dev`; the orchestrator reviews and merges.

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
