# Workorder Series (docs/workorders)

**Single source of work-order truth.** Every durable unit of work is a WO file here. `workplan.md` (gitignored) is per-session scratch, never truth. Root `WO/` was consolidated here 2026-08-17 and deleted.

Improvement series to push the production review score up. Work happens in isolated worktrees off `dev`; the orchestrator reviews and merges.

## WO7.0.0 — Seventh series (OPEN — seeded by the 2026-08-20 six-explorer round)

Priorities: P0 = security/correctness, do first. Every WO carries verified evidence. Worktrees: `wo/7.0.0/<slug>` off `origin/dev`.

| ID | Title | Pri | Effort |
|----|-------|-----|--------|
| [WO7.0.0-001](WO7.0.0-001-osv-crates-io-dropped.md) | Scan: OSV connected-mode drops ALL Rust/cargo advisories (`crates.io` not mapped) | P0 | S |
| [WO7.0.0-002](WO7.0.0-002-sandbox-http-health-bypassed.md) | Sandbox: HTTP /health hardcodes "healthy" — bypasses check_health() | P0 | S |
| [WO7.0.0-003](WO7.0.0-003-grpc-scan-audit-untenantable.md) | Sandbox: gRPC Scan RPC audit events not attributable and not tenant-tagged | P0 | S |
| [WO7.0.0-004](WO7.0.0-004-correlation-chains-unique-tenant.md) | Serve: `correlation_chains.artifact_id UNIQUE` clobbers cross-tenant chain scores | P0 | S |
| [WO7.0.0-005](WO7.0.0-005-project-stats-cross-tenant-count.md) | Serve: `update_project_stats` counts ALL orgs' runs (cross-tenant leak) | P0 | S |
| [WO7.0.0-006](WO7.0.0-006-firewall-encoded-dot-traversal.md) | Firewall: encoded-dot path traversal bypasses `_safe_upstream_path` (SSRF) | P0 | S |
| [WO7.0.0-007](WO7.0.0-007-pep508-dep-name-corruption.md) | Scan: PEP 508 dep parser in advisory collector corrupts 3 dep spec forms | P1 | S |
| [WO7.0.0-008](WO7.0.0-008-firewall-toml-injection.md) | Firewall: TOML injection via URL-path package name | P1 | S |
| [WO7.0.0-009](WO7.0.0-009-firewall-unresolved-cached.md) | Firewall: `UNRESOLVED` verdict cached with full TTL (stale 502 on new publishes) | P1 | S |
| [WO7.0.0-010](WO7.0.0-010-firewall-cache-on-eviction.md) | Firewall: VerdictCache O(n) eviction on every get/put (3.4ms/get at 10k) | P1 | S-M |
| [WO7.0.0-011](WO7.0.0-011-scan-cache-ecosystem-blind.md) | Scan: cache blind to ecosystem detection (stale no-pypi verdict) | P1 | M |
| [WO7.0.0-012](WO7.0.0-012-typosquat-known-legit-normalize.md) | Scan: PyPI typosquat `known_legitimate` normalized vs raw deps → self-typosquat FP | P1 | S |
| [WO7.0.0-013](WO7.0.0-013-firewall-pypi-metadata-unused.md) | Firewall: PyPI scan blind to author/maintainer/repo/provenance | P1 | M |
| [WO7.0.0-014](WO7.0.0-014-grpc-scan-bypasses-jobstore.md) | Sandbox: gRPC Scan RPC bypasses job_store (not persisted, not tenant-scoped) | P1 | M |
| [WO7.0.0-015](WO7.0.0-015-grpc-ratelimit-skip.md) | Sandbox: gRPC auth interceptor skips rate limiting (DoS with valid token) | P1 | S |
| [WO7.0.0-016](WO7.0.0-016-clustertokenstore-timing.md) | Sandbox: `ClusterTokenStore.is_accepted` non-constant-time dict membership | P1 | S |
| [WO7.0.0-017](WO7.0.0-017-tokenauth-bruteforce-threadsafe.md) | Sandbox: `TokenAuth` brute-force tracking dict not thread-safe | P1 | S |
| [WO7.0.0-018](WO7.0.0-018-daemon-orphaned-jobs.md) | Sandbox: daemon restart leaves orphaned "running" jobs (no reconciliation) | P1 | S |
| [WO7.0.0-019](WO7.0.0-019-versioned-policy-signature.md) | Sandbox: versioned policy loads skip signature verification (only latest.json signed) | P1 | S |
| [WO7.0.0-020](WO7.0.0-020-l4engine-exception-narrow.md) | Sandbox: `L4Engine.analyze` exception tuple too narrow (`KeyError` kills scan) | P1 | S |
| [WO7.0.0-021](WO7.0.0-021-gateway-nonjson-200-unscanned.md) | Watch: gateway non-JSON 200 passes output unscanned (no picowatch metadata) | P1 | S |
| [WO7.0.0-022](WO7.0.0-022-gateway-error-body-attested.md) | Watch: gateway upstream 200 with error body attests `output_valid: true` | P1 | S |
| [WO7.0.0-023](WO7.0.0-023-cli-flag-forwarding.md) | CLI: flag forwarding gaps (admission/daemon/watch) | P1 | M |
| [WO7.0.0-024](WO7.0.0-024-serve-helm-templates.md) | Deploy: serve helm chart missing PVC/SA/Secret/RBAC/NetworkPolicy/PDB templates | P1 | M |
| [WO7.0.0-025](WO7.0.0-025-gitlab-template-github-format.md) | CI: gitlab template github-format hard-fails (action.yml fixed, gitlab not) | P1 | S |
| [WO7.0.0-026](WO7.0.0-026-grpc-health-dos.md) | Sandbox: gRPC `Health()` unauthenticated + expensive check_health() (DoS) | P1 | S |
| [WO7.0.0-027](WO7.0.0-027-backup-tempdir-collision.md) | Serve: `backup.create_backup` temp_dir collision under concurrency | P1 | S |
| [WO7.0.0-028](WO7.0.0-028-acknowledge-alert-sent-conflation.md) | Serve: `acknowledge_alert` conflates "acknowledged" with "delivered" via `sent` | P1 | S |
| [WO7.0.0-029](WO7.0.0-029-ratelimit-flush-sigterm.md) | Serve: rate-limit flush thread not stopped in SIGTERM (post-db.close errors) | P2 | S |
| [WO7.0.0-030](WO7.0.0-030-deny-packages-normalize.md) | Scan: `deny_packages` comparison case-sensitive, not PEP 503 normalized | P2 | S |
| [WO7.0.0-031](WO7.0.0-031-osv-disk-cache-on2.md) | Scan: OSV disk-cache `_write_cache` O(N²) — `_enforce_caps` on every write | P2 | S |
| [WO7.0.0-032](WO7.0.0-032-is-package-reachable-rescan.md) | Scan: `_is_package_reachable` rescans source tree per package (O(packages×files)) | P2 | M |
| [WO7.0.0-033](WO7.0.0-033-orchestrator-health-atomic.md) | Serve: `_orchestrator_health.perform_health_checks` writes rows non-atomically | P2 | S |
| [WO7.0.0-034](WO7.0.0-034-core-truthfulness-riders.md) | Core: truthfulness riders round 4 (doctor, CLI, README, k8s, picodome ro-fs) | P2 | M |

Suggested batch shape: P0 scan (001/006) + watch (002-003) + serve (004/005); P1 scan cluster (007/009/011/012/013) + sandbox cluster (014-020) + watch (021/022) + serve (027/028) + core (023-025); P2 riders (029-034).

## WO6.0.0 — Sixth series (DONE 2026-08-20 — 22/22 DONE, 7 parallel worktrees off origin/dev)

Priorities: P0 = security/correctness, do first. Every WO carries verified evidence (live repros or airtight file:line chains; the top claims re-verified by the orchestrator — 5/5 confirmed). WO5-033/031's interplay produced two of the biggest finds (outbox). Worktrees: `wo/6.0.0/<slug>` off `origin/dev`.

| ID | Title | Pri | Effort | Final status |
|----|-------|-----|--------|---------------|
| [WO6.0.0-001](WO6.0.0-001-watch-prefilter-soundness.md) | Watch: prefilter drops unconstrained alternation branches (3 shipped-rule FNs) | P0 | M | DONE |
| [WO6.0.0-002](WO6.0.0-002-watch-gate-bypasses.md) | Watch: decode/normalize gate bypasses (textlike dilution, separator split, entity, rot13 vocab) | P0 | M-L | DONE |
| [WO6.0.0-003](WO6.0.0-003-output-gateway-holes.md) | Watch: output FP (SYSTEM/PUBLIC English) + gateway message-shape holes | P0 | M | DONE |
| [WO6.0.0-004](WO6.0.0-004-grpc-audit-tenancy.md) | Sandbox: gRPC QueryAudit leaks all tenants' audit events | P0 | S | DONE |
| [WO6.0.0-005](WO6.0.0-005-seccomp-trace-parity.md) | Sandbox: seccomp-trace verdict parity break | P0 | M | DONE |
| [WO6.0.0-006](WO6.0.0-006-advisory-normalization.md) | Scan: advisory exact-match names (Flask/PyYAML zero advisories) + CVSS flattening | P0 | S-M | DONE |
| [WO6.0.0-007](WO6.0.0-007-policy-deny-inversion.md) | Scan: deny_packages SUPPRESSES findings for banned packages | P0 | S | DONE |
| [WO6.0.0-008](WO6.0.0-008-cache-node-modules.md) | Scan: cache blind to node_modules source content (stale clean verdicts) | P0 | M | DONE |
| [WO6.0.0-009](WO6.0.0-009-outbox-correctness.md) | Serve: outbox poller dies on pg + N× escalation delivery across workers | P0 | M-L | DONE |
| [WO6.0.0-010](WO6.0.0-010-persistence-contracts.md) | Serve: persistence catches wrong exceptions (500s) + /run orphaned rows | P0 | M | DONE |
| [WO6.0.0-011](WO6.0.0-011-events-history.md) | Serve: /events/history 500 (uuid vs int) + system-event visibility | P0 | S | DONE |
| [WO6.0.0-012](WO6.0.0-012-org-tier-clamp.md) | Serve: org create honors client tier (viewer self-serves enterprise) | P0 | S | DONE |
| [WO6.0.0-013](WO6.0.0-013-serve-tx-discipline.md) | Serve: login lock-order inversion (15s stalls) + immediate-default convoys | P0 | M | DONE |
| [WO6.0.0-014](WO6.0.0-014-cluster-lifecycle.md) | Sandbox: cluster token lifecycle (grace=0 inverted, self-refreshing trust, dead EITHER-auth) | P0 | M | DONE (TOCTOU rider deferred) |
| [WO6.0.0-015](WO6.0.0-015-helm-default-install.md) | Deploy: helm default install prints --help and exits | P0 | S | DONE |
| [WO6.0.0-016](WO6.0.0-016-decode-budget-starvation.md) | Watch: decode-budget starvation advisory-only | P1 | M | DONE |
| [WO6.0.0-017](WO6.0.0-017-firewall-cache-scope.md) | Firewall: VerdictCache thread safety + %40 scope misclassification | P1 | S-M | DONE |
| [WO6.0.0-018](WO6.0.0-018-sandbox-hygiene-3.md) | Sandbox: hygiene round 3 (audit archives, reserved names, health, /ready forks, riders) | P1 | M | DONE |
| [WO6.0.0-019](WO6.0.0-019-corpus-memory-governance.md) | Scan: corpus-index memory governance + GO keyboard ceiling + riders | P1 | M | DONE |
| [WO6.0.0-020](WO6.0.0-020-serve-multiworker-riders.md) | Serve: multi-worker riders (SIGTERM, topology, sync deps, TOCTOU, UTC) | P1 | M | DONE |
| [WO6.0.0-021](WO6.0.0-021-core-truthfulness-3.md) | Core: truthfulness round 3 (maturity drift, scan-artifacts push tier, lockstep gaps) | P1 | M | DONE |
| [WO6.0.0-022](WO6.0.0-022-manual-p2-rider.md) | Docs: manual P2-wave rider (X-Org-Id, members/quotas, multi-worker honesty) | P1 | S-M | DONE |

**Batch executed 2026-08-20**: 6 parallel worktrees off `origin/dev` (watch-guards 001/002/003/016, sandbox-cluster 004/005/014/018, scan-cluster 006/007/008/019, serve-outbox 009/010, serve-rest 011/012/013/020, core-docs 015/021/022) + 1 follow-up worktree (firewall 017). 22/22 DONE in one session. Orchestrator landed the `--picoshogun-plugin` 1-line reorder (WO-022 item 5) flagged by two workers. Zero merge conflicts (disjoint file ownership verified pre-merge). Central gate green: fast 5639 passed / 0 failed, ruff/format/mypy clean.

## WO5.0.0 — Fifth series (CLOSED 2026-08-18 — 32 DONE / 3 honest PARTIALs, shipped v2.1.3; remainders tracked in state.md)

| ID | Title | Final status |
|----|-------|--------------|
| WO5.0.0-001..035 | See the WO files | 32 DONE (001-013, 015-027, 033-035) · PARTIAL 014 (docker push, tooling-gated) · PARTIAL 029 (<1s/MB target; 2.8× landed) · PARTIAL 031 (multi-worker core landed, e2e isolation pending) |

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
| [WO5.0.0-028](WO5.0.0-028-scan-typo-dp-calibration.md) | Scan: typosquat DP acceleration + short-name calibration (folds WO4-014) | P1 | M |
| [WO5.0.0-029](WO5.0.0-029-watch-fused-perf.md) | Watch: fused-pass <1s/MB + perf-ceiling test robustness (folds WO4-016) | P2 | M-L |
| [WO5.0.0-030](WO5.0.0-030-cluster-rotation-announcements.md) | Sandbox: cluster token rotation announcements + trust ceilings (folds WO4-019) | P2 | M |
| [WO5.0.0-031](WO5.0.0-031-serve-multi-worker.md) | Serve: multi-worker / horizontal readiness (folds WO4-020) | P2 | L |
| [WO5.0.0-032](WO5.0.0-032-serve-tenant-product.md) | Serve: tenant product completeness (folds WO4-021) | P2 | L |
| [WO5.0.0-033](WO5.0.0-033-serve-webhook-wildcard.md) | Serve: webhook wildcard event matching broken (new, P0-wave flag) | P1 | S |
| [WO5.0.0-034](WO5.0.0-034-scan-osv-cache-roundtrip.md) | Scan: OSV disk-cache round-trip decodes to empty (new, P0-wave flag) | P1 | S |
| [WO5.0.0-035](WO5.0.0-035-test-infra-py314-races.md) | Test-infra: py3.14 forkserver spawn race + slow-tier drift (new, P0-wave flag) | P2 | S-M |

Suggested batch shape: P0 security cluster as 3 parallel subagent worktrees (sandbox 001-004 / serve 005-008 / scan+watch+firewall 009-013), 014 solo before the next release; P1 next (incl. new flags 033-034); P2 riders last.

## WO4.0.0 — Fourth series (CLOSED 2026-08-18 — shipped parts in v2.1.2; every remainder folded into WO5.0.0)

| ID | Title | Final status |
|----|-------|--------------|
| [WO4.0.0-001](WO4.0.0-001-landlock-backend-truth.md) | Landlock backend: make it actually work | CLOSED-FOLDED → WO5.0.0-019 (real-exec CI job + seccomp composition); backend fixed & shipped |
| [WO4.0.0-002](WO4.0.0-002-daemon-transport-security.md) | Sandbox daemon: gRPC auth + availability + signals + traversal | DONE — shipped v2.1.2 |
| [WO4.0.0-003](WO4.0.0-003-serve-pg-tenancy.md) | Serve: postgres org-create/association | DONE — shipped v2.1.2 |
| [WO4.0.0-004](WO4.0.0-004-serve-audit-lifecycle.md) | Serve: retention × audit-chain coexistence | DONE — shipped v2.1.2 |
| [WO4.0.0-005](WO4.0.0-005-serve-correlation-tenancy.md) | Serve: correlation/report/alert tenancy | DONE — shipped v2.1.2 |
| [WO4.0.0-006](WO4.0.0-006-scan-cache-correctness.md) | Scan: cache correctness; OSV versioning | DONE — shipped v2.1.2 |
| [WO4.0.0-007](WO4.0.0-007-watch-guard-integrity.md) | Watch: guard integrity | DONE — shipped v2.1.2 |
| [WO4.0.0-008](WO4.0.0-008-scan-detection-quality.md) | Scan: detection quality + honest card | DONE — shipped v2.1.2 |
| [WO4.0.0-009](WO4.0.0-009-release-mechanics.md) | Release mechanics | DONE — shipped v2.1.2 |
| [WO4.0.0-010](WO4.0.0-010-sandbox-tenant-secrets.md) | Sandbox: tenant store, env allowlist, redaction | DONE — shipped v2.1.2 (production wiring completed by WO5.0.0-001) |
| [WO4.0.0-011](WO4.0.0-011-sandbox-containment.md) | Sandbox: killpg, RLIMIT_CPU/NPROC | DONE — shipped v2.1.2 |
| [WO4.0.0-012](WO4.0.0-012-serve-truthfulness.md) | Serve: scheduler/health/anomaly truthfulness | DONE — shipped v2.1.2 |
| [WO4.0.0-013](WO4.0.0-013-serve-concurrency.md) | Serve: event-loop + locks + /health | DONE — shipped v2.1.2 |
| [WO4.0.0-014](WO4.0.0-014-scan-perf.md) | Scan: throughput + daemon responsiveness | CLOSED-FOLDED → WO5.0.0-028 (typo DP + calibration); 1.33× + caches shipped |
| [WO4.0.0-015](WO4.0.0-015-scan-sbom-monorepo.md) | Scan: SBOM maven + CycloneDX + nested manifests | DONE — shipped v2.1.2 |
| [WO4.0.0-016](WO4.0.0-016-watch-perf-metrics.md) | Watch: perf + Prometheus hygiene | CLOSED-FOLDED → WO5.0.0-029 (fused pass); 2.8× + metrics shipped |
| [WO4.0.0-017](WO4.0.0-017-ci-tiers-versions.md) | CI: path-filter, matrices, 3.14, nightly | DONE — shipped v2.1.2 |
| [WO4.0.0-018](WO4.0.0-018-l4-evidence-fp.md) | Sandbox: L4 evidence + FP recalibration | DONE — shipped v2.1.2 |
| [WO4.0.0-019](WO4.0.0-019-cluster-trust-healing.md) | Sandbox: cluster trust + healing | CLOSED-FOLDED → WO5.0.0-030 (rotation announcements); digests + healing shipped |
| [WO4.0.0-020](WO4.0.0-020-serve-multi-worker.md) | Serve: multi-worker readiness | CLOSED-FOLDED → WO5.0.0-031; atomic persistence + boot race shipped |
| [WO4.0.0-021](WO4.0.0-021-serve-tenant-product.md) | Serve: tenant product completeness | CLOSED-FOLDED → WO5.0.0-032; plugin + output-bounding shipped |
| [WO4.0.0-022](WO4.0.0-022-firewall-productization.md) | Firewall: version-scoped verdicts + surface | DONE — shipped v2.1.2 (typosquat calibration → WO5.0.0-028) |
| [WO4.0.0-023](WO4.0.0-023-watch-gateway-shim.md) | Watch: gateway shim prototype | DONE-prototype — shipped v2.1.2 (hardening → WO5.0.0-023) |
| [WO4.0.0-024](WO4.0.0-024-cli-doctor-deploy-hygiene.md) | CLI/doctor/deploy hygiene | CLOSED-FOLDED → WO5.0.0-025 + WO5.0.0-027 |

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
