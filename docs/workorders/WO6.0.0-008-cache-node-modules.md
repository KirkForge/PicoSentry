# WO6.0.0-008 — Scan: cache blind to node_modules SOURCE content the OBFS/NETEX/CRED rules scan (stale clean verdicts)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/cache-node-modules`)
**Priority:** P0 · Effort M · Risk M (cache cost on large trees — measure)
**Scope:** `picosentry/scan/cli_service.py`, `picosentry/scan/rules/{obfuscation.py,network_exfil.py,credential_read.py}`, `tests/scan/test_cache_correctness.py`

**Gate:** `bash scripts/test.sh fast` + end-to-end: RUN1 benign → payload injected into `node_modules/*/index.js` → RUN2 (cached) reflects the new findings OR the residual window is `ceiling:`-annotated with the pinning test renamed to state the staleness consequence; cache-key cost measured on a large monorepo (no pathological hashing).

## Objective
WO5-010 fixed cache parity for build-hook files and node_modules MANIFESTS — but three rules scan node_modules JS/TS CONTENT, which the key still ignores. The pinning test (`test_cache_correctness.py:230`) currently enshrines the gap.

## Evidence (verified 2026-08-18, explorer SA-AP; live CLI with PICOSENTRY_CACHE_DIR)
`_is_scan_input` (`cli_service.py:93-108`): node_modules → only `package.json`. Readers: `obfuscation.py:227-265`, `network_exfil.py:357`, `credential_read.py:281` (scan `node_modules/**/*.{js,mjs,cjs,ts,tsx}`). Live: RUN1 benign 8 findings → inject eval+hex into `node_modules/evil-pkg/index.js` → RUN2 **8 findings (cache hit)** → RUN3 `--no-cache` **11** (L2-OBFS-001×2, L2-OBFS-002 back). TTL-bounded (default 1h; configurable longer). For a supply-chain scanner, "installed package code changed without a manifest change" is an in-scope threat.

## Deliverables
1. Hash JS-family content under node_modules within a byte budget (mirror `_MAX_INPUT_BYTES`), or fold a bounded sample (first N files × K bytes per package).
2. If full coverage is too costly: implement the bounded variant AND `ceiling:`-annotate the residual with the exact rules + window; update the pinning test to assert the consequence honestly.
