# WO4.0.0-022 — Firewall: productization

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN — NOT STARTED in `wo/4.0.0/scan-watch-p1` (2026-08-17): this WO's file scope (`picosentry/firewall/**`, `tests/firewall/**`, `docs/FIREWALL.md`) is outside that worktree's exclusive ownership (scan/** + watch/**); it needs its own worktree per the WO's owner field (`wo/4.0.0/registry-firewall`). Also note dependency: the default-BLOCK short-name FP it hits depends on WO4.0.0-008's FP gating (landed in 2.1.2) — re-verify the repro before scoping the fix.
**Priority:** P2 · Effort M-L · Risk M
**Scope:** `picosentry/firewall/{proxy.py,scanner.py,config.py}`, `docs/FIREWALL.md` (new)

**Gate:** `bash scripts/test.sh fast` + clean-catalog fixtures pass (no default BLOCK/QUARANTINE on benign packages, pending WO4.0.0-008); ThreadingHTTPServer + listen_host/auth config tests; `docs/FIREWALL.md` documents the tarball decision.

## Objective
Make the registry firewall usable as designed — today it blocks minimal-but-benign packages by default and passes tarballs unscanned by accident.

## Evidence (verified live 2026-08-17)
1. Minimal clean catalog for name `"pkg"` → BLOCK (L2-TYPO-001 CRITICAL — short-name FP); realistic manifests → QUARANTINE (LICENSE/MAINT MEDIUM) — inherited scan FPs become install failures (depends on WO4.0.0-008 FP gating).
2. Verdict cached under `(name, version)` but computed from whole-catalog metadata (scanner.py:81-108 — npm `/pkg` returns all versions; an old version's finding blocks the latest).
3. Package tarballs (3+ path segments) match no regex → streamed with ZERO inspection (scanner.py:18-19) — metadata-only firewall by accident, not documented decision. No docs/FIREWALL.md exists at all.
4. QUARANTINE serves the body anyway (headers only, proxy.py:122-132); single-threaded HTTPServer head-of-line blocking; 512MB in-memory pass-through buffering; hard-coded bind 0.0.0.0, no auth option, no listen_host config.

## Deliverables
1. Version-scoped verdicts (scan the requested version's manifest slice); quarantine body policy decision; tarball decision (scan hook or documented explicit pass-through + header).
2. ThreadingHTTPServer; listen_host/auth config; streaming pass-through with bounded memory.
3. `docs/FIREWALL.md` — the missing surface doc.
