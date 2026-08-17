# WO4.0.0-022 — Firewall: productization

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (2026-08-17, `wo/4.0.0/registry-firewall`) — deliverables 1-3 implemented with tests; premise re-verification below (1 FP-class still open, scan-side: `L2-TYPO-001` short-name calibration — flagged to scan detection-quality, NOT firewall-fixable without blinding the typosquat gate). PARTIAL on that one class; everything else landed.
**Priority:** P2 · Effort M-L · Risk M
**Scope:** `picosentry/firewall/{proxy.py,scanner.py,config.py}`, `docs/FIREWALL.md` (new)

**Gate:** `bash scripts/test.sh fast` + clean-catalog fixtures pass (no default BLOCK/QUARANTINE on benign packages, pending WO4.0.0-008); ThreadingHTTPServer + listen_host/auth config tests; `docs/FIREWALL.md` documents the tarball decision.

## Premise re-verification (against dev 6044567e, live repro 2026-08-17)

1. **PARTLY RESOLVED-PREEXISTING.** LICENSE/MAINT MEDIUM quarantine on clean manifests: gone — WO-008's gating (v2.1.2) holds; clean manifests without install scripts produce zero findings (verified live). BUT `"pkg"` → BLOCK via L2-TYPO-001 CRITICAL still reproduces (edit-distance 1 from `pg`) — scan-side rule calibration, outside this WO's file scope. AND a NEW structural FP surfaced: `L2-LOCK-001` HIGH fires on any manifest with ≥1 dependency because registry metadata never ships a lockfile → near-universal default BLOCK. Fixed firewall-side (artifact-rule exclusion).
2. **PREMISE WRONG-DIRECTION — real bug worse.** Whole-catalog verdicts were not poisoned by old versions; they were **blind**: rules only read root-level manifest fields, so `GET /pkg` (all versions nested under `versions`) produced ZERO version-content findings (verified: old evil 0.9.0 invisible when querying clean latest). Fixed by version-slice extraction (`extract_version_manifest`).
3. **CONFIRMED.** Tarballs (3+ segments) match no regex → streamed unscanned; no docs/FIREWALL.md existed. Decision taken: documented explicit pass-through + `X-PicoSentry-Verdict: passthrough` header + doc (no synchronous tarball scan hook — that is `picosentry scan`'s job on the artifact).
4. **CONFIRMED** (all four): QUARANTINE served body with headers only by accident → now explicit `quarantine_action` config (`tag` default / `block`); single-threaded `HTTPServer` → `ThreadingHTTPServer` + `daemon_threads`; 512MB in-memory buffering → 64KiB-chunk streaming with running cap (`pass_through_max_bytes`); hard-coded `0.0.0.0` → `listen_host` config defaulting `127.0.0.1` + `auth_token` option (Bearer, constant-time compare).

## What landed

- `scanner.py`: `extract_version_manifest()` (npm catalog → dist-tags/explicit version slice; PyPI → `info`); artifact rules (`L2-LOCK-001`, `L2-PNPM-001`) unregistered from the firewall's engine instance — NOT via `scan(rules=...)`, which the engine post-filters to registered ids and would silently drop fan-out ids like `L2-PYPI-TYPO-001` (engine.py:546-548); default thresholds recalibrated BLOCK=[CRITICAL], QUARANTINE=[HIGH, MEDIUM] (HIGH metadata alone — install scripts — must not 403 every esbuild-class package).
- `proxy.py`: `_authorized()` Bearer check (hmac.compare_digest), `ThreadingHTTPServer`, `listen_host`, `quarantine_action`, `_open_upstream_stream()` (safe_urlopen's HTTPS/SSRF checks, unbuffered) + chunked `_proxy_pass` with cap-and-close, `passthrough`/`allow` verdict headers.
- `tests/firewall/`: +28 tests — real-engine integration postures (clean catalog ALLOW incl. deps, evil version BLOCK, benign postinstall QUARANTINE, pypi typo QUARANTINE, lock-FP exclusion), version-slice units, auth matrix, quarantine block action, streaming + cap abort, serve wiring. 77 passed in suite.
- `docs/FIREWALL.md`: new surface doc — verdict taxonomy/headers, tarball decision + rationale, version scoping, rule exclusions, config reference, honest-doc limitations.

## Open follow-ups (outside this WO's file scope)

- `L2-TYPO-001` short-name calibration (`pkg`→`pg` class): needs scan-side known-legitimate allowlist growth or min-length heuristic — scan detection-quality territory.
- `picosentry/cli_commands/firewall.py` still passes argparse defaults `CRITICAL,HIGH`/`MEDIUM` (old posture) and does not expose `--listen-host`/`--auth-token`/`--quarantine-action` — CLI seam left to owner of that tree.

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
