# WO5.0.0-009 — Scan: advisory pipeline correctness (default no-op, maven keying, multi-package records)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** DONE (2026-08-18, merge `8a0fbe2f`, worker SA-Y) — `AdvisoryDB.load()` unwraps the envelope (`load_bundled_advisories()` now delegates, ~25 lines deleted); pom emits `group:artifact` primary + bare fallback (deduped so dual-keyed DBs fire once); `from_osv` → `list[Advisory]` one per affected entry with isolated ranges (4 call sites updated); `from_ghsa` deleted. Tests: default-corpus lodash@4.17.15 fires L2-ADV-001 with no `--advisory-db` (hermetic), real-keyed pom repro, multi-package isolation. Fallout: clean fixtures no longer declare corpus-vulnerable lodash (→ chalk). FLAGGED → WO5.0.0-034 (OSV disk-cache round-trip decodes empty — pre-existing, adjacent file).
**Owner:** (unassigned — worktree `wo/5.0.0/scan-advisory`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/scan/rules/advisory_check.py`, `picosentry/scan/advisory.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + new tests: default-corpus (no `--advisory-db`) engine scan of lodash@4.17.15 fires L2-ADV-001; pom with real-keyed OSV log4j record fires; multi-package GHSA record matches all its packages.

## Objective
The product's core CVE capability must fire on default installs and against real-world OSV data shapes.

## Evidence (verified 2026-08-18, explorer SA-R; live repros)
1. **Default offline advisory check is a silent no-op** (HIGH): bundled corpus ships `corpus/advisories/npm-critical-advisories.json` as an envelope `{"metadata":…,"advisories":[51 records]}`. `_get_advisory_db(corpus_dir, None)` (default path) loads via `AdvisoryDB.load()` which parses each file as a raw OSV record → `from_osv(envelope)` finds no `affected` → 0 advisories → falls through to `~/.local/share/picosentry/advisories` (absent) → returns None → `detect_all_advisory_vulnerabilities` returns `[]`. Meanwhile `load_bundled_advisories()` (daemon *dashboard* only) unwraps correctly ("loaded, 51 advisories"). Live: bundled check of lodash 4.17.15 → 3 GHSAs via the dashboard loader, `db: None` via the scan-rule path.
2. **Maven pom branch keys by bare `artifactId`** (HIGH): `advisory_check.py:207-230` — pom `pkg_key = artifact_id` (line 217) while gradle uses `group:artifact` (line 226). Real OSV maven records name packages `org.apache.logging.log4j:log4j-core`. Live: pom + real-keyed record → `db.check('log4j-core', …)` misses; engine findings `[]`. `test_sbom_monorepo.py::test_maven_sbom_scan_fires_advisory` masks it with a synthetic bare-name fixture real OSV data never uses.
3. **`Advisory.from_osv` multi-package records** (LOW): `advisory.py:52-80` — loop over `affected` overwrites `pkg_name` per entry but accumulates ranges from every entry → only last package indexed, inheriting others' ranges (wrong versions flagged / FNs).
4. **`from_ghsa` is dead code** with a latent composite-range bug (`>= 4.0.0, < 4.2.1` parsed as `>= 4.0.0` only — `advisory.py:115-128`, zero callers). Delete it (deletion over addition).

## Deliverables
1. `AdvisoryDB.load()` (or `_get_advisory_db`) understands the envelope; default path fires without `advisories fetch`.
2. Pom lookups emit `group:artifact` (primary) + bare `artifact_id` (fallback); replace the unrealistic fixture with a real-keyed OSV record.
3. One `Advisory` per affected package for multi-package records.
4. Delete `from_ghsa`.
