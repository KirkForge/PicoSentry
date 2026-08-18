# WO6.0.0-006 — Scan: advisory lookups exact-match on package name (Flask/PyYAML get zero advisories) + CVSS severity flattening

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/advisory-normalization`)
**Priority:** P0 · Effort S-M · Risk L
**Scope:** `picosentry/scan/advisory.py`, `picosentry/scan/rules/{pypi_lock_parser.py,pypi_utils.py}`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + regression test: `check('Flask', …)` == `check('flask', …)`; `ruamel.yaml` matches a `ruamel-yaml`-keyed record; CVSS 9.8-only record → CRITICAL.

## Objective
PEP 503 name normalization at index AND lookup — non-canonical PyPI names (the COMMON case in requirements.txt/METADATA) currently get zero advisories while the DB holds matches; connected-mode OSV records with only CVSS severity flatten to MEDIUM.

## Evidence (verified 2026-08-18, explorer SA-AP; live repro r3_advisory_case.py)
`advisory.py:168` `self._advisories.get(pkg_name, [])` — exact match; collectors feed raw names (`pypi_lock_parser.py:60`, `pypi_utils.py` METADATA `Name:`). Live: `check('flask')` → 1 advisory, `check('Flask')` → `[]`; `check('pyyaml')` vs `check('PyYAML')` same; `ruamel.yaml` → `[]` (DB keys `ruamel-yaml`). The bundled snapshot is npm-only, so this bites exactly on the `picosentry advisories fetch` workflow. OSV severity: `advisory.py:62-67` reads only `database_specific.severity` (bundled 51/51 have it; raw PyPI/Go records often carry only `severity: [{type: CVSS_V3, score}]` → default MEDIUM).

## Deliverables
1. `re.sub(r"[-_.]+", "-", name).lower()` at AdvisoryDB index time and in `check` (single chokepoint; collectors may stay raw).
2. CVSS score → severity bucket when `database_specific.severity` is absent.
3. Fixture-driven tests incl. the exact repro names.
