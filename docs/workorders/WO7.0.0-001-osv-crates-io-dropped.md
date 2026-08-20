# WO7.0.0-001 — Scan: OSV connected-mode drops ALL Rust/cargo advisories (`crates.io` ecosystem not mapped)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/osv-crates-io-dropped`)
**Priority:** P0 · Effort S · Risk M
**Scope:** `picosentry/scan/advisory.py`, `picosentry/scan/rules/advisory_check.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + test: a real OSV `crates.io` record (e.g. RUSTSEC-2018-0001/RUSTSEC-2021-0014) round-trips through `Advisory.from_osv` and reaches `advisory_check`.

## Objective
Every Rust advisory from OSV connected mode is silently dropped — `Advisory.from_osv` filters `affected[].package.ecosystem` against `_KNOWN_ECOSYSTEMS`, which holds `cargo` but OSV uses `crates.io`; `.lower()` cannot bridge that. Map `crates.io → cargo` before the membership check.

## Evidence (verified 2026-08-20, explorer SA-scan; file:line chain)
- `advisory.py:16`: `_KNOWN_ECOSYSTEMS = frozenset(("npm", "pypi", "go", "cargo", ...))`.
- `advisory.py:101`: `if pkg_ecosystem.lower() not in _KNOWN_ECOSYSTEMS: continue` — `"crates.io"` ∉ set → record `continue`d.
- `advisory_check.py:465-473`: downstream consumer never sees the dropped record.
- OSV schema ships Rust advisories with `"ecosystem": "crates.io"` (verified against api.osv.dev).

## Deliverables
1. In `from_osv`, normalize `crates.io` → `cargo` (and audit for any other OSV-specific aliases) before the `_KNOWN_ECOSYSTEMS` check.
2. Regression test: feed a `crates.io` ecosystem record through `from_osv`, assert it is returned and reachable by `advisory_check`.