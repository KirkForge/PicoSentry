# WO7.0.0-012 — Scan: PyPI typosquat `known_legitimate` uses normalized names but deps are raw → self-typosquat FP

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/typosquat-known-legit`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `picosentry/scan/rules/typosquat.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + test: `ruamel.yaml` (raw dep) vs `ruamel-yaml` (normalized known-legitimate) matches; no self-typosquat finding at edit distance 1.

## Objective
`known_legitimate` stores PEP 503-normalized names (`ruamel-yaml`); deps are collected raw (`ruamel.yaml`). The compare doesn't normalize → a package is its own typosquat at edit distance 1.

## Evidence (verified 2026-08-20, explorer SA-scan; file:line chain)
- `typosquat.py:394-411`: `known_legitimate` is built with normalized names (dot/underscore → dash).
- `typosquat.py:164-178`: collected dep names are raw (no normalization) when compared against `known_legitimate`.
- `ruamel.yaml` (raw) vs `ruamel-yaml` (normalized) → no match → self-typosquat at edit distance 1.

## Deliverables
1. PEP 503-normalize the dep name before the `known_legitimate` membership check (and before the edit-distance compare against itself).
2. Regression test per the gate.