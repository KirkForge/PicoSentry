# WO5.0.0-016 — Scan: silent-skip accounting (SBOM unknown dead-end, error paths, validation skips)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/scan-silentskip`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/scan/sbom.py`, `picosentry/scan/cli_service.py`, `picosentry/scan/validation.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + new tests: purl-less SBOM → non-zero `unscannable_components` surfaced (result + stderr); garbage `--sbom` file → clean exit 2; validation report carries `skipped_fixtures` and warns when non-zero.

## Objective
Skipping must be loud and counted — the class of bug that manufactured stale benchmark claims before (lessons 2026-08-17).

## Evidence (verified 2026-08-18, explorer SA-R; live repros)
1. **Purl-less SBOM components vanish silently** (HIGH truthfulness, product promise): purl optional in CycloneDX; SPDX-2.x fallback reads a nonexistent-in-spec key. Components get `ecosystem="unknown"`, appended to `refs` (so the "SBOM contains no packages" guard does NOT fire), written to `unknown-packages.json` — a file no rule parses (`sbom.py:172-186,226-248`, `cli_service.py:416-418,428-489`). Live: CycloneDX 1.5 with two purl-less npm components → 0 findings, all rules "ok".
2. **`--sbom` garbage/oversized → raw traceback** (LOW): `parse_sbom` ValueError propagates (`cli_service.py:402-412`; no catch in `cli_commands/scan.py:213-241`) — 22-line traceback, exit 1, where other input errors exit 2 with a clean message.
3. **Validation harness skips without counting** (LOW): `_load_fixture` returns None on malformed spec / unknown label with only a log warning; no `skipped` counter in `discover_fixtures`/`ValidationReport` (`validation.py:251-317`) — precision/recall silently computed over a smaller population. WO-008 fixed label acceptance, not skip accounting.

## Deliverables
1. Ecosystem fallbacks for purl-less components (CycloneDX `type` + name heuristics, SPDX `downloadLocation` sniffing) + `unscannable_components` count surfaced in result/stderr when non-zero.
2. `ValueError` around `parse_sbom` → clean message, `SystemExit(2)`.
3. `skipped_fixtures` in the validation report; `--validate` warns (or fails) when non-zero.
