# WO5.0.0-025 — CI/doctor gate truthfulness (exit codes, gates that can't fail)

**Series:** WO5.0.0 (exploration round 2026-08-18; folds WO4.0.0-024 remainder 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/gate-truth`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/cli_commands/doctor.py`, `picosentry/cli_commands/health.py`, `picosentry/_core/doctor.py`, `action.yml`, `ci-templates/gitlab-picosentry.yml`, `.github/workflows/verify-release.yml`, `tests/test_doctor.py`, `tests/test_release.py`

**Gate:** `bash scripts/test.sh fast` + new tests: `doctor --json` with a failing check exits 1; SARIF parse failure in the action path hard-fails (distinguish from count 0); attestation step fails on verification failure.

## Objective
Every gate that looks like it verifies something must be able to fail. (The systemic fix class from lessons: "a check that reports green while verifying nothing".)

## Evidence (verified 2026-08-18, explorer SA-V; live repros)
1. **`picosentry doctor --json` exits 0 even when checks fail** (HIGH): `cli_commands/doctor.py:21-23` (`if args.output_json: print(...); return 0`) vs the text path returning 1 on failure (`:36-38`). Live: failing report → `--json` exit 0, text exit 1. The `python -m picosentry._core.doctor` entry does it right (`_core/doctor.py:358-360`). No test exercises the `--json` path. Adjacent to WO-024's doctor coverage gap but a distinct defect.
2. **action.yml declares a `format` input that is silently ignored**: input declared (`action.yml:16-19`, "json, sarif, cyclonedx") but `--format sarif` hardcoded (`:42`); `inputs.format` referenced nowhere. `format: json` users get SARIF silently.
3. **action.yml + GitLab template report "0 findings" when SARIF fails to parse**: `FINDINGS_COUNT=$(python3 -c …) 2>/dev/null || echo "0"` (`action.yml:59`; `ci-templates/gitlab-picosentry.yml:18` identical) — malformed SARIF → fail-on-findings never trips → the weekly security scan goes permanently green-blind. The forbidden `|| echo`-to-green class.
4. **verify-release attestation step cannot fail**: `verify-release.yml:107-115` — digest extraction failure skips verification; `gh attestation verify … || echo "ceiling: …"` swallows real verification failures along with "not yet available". (Same workflow's version assertions DO have teeth.)
5. **`picosentry health` scan check never imports the engine**: `cli_commands/health.py:21-24` uses `importlib.util.find_spec` (locates the file; broken imports still pass) while sibling checks do real imports — "engine importable" overclaims.
6. **doctor `fixture_count` check verifies almost nothing** (`_core/doctor.py:133-139`): counts 5 subdirectories (detail says "4"), passes unconditionally on any dirs existing; experimental.py's "5673 (3431 pos / 2235 neg)" phrasing is arithmetically confusing (5666 + 7 tricky).
7. **`tests/test_doctor.py:200,210` accept both pass and fail exit codes** (`assert result.returncode in (0, 1)`) — crash-detection teeth only.

## Deliverables
1. `--json` exits 1 on failure (+ test); health check does a real import; fixture_count counts fixtures and cross-checks experimental claims.
2. Honor or remove the `format` input; SARIF parse failure hard-fails (both action and GitLab template).
3. Attestation step fails on verification failure (keep explicit skip only for provable "not attested yet").
4. Give the doctor tests real assertions.
5. (Folded from WO4.0.0-024) Unified-CLI wrapper consolidation: `check` + `cluster` hand-duplicate inner argparse (the drift class that already bit once) — reuse inner `add_arguments` like `picosentry scan` does; `picosentry check --help` must equal `python -m picosentry.scan check --help`.
6. (Folded from WO4.0.0-024) GitLab template exit-map: only exit 2 is treated as error — scan exits 3 (timeout)/4 (rule error)/5 (corpus age) pass silently with stale counts.
7. (Folded from WO4.0.0-024) Doctor coverage: watch rules-corpus check (`load_errors`), optional-extras presence vs COMPONENT_STATUS (the pynacl-silent-degrade class), version-consistency adds `serve.config.version` + helm.
8. (Folded from WO4.0.0-024) Riders: watch blocked-prompt exit-2 collision vs argparse convention (decision); serve falsy-zero flags ignored (serve.py:72-79); helm Chart.yaml stale URLs; GHA docker cache on push-tier jobs (bake hcl defines it, only release uses bake).
