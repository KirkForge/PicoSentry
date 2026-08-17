# WO4.0.0-008 — Scan: detection quality (recall recovery + FP gating + honest card)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (verified 2026-08-17, shipped in v2.1.2 — npm metadata FPs gated on install-scripts/installed-deps (rules/engine.py:47-73), PYPI underscore prefixes (_dep_confusion_config.py:207-211) + npm internal scope words (dep_confusion.py:219-226), rubygems corpus shipped + fixtures regenerated (93360edb), completeness honesty on timeout (models.py:234-237), unknown-rule-expectation warning (cli_service.py:714-720), dead-code swept (1c724a53), card re-baselined 100.00/90.87 (docs/model-card.md:41-42))
**Owner:** (unassigned — worktree `wo/4.0.0/detection-quality`)
**Priority:** P0 · Effort L · Risk M
**Scope:** `picosentry/scan/rules/{_dep_confusion_config.py,dep_confusion.py,engine.py,fork_drift.py,license.py,maintainer_change.py,provenance.py}`, `picosentry/scan/corpus/`, `picosentry/scan/models.py` (completeness rider), `scripts/{expand_corpus_to_6k.py,generate_corpus_fixtures.py}`, `tests/scan/fixtures/**/fixture.json`, `docs/model-card.md`

**Gate:** `uv run picosentry scan --validate --output /tmp/r.json` → mean_recall ≥ 0.85 AND mean_precision ≥ 0.95 (from 0.7279/0.8492) with zero silent skips; `bash scripts/test.sh fast`; card re-baselined once, root-cause narrative corrected.

## Objective
Recover the ~700 FNs and kill the 6050 metadata FPs whose root causes the exploration round verified — then re-baseline the card with a truthful narrative.

## Evidence (verified live against REPORT.json + rule runs 2026-08-17)
**FPs (precision 0.8492 → the 0.95 target):**
1. 5 npm metadata rules × 1210 FPs each: informational LOW branches fire on ANY sparse manifest — "no engines" else-branch (rules/engine.py:69-87), fork_drift.py:168-185, license.py:185, maintainer_change.py:258, provenance.py:41,60,103,123. `basic-npm-lib_*` clean fixtures legitimately lack metadata.

**FNs (recall 0.7279 → the 0.85 target):**
2. L2-PYPI-DEPC-001 (75 FN): `_PYPI_CONFIG` uses hyphen-only prefixes (_dep_confusion_config.py:198-203); PyPI convention is underscores — `company_auth` not recognized though the shared pattern list has `company[_-]`. One config line.
3. L2-DEPC-001 (152 FN): npm branch recognizes only `@internal/`+`@private/` scopes (dep_confusion.py:218,497-507); fixtures use `@company/billing`. Unscoped internal-looking names never pattern-checked for npm (go/cargo/pypi branches do).
4. Typosquat FNs are corpus-content mismatches, not edit-distance limits: `rubygems_top_packages.json` doesn't ship at all (all 6 other ecosystems have one); nuget/maven corpora lack the target names; ~93 fixtures encode the typo as the project's OWN module name with zero deps — structurally unscannable, must be regenerated as dependency-based.
5. L2-CVE-001 (115 FN) doesn't exist; fixtures are direct deps for which `L2-MAVEN-ADV-001` fires — expected-id fix or documented alias. 32 more fixtures expect nonexistent `L2-NPM-OBFS/POST-001` (actual ids lack NPM). MAVEN-ADV transitive FNs (17) = genuine feature gap (transitive resolution), document as ceiling.
6. The model-card root-cause narrative (incl. the 2026-08-17 re-baseline note's "ecosystem-id expectations" framing) is partly WRONG — correct it with the verified causes above.

**Riders:** `scan_completeness` says "complete" on timeout (models.py:234 checks only "failed"); `--fail-on-rule-error` blind to timeouts; fixture-loader warning for unknown expected_rule_ids (would have caught CVE/NPM-*); dead-code sweep (crypto.py:49 always-True, RULE_TIMEOUT_SECONDS unused, campaigns no-op, `_advisory_db_cache` unbounded, fleet corrupt-load clobber).

## Deliverables
1. Gate the 5 metadata rules on risk signals (install scripts present / inside node_modules / non-root dep) or policy-opt-in.
2. Config/scope fixes (findings 2-3); ship rubygems corpus; align generator package lists; regenerate own-name fixtures as dependency-based; fix expected ids (4-5).
3. Completeness honesty + loader unknown-rule warning + dead-code sweep.
4. Single honest card re-baseline from a fresh REPORT.json.
