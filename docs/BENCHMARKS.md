# PicoSentry — Detection Quality Benchmarks

> **Version:** 2.0.9 (2026-06-06)
>
> **Reproducible from a fresh clone:** `picosentry scan --validate` (see [Reproduction](#reproduction) below).
> **Updated on every minor release.** The numbers in this document are the v2.0.9 baseline;
> the next release is expected to expand the fixture corpus (see [v2.1.0 expansion target](#v210-expansion-target)).
>
> **A checked-in JSON dump of the latest run lives at**
> [`tests/scan/fixtures/validation/REPORT.json`](../tests/scan/fixtures/validation/REPORT.json).
> The per-rule table below is mechanically derivable from that file; if the two diverge, the
> JSON is the source of truth.

---

## TL;DR

- **Fixtures:** 45 total (39 positive, 6 negative)
- **Rules covered by fixtures:** 50 (all 49 L2 rule_ids + the 5 L2 campaign rules; every L2
  rule in `RULE_INFO` is exercised by at least one positive fixture)
- **Aggregate TP / FP / FN:** 50 / 0 / 0
- **Mean precision / recall:** 1.00 / 1.00
- **CI gate:** `pytest tests/scan/test_validation.py::test_validation_passes_at_100_percent_on_current_fixtures` — **runs on every PR, fails the build on any regression**.
- **Tricky-negatives corpus:** 6 fixtures in `tests/scan/fixtures/validation/_tricky/`,
  guarded by `tests/scan/test_tricky_negatives.py`. These document known detector limits
  (3 expected-fires, 3 expected-clean).

## Honest limitations — read this first

The headline number (**100% precision, 100% recall**) is reproducible from a single
command and is enforced by CI. But it is a **v2.0.9 baseline**, not a statistically
meaningful measurement. Specifically:

1. **45 fixtures is small.** A scanner that over-matches on common patterns could pass
   today and fail tomorrow against 30 real-world packages. The current corpus is a smoke
   test, not a benchmark. The 6 tricky fixtures in `_tricky/` exist specifically to
   document the *known* cases where a detector's regex is too coarse, but they don't
   prove the detector is precise on the long tail.
2. **One fixture per rule.** Most rules have exactly one positive fixture exercising their
   primary case. Multi-rule combined fixtures and edge cases (e.g. multi-version ranges,
   scoped-name variants) are deferred to v2.1.0.
3. **Ecosystem coverage is now full.** All 7 ecosystems (npm, PyPI, Go, Cargo, Maven,
   RubyGems, NuGet) are exercised. v2.0.8 had only npm and PyPI; v2.0.9 added 5 more.
4. **Layer coverage is L2 only.** The 50 verified rules are static-analysis (L2) detectors.
   The L3 kernel sandbox and the L4 behavioral profiler are not benchmarked here — those
   benchmarks depend on the v2.0.8 `seccomp-trace` backend settling in and are scheduled
   for v2.1.0+ (see backlog).
5. **All 49 L2 rule_ids are now covered.** v2.0.8 had only 5; v2.0.9 expanded the corpus
   to 45 fixtures covering all 49 L2 rule_ids (50 unique rule metrics when the campaign
   rules like `L2-CAMP-SHAI-HULUD` are included).

The 100% floor exists so a *regression* breaks the build. It is not a claim that
the scanner is 100% accurate in production. If you find a package that PicoSentry
misses or over-matches on, please open an issue with the package URL and a
reproduction command — adding a fixture is the path to fixing it (see
[How to add fixtures](#how-to-add-fixtures)).

---

## Methodology

### The harness

`picosentry.scan.validation.run_validation()` (Python API) and
`picosentry scan --validate` (CLI) walk the `tests/scan/fixtures/validation/`
tree, run the scanner against every fixture, and compare the fired `rule_id`s
against the fixture's declared `expected_rule_ids`.

The full report shape is the `ValidationReport` dataclass in
`picosentry/scan/validation.py`. The CLI prints a fixed-width per-rule table
and exits 0 if mean precision ≥ 0.95 and mean recall ≥ 0.80, else 1. **The
0.95 / 0.80 thresholds are advisory** — the strict floor is the CI test
mentioned in the TL;DR.

### The fixture contract

Each fixture is a directory under `tests/scan/fixtures/validation/{positive,negative}/<name>/`
containing a `fixture.json` (not `.yaml` — note for contributors used to the
older draft) with this shape:

```json
{
  "label": "positive",
  "description": "Human-readable one-liner about what this fixture covers.",
  "expected_rule_ids": ["L2-PYPI-POST-001", "L2-PYPI-OBFS-007"]
}
```

- `label` is `"positive"` (known-malicious) or `"negative"` (known-clean).
- `expected_rule_ids` is required for positive fixtures and lists the `rule_id`s
  that **must** fire. Negative fixtures omit the field — any rule that fires
  on a negative fixture is a false positive.
- The fixture source files (`package.json`, `setup.py`, `Cargo.toml`, etc.)
  sit alongside `fixture.json` in the same directory.

### Scoring rules

- A positive fixture that fires every expected rule → **TP per expected rule**.
- A positive fixture that misses an expected rule → **FN per missing rule**.
- A negative fixture that fires *any* rule → **FP per rule that fired**.
- `precision = TP / (TP + FP)` and `recall = TP / (TP + FN)`, computed per
  rule_id across all fixtures.

The harness only scores **declared expectations**: an undeclared-but-fired
rule on a positive fixture is not counted as a TP. (This means the harness
under-counts TPs by design; the goal is to catch regressions on rules we
*claim* to detect.)

### The CI gate

`tests/scan/test_validation.py::test_validation_passes_at_100_percent_on_current_fixtures`
runs on every PR via `.github/workflows/ci.yml::test-scan`. It fails the
build if any fixture regresses. To raise the floor intentionally (e.g. as the
corpus grows), update both this test and the per-rule table below.

### The tricky-negatives corpus

`tests/scan/fixtures/validation/_tricky/` (note the leading underscore —
intentionally *not* picked up by `discover_fixtures()`) holds 6 fixtures
that document **known detector limits**. They are exercised by
`tests/scan/test_tricky_negatives.py` (6 tests) which asserts:

- 3 fixtures should fire a specific `rule_id` at the expected severity.
  These are the cases where the detector's regex is *intentionally*
  coarse — e.g. `L2-PYPI-OBFS-001` matches `exec(compile(...))` because
  `exec(` is a literal token, not a parsed AST.
- 3 fixtures should produce zero findings. These are the cases where the
  detector is *intentionally* silent — e.g. `L2-PYPI-OBFS-002` does not
  match `bytes.fromhex("...")` at runtime, only literal `\xNN` escape
  sequences in source.

Adding a new tricky fixture is the right move when you discover a case
where the detector's behavior is *correct in intent* but the regex is too
loose or too tight. The tricky tests guard against the limit silently
disappearing after a refactor.

---

## Per-rule results (v2.0.9)

All 49 L2 rule_ids in `RULE_INFO` (plus the 5 L2 campaign rule_ids from
`RULE_ID_ALIASES`) have at least one positive fixture. The harness
reproduces these numbers from a fresh clone.

| rule_id                 | n_pos | n_neg | TP | FP | FN | precision | recall |
|-------------------------|------:|------:|---:|---:|---:|----------:|-------:|
| L2-ADV-001              |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-BUND-001             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-CAMP-SHAI-HULUD      |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-CARGO-ADV-001        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-CARGO-DEPC-001       |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-CARGO-TYPO-001       |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-CRED-001             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-DEPC-001             |     1 |     1 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-ENGIN-001            |     1 |     1 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-FORK-001             |     1 |     1 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-GO-ADV-001           |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-GO-DEPC-001          |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-GO-TYPO-001          |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-IOC-001              |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-LICENSE-001          |     1 |     1 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-LOCK-001             |     1 |     1 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-MAINT-001            |     1 |     1 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-MANI-001             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-MANI-002             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-MAVEN-ADV-001        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-MAVEN-DEPC-001       |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-MAVEN-TYPO-001       |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-NETEX-001            |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-NUGET-ADV-001        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-NUGET-DEPC-001       |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-NUGET-TYPO-001       |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-OBFS-001             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-OBFS-002             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-OBFS-003             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-OBFS-004             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PNPM-001             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-POST-001             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PROV-001             |     1 |     1 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-ADV-001         |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-DEPC-001        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-OBFS-001        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-OBFS-002        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-OBFS-003        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-OBFS-004        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-OBFS-005        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-OBFS-006        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-OBFS-007        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-POST-001        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-TYPO-001        |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-RUBYGEMS-ADV-001     |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-RUBYGEMS-DEPC-001    |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-RUBYGEMS-TYPO-001    |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-SIDELOAD-001         |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-TYPO-001             |     1 |     1 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-WORM-001             |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| **Aggregate**           | **45** | **6** | **50** | **0** | **0** | **1.00** | **1.00** |

> **Note on `n_neg`:** The six "n_neg=1" rows are the rules exercised by the
> `clean_npm_*` negative fixtures. These rules (DEPC, ENGIN, FORK, LICENSE,
> LOCK, MAINT, PROV, TYPO) are checked against a *fully filled-in* clean
> `package.json` to confirm they don't over-fire on legitimate projects.

---

## Tricky-negatives corpus (`_tricky/`)

| fixture                              | assertion                      | rule_id(s)              | what it documents                                                  |
|--------------------------------------|--------------------------------|-------------------------|--------------------------------------------------------------------|
| `tricky_pypi_exec_compile`           | expected_fires                 | L2-PYPI-OBFS-001        | `exec(compile(...))` matches the literal `exec(` token             |
| `tricky_npm_reads_etc_hosts`         | expected_clean (zero findings) | —                       | `/etc/hosts` reads do NOT trigger CRED-001 or NETEX-001            |
| `tricky_typosquat_lowpop`            | expected_fires                 | L2-TYPO-001             | `l0dash` (edit dist 2) is caught despite low popularity            |
| `tricky_pypi_hex_buffer`             | expected_clean (zero findings) | —                       | `bytes.fromhex(...)` does NOT trigger L2-PYPI-OBFS-002             |
| `tricky_npm_dual_license`            | expected_clean (zero findings) | —                       | `(MIT OR Apache-2.0)` does NOT trigger L2-LICENSE-001             |
| `tricky_npm_git_dep_safe`            | expected_fires (MEDIUM)        | L2-WORM-001             | git-resolved dep without install script fires at MEDIUM not CRITICAL |

---

## v2.1.0 expansion target

These are the acceptance criteria for the next release. Each is something
the corpus can be measured against, not aspirational language.

- [ ] ≥ 30 fixtures per rule (positive + negative combined), for **every** rule in
      the [per-rule table](#per-rule-results-v209). v2.0.9 sits at 1 fixture per rule.
- [ ] ≥ 5 "tricky negative" fixtures per rule category. v2.0.9 ships 6 total.
- [ ] Aggregate precision ≥ 0.95 across all rules. v2.0.9 sits at 1.00.
- [ ] Aggregate recall ≥ 0.90 across all rules. v2.0.9 sits at 1.00.
- [ ] No single rule below precision = 0.85 or recall = 0.80.

When these are met, the floor in `test_validation_passes_at_100_percent_on_current_fixtures`
will be relaxed to the 0.95 / 0.80 advisory thresholds from the CLI.

---

## How to add fixtures

1. Create a directory under `tests/scan/fixtures/validation/positive/<name>/` or
   `tests/scan/fixtures/validation/negative/<name>/`.
2. Add `fixture.json` conforming to the contract in [Methodology](#methodology).
3. Add the package source under the same directory (typically a stripped
   directory with just the relevant files: `package.json` + the suspicious
   `.js` for npm, `setup.py` for PyPI, etc.).
4. Run `picosentry scan --validate` from the repo root to confirm the fixture
   is classified as expected and no other fixture regressed.
5. Update the [per-rule table](#per-rule-results-v209) and re-run the harness
   to refresh `tests/scan/fixtures/validation/REPORT.json`.
6. Open a PR. The CI gate will fail if your fixture is misclassified.

If a fixture fires a rule that is **not** in your `expected_rule_ids` (for
positive fixtures) or fires *any* rule (for negative fixtures), the harness
will report it and the CI gate will fail. The fix is to either update the
expected rule list (if the new rule firing is correct) or the rule code (if
it is a false positive).

For documenting **known detector limits** (cases where a detector is
correctly silent or correctly firing on a borderline pattern), drop the
fixture under `tests/scan/fixtures/validation/_tricky/<name>/` and add a
test to `tests/scan/test_tricky_negatives.py`. Tricky fixtures are
intentionally **not** in the strict CI gate.

---

## Reproduction

From a fresh clone:

```bash
git clone https://github.com/KirkForge/PicoSentry
cd PicoSentry
pip install -e ".[all,dev]"
picosentry scan --validate
```

Expected output (truncated):

```
fixtures: 45 (39 pos / 6 neg) | mean precision: 100.00% | mean recall: 100.00% | fixture failures: 0 | passes: True
rule_id                    tp   fp   fn     prec   recall
---------------------------------------------------------
L2-ADV-001                  1    0    0 100.00% 100.00%
L2-BUND-001                 1    0    0 100.00% 100.00%
L2-CAMP-SHAI-HULUD          1    0    0 100.00% 100.00%
L2-CARGO-ADV-001            1    0    0 100.00% 100.00%
L2-CARGO-DEPC-001           1    0    0 100.00% 100.00%
... (45 rule_id rows total)
```

To dump the report JSON (matches `tests/scan/fixtures/validation/REPORT.json`):

```bash
picosentry scan --validate --output tests/scan/fixtures/validation/REPORT.json
```

To run the tricky-negatives pytest:

```bash
pytest tests/scan/test_tricky_negatives.py -v
# Expected: 6 passed
```

---

## Out of scope (deferred)

- **30+/rule per rule** — requires the corpus-marketplace infrastructure
  that is a `❌ Stub` in `experimental.py`. v2.1.0 work.
- **Renaming `name` → `package_name` in the 7 existing IoC files** — the
  detector reads `package_name` but the existing 7 IoC files use `name`.
  This is a latent bug; the v2.0.9 `event_stream_malicious_336.json` IoC
  uses the correct key. The fix for the other 7 is a separate PR in
  v2.0.10 to keep the v2.0.9 blast radius small.
- **L3 sandbox syscall-trace benchmarks** — depends on the v2.0.8 `seccomp-trace`
  backend settling in. Tracked as P1 in the project hardening backlog.
- **L4 behavioral-analysis benchmarks** — depends on the v2.0.8 trace events
  settling in. Deferred to v2.0.10.
- **Cross-language LLM-generated fixture expansion** — gated on the
  fixture-authoring review process. Deferred to v2.0.11+.
- **Auto-generating this document from the JSON dump at release time** —
  nice-to-have; v2.0.10 candidate.
