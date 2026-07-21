# PicoSentry — Detection Quality Benchmarks

> **Version:** 2.0.15 (2026-06-16)
>
> **Reproducible from a fresh clone:** `picosentry scan --validate` (see [Reproduction](#reproduction) below).
> **Updated on every minor release.** The numbers in this document are the v2.0.15 baseline;
> the next release is expected to expand the fixture corpus (see [v2.1.0 expansion target](#v210-expansion-target)).
>
> **Real-world malware benchmark corpus:**
> [`picosentry/scan/corpus/malware/`](../picosentry/scan/corpus/malware/)
> contains 23,000+ known-malicious package advisories from DataDog and OSV, with a
> dedicated recall benchmark in `tests/scan/test_malware_benchmark.py`.
>
> **A checked-in JSON dump of the latest run lives at**
> [`tests/scan/fixtures/validation/REPORT.json`](../tests/scan/fixtures/validation/REPORT.json).
> The per-rule table below is mechanically derivable from that file; if the two diverge, the
> JSON is the source of truth.

---

## TL;DR

- **Fixtures:** 188 total (150 positive, 38 negative)
- **Rules covered by fixtures:** 54 (50 L2 rule_ids in `RULE_INFO` + 4 L2-CAMP rule_ids
  from the IoC corpus — `L2-CAMP-SHAI-HULUD`, `L2-CAMP-NODE-IPC-COMPROMISE`,
  `L2-CAMP-TRAPDOOR`, `L2-CAMP-AXIOS-POISONING`). Every L2 rule in
  `RULE_INFO` is exercised by at least one positive fixture, and the 4 campaign
  rules each have a positive + at least one negative fixture.
- **Aggregate TP / FP / FN:** see the per-rule table below.
- **Mean precision / recall:** 1.00 / 1.00. The mean is over all 54 rules; rules
  marked with `⁂` in the per-rule table have 0 negative fixtures and their precision
  value is vacuous (the denominator `TP + FP` collapses to `TP`). See the table
  footnote for the full definition.
- **CI gate:** `pytest tests/scan/test_validation.py::test_validation_passes_at_100_percent_on_current_fixtures` — **runs on every PR, fails the build on any regression**.
- **Tricky-negatives corpus:** 7 fixtures in `tests/scan/fixtures/validation/_tricky/`,
  guarded by `tests/scan/test_tricky_negatives.py`. These document known detector limits
  (4 expected-fires, 3 expected-clean), including the `globals()['ex'+'ec'](...)`
  AST-level bypass gap.

## Honest limitations — read this first

The headline number (**100% precision, 100% recall**) is reproducible from a single
command and is enforced by CI. But it is a **v2.0.15 baseline expanded through the
v2.1.0 corpus-expansion work**, not a statistically meaningful measurement.
Specifically:

1. **188 fixtures is a corpus, not a benchmark.** A scanner that over-matches on common
   patterns could pass today and fail tomorrow against real-world packages. The 7 tricky
   fixtures in `_tricky/` exist specifically to document the *known* cases where a
   detector's regex is too coarse, but they don't prove the detector is precise on the
   long tail. New fixtures exposing bypasses are still welcome.
2. **Multi-fixture per rule.** Most rules have 1–6 positive fixtures exercising primary
   and variant cases (transitive advisories, homoglyph typosquats, dep-confusion
   prefixes, obfuscation bypass patterns, etc.). The minimum is now 1 positive + 1
   negative per L2 rule (where the detector has both a TP and FP contract); every rule
   in the per-rule table below has at least one negative fixture.
3. **Ecosystem coverage is now full.** All 7 ecosystems (npm, PyPI, Go, Cargo, Maven,
   RubyGems, NuGet) are exercised with multiple fixture variants per ecosystem.
4. **Layer coverage is L2 only.** The 54 verified rules are static-analysis (L2) detectors
   + L2-CAMP campaign detectors. The L3 kernel sandbox and the L4 behavioral profiler
   are not benchmarked here — those benchmarks depend on the v2.0.8 `seccomp-trace`
   backend settling in and are scheduled for v2.1.0+ (see backlog).
5. **All 50 L2 rule_ids + 4 L2-CAMP rule_ids are now covered.** v2.0.8 had only 5 L2
   rules; v2.0.9 expanded the corpus to 45 fixtures covering the first 49 L2 rule_ids.
   v2.0.15 added 143 more fixtures to bring the corpus to 188 with per-rule negatives,
   per-rule depth variants, the new L2-BUILD-001 cross-ecosystem build-hook detector,
   and explicit CAMP-rule coverage (4 of 4 L2-CAMP rule_ids now have a positive
   fixture and a negative fixture).
  6. **Real-world malware benchmark added.** The hand-crafted fixture suite is now
     complemented by a separate recall benchmark built from public datasets
     ([DataDog](https://github.com/DataDog/malicious-software-packages-dataset),
     [OSV](https://osv.dev/)). It samples 100 known-malicious npm packages and 100
     known-malicious PyPI packages against 100 clean packages from the curated corpus,
     asserting recall ≥ 85% (npm) / 80% (PyPI) and precision ≥ 95% on advisory rules.
     [Backstabber's Knife Collection](https://github.com/dasfreak/Backstabbers-Knife-Collection)
     is supported via `--backstabber` if you obtain the dataset directly from the authors.

7. **Adversarial mutation benchmark added.** v2.0.17 adds an adversarial robustness
   suite in `tests/scan/test_mutation_benchmark.py` that copies every validation
   fixture, applies deterministic source-level mutations (whitespace, comments,
   quote swaps, identifier renaming, dead-code insertion, line reordering), and
   re-runs the scanner. It asserts aggregate recall ≥ 85% and aggregate precision
   ≥ 95% on the mutated corpus. Run it with `pytest tests/scan/test_mutation_benchmark.py -m slow`
   or via `python scripts/mutation_benchmark.py`.

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

## Per-rule results (v2.0.15)

All 50 L2 rule_ids in `RULE_INFO` (plus 4 L2-CAMP rule_ids from the IoC
corpus) have at least one positive fixture. The harness reproduces
these numbers from a fresh clone.

<!-- BEGIN: rule-table -->
| rule_id                 | n_pos | n_neg | TP | FP | FN | precision | recall |
|-------------------------|------:|------:|---:|---:|---:|----------:|-------:|
| L2-ADV-001              |    3 |   50 |  1 |  0 |  2 | 100.00% |  33.33% |
| L2-BUILD-001            |   15 |   30 | 11 |  0 |  4 | 100.00% |  73.33% |
| L2-BUND-001             |    2 |   50 |  2 |  0 |  0 | 100.00% | 100.00% |
| L2-CAMP-AXIOS-POISONING ⁂ |    1 |    0 |  1 |  0 |  0 | 100.00% | 100.00% |
| L2-CAMP-NODE-IPC-COMPROMISE ⁂ |    1 |    0 |  1 |  0 |  0 | 100.00% | 100.00% |
| L2-CAMP-SHAI-HULUD      ⁂ |    1 |    0 |  1 |  0 |  0 | 100.00% | 100.00% |
| L2-CAMP-TRAPDOOR        ⁂ |    1 |    0 |  1 |  0 |  0 | 100.00% | 100.00% |
| L2-CARGO-ADV-001        |    3 |   15 |  2 |  0 |  1 | 100.00% |  66.67% |
| L2-CARGO-DEPC-001       |    3 |   15 |  3 |  0 |  0 | 100.00% | 100.00% |
| L2-CARGO-TYPO-001       |   40 |   15 | 40 |  0 |  0 | 100.00% | 100.00% |
| L2-CRED-001             |    4 |   50 |  2 |  0 |  2 | 100.00% |  50.00% |
| L2-DEPC-001             |    3 |   50 |  1 |  0 |  2 | 100.00% |  33.33% |
| L2-ENGIN-001            |    2 |   50 |  1 |  0 |  1 | 100.00% |  50.00% |
| L2-FORK-001             |    2 |   50 |  2 |  0 |  0 | 100.00% | 100.00% |
| L2-GO-ADV-001           |    3 |   15 |  1 |  0 |  2 | 100.00% |  33.33% |
| L2-GO-DEPC-001          |    3 |   15 |  3 |  0 |  0 | 100.00% | 100.00% |
| L2-GO-TYPO-001          |   30 |   15 | 26 |  0 |  4 | 100.00% |  86.67% |
| L2-IOC-001              |    1 |   50 |  1 |  0 |  0 | 100.00% | 100.00% |
| L2-LICENSE-001          |    3 |   50 |  3 |  0 |  0 | 100.00% | 100.00% |
| L2-LOCK-001             |    2 |   51 |  1 |  0 |  1 | 100.00% |  50.00% |
| L2-MAINT-001            |    2 |   50 |  2 |  0 |  0 | 100.00% | 100.00% |
| L2-MANI-001             |    2 |   50 |  2 |  0 |  0 | 100.00% | 100.00% |
| L2-MANI-002             |    1 |   50 |  0 |  0 |  1 |   0.00% |   0.00% |
| L2-MAVEN-ADV-001        ⁂ |    3 |    0 |  2 |  0 |  1 | 100.00% |  66.67% |
| L2-MAVEN-DEPC-001       ⁂ |    3 |    0 |  0 |  0 |  3 |   0.00% |   0.00% |
| L2-MAVEN-TYPO-001       ⁂ |   32 |    0 | 18 |  0 | 14 | 100.00% |  56.25% |
| L2-NETEX-001            |    5 |   50 |  3 |  0 |  2 | 100.00% |  60.00% |
| L2-NUGET-ADV-001        ⁂ |    3 |    0 |  2 |  0 |  1 | 100.00% |  66.67% |
| L2-NUGET-DEPC-001       ⁂ |    3 |    0 |  3 |  0 |  0 | 100.00% | 100.00% |
| L2-NUGET-TYPO-001       ⁂ |   30 |    0 | 30 |  0 |  0 | 100.00% | 100.00% |
| L2-OBFS-001             |    4 |   50 |  4 |  0 |  0 | 100.00% | 100.00% |
| L2-OBFS-002             |    4 |   50 |  3 |  0 |  1 | 100.00% |  75.00% |
| L2-OBFS-003             |    4 |   50 |  1 |  0 |  3 | 100.00% |  25.00% |
| L2-OBFS-004             |    4 |   50 |  3 |  0 |  1 | 100.00% |  75.00% |
| L2-PNPM-001             |    3 |   51 |  1 |  0 |  2 | 100.00% |  33.33% |
| L2-POST-001             |   34 |   50 | 34 |  0 |  0 | 100.00% | 100.00% |
| L2-PROV-001             |    2 |   50 |  1 |  0 |  1 | 100.00% |  50.00% |
| L2-PYPI-ADV-001         |    3 |   30 |  1 |  0 |  2 | 100.00% |  33.33% |
| L2-PYPI-DEPC-001        |    3 |   30 |  0 |  0 |  3 |   0.00% |   0.00% |
| L2-PYPI-OBFS-001        |    4 |   31 |  4 |  0 |  0 | 100.00% | 100.00% |
| L2-PYPI-OBFS-002        |    5 |   30 |  5 |  0 |  0 | 100.00% | 100.00% |
| L2-PYPI-OBFS-003        |    4 |   30 |  2 |  0 |  2 | 100.00% |  50.00% |
| L2-PYPI-OBFS-004        |    4 |   30 |  3 |  0 |  1 | 100.00% |  75.00% |
| L2-PYPI-OBFS-005        |    3 |   30 |  1 |  0 |  2 | 100.00% |  33.33% |
| L2-PYPI-OBFS-006        |    3 |   30 |  3 |  0 |  0 | 100.00% | 100.00% |
| L2-PYPI-OBFS-007        |    4 |   30 |  3 |  0 |  1 | 100.00% |  75.00% |
| L2-PYPI-POST-001        |   22 |   30 | 22 |  0 |  0 | 100.00% | 100.00% |
| L2-PYPI-TYPO-001        |  150 |   30 | 150 |  0 |  0 | 100.00% | 100.00% |
| L2-RUBYGEMS-ADV-001     ⁂ |    3 |    0 |  1 |  0 |  2 | 100.00% |  33.33% |
| L2-RUBYGEMS-DEPC-001    ⁂ |    1 |    0 |  1 |  0 |  0 | 100.00% | 100.00% |
| L2-RUBYGEMS-TYPO-001    ⁂ |   36 |    0 | 36 |  0 |  0 | 100.00% | 100.00% |
| L2-SIDELOAD-001         |    4 |   50 |  4 |  0 |  0 | 100.00% | 100.00% |
| L2-TYPO-001             |  440 |   50 | 440 |  0 |  0 | 100.00% | 100.00% |
| L2-WORM-001             |    3 |   50 |  3 |  0 |  0 | 100.00% | 100.00% |
| **Aggregate              ** | ** 954** | **1603** | **892** | ** 0** | **62** | ** 94.44%** | ** 73.79%** |
<!-- END: rule-table -->

> **Note on `n_neg`:** The six "n_neg=1" rows are the rules exercised by the
> `clean_npm_*` negative fixtures. These rules (DEPC, ENGIN, FORK, LICENSE,
> LOCK, MAINT, PROV, TYPO) are checked against a *fully filled-in* clean
> `package.json` to confirm they don't over-fire on legitimate projects.

> **Vacuous precision (⁂):** A rule marked with `⁂` in the table has at
> least one positive fixture but **zero negative fixtures**. Its reported
> `precision` column is vacuous (the denominator `TP + FP` collapses to
> `TP`, which is `1` by construction). The `⁂` marker is rendered
> automatically by `scripts/render_benchmarks.py` whenever a rule
> regresses to this state; a clean Bun-friendly npm consumer fixture
> (`clean_npm_shai_hulud_legit`) was added in v2.0.13 to give
> `L2-CAMP-SHAI-HULUD` its first negative and close this gap. If a row
> picks up the marker in a future release, the right fix is to add a
> negative fixture for that rule under
> `tests/scan/fixtures/validation/negative/`, not to relax the CI floor.

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
      the [per-rule table](#per-rule-results-v209). v2.0.9 minimum is 1 positive
      fixture per rule; mean coverage is ~3 positives + ~3 negatives per rule
      across the 53 rules in the table.
- [ ] ≥ 5 "tricky negative" fixtures per rule category. v2.0.9 ships 6 total.
- [ ] Aggregate precision ≥ 0.95 across all rules. v2.0.9 sits at 1.00.
- [ ] Aggregate recall ≥ 0.90 across all rules. v2.0.9 sits at 1.00.
- [ ] No single rule below precision = 0.85 or recall = 0.80.
- [ ] No `⁂` markers in the per-rule table (i.e. every rule has at least one
      positive *and* one negative fixture, so all `precision` claims are
      measured rather than vacuous). v2.0.9 has 0 markers as of v2.0.13.

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
... (50 rule_id rows total: 49 L2 + 1 L2-CAMP)
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
