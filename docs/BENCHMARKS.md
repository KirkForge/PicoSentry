# PicoSentry — Detection Quality Benchmarks

> **Version:** 2.0.8 (2026-06-06)
>
> **Reproducible from a fresh clone:** `picosentry scan --validate` (see [Reproduction](#reproduction) below).
> **Updated on every minor release.** The numbers in this document are the v2.0.8 baseline;
> the next release is expected to expand the fixture corpus (see [v2.0.9 expansion target](#v209-expansion-target)).
>
> **A checked-in JSON dump of the latest run lives at**
> [`tests/scan/fixtures/validation/REPORT.json`](../tests/scan/fixtures/validation/REPORT.json).
> The per-rule table below is mechanically derivable from that file; if the two diverge, the
> JSON is the source of truth.

---

## TL;DR

- **Fixtures:** 7 total (3 positive, 4 negative)
- **Rules covered by fixtures:** 5
- **Aggregate TP / FP / FN:** 5 / 0 / 0
- **Mean precision / recall:** 1.00 / 1.00
- **CI gate:** `pytest tests/scan/test_validation.py::test_validation_passes_at_100_percent_on_current_fixtures` — **runs on every PR, fails the build on any regression**.

## Honest limitations — read this first

The headline number (**100% precision, 100% recall**) is reproducible from a single
command and is enforced by CI. But it is a **v0.1 baseline**, not a statistically
meaningful measurement. Specifically:

1. **7 fixtures is small.** A scanner that over-matches on common patterns (e.g.
   the substring `exec(`) could pass today and fail tomorrow against 30 real-world
   packages. The current corpus is a smoke test, not a benchmark.
2. **Negative fixtures are coarse.** `clean_npm_app` is a single Express app;
   `clean_pypi_lib` is a single `pyproject.toml`. There is exactly one negative
   fixture per ecosystem exercised.
3. **Ecosystem coverage is partial.** All 3 positive fixtures are npm + PyPI; Go,
   Cargo, Maven, RubyGems, and NuGet are **not exercised** by the corpus.
4. **Layer coverage is L2 only.** The 5 verified rules are static-analysis (L2)
   detectors. The L3 kernel sandbox and the L4 behavioral profiler are not
   benchmarked here — those benchmarks depend on the v2.0.8 `seccomp-trace`
   backend settling in and are scheduled for v2.0.9+ (see backlog).
5. **Of 49 L2 rules in the registry, only 5 have fixtures.** 44 L2 rules have
   no positive or negative fixture and are **unverified**; the table below
   enumerates them.

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

---

## Per-rule results (v2.0.8)

These are the 5 rules that have at least one positive fixture. The harness
reproduces these numbers from a fresh clone.

| rule_id             | n_pos | n_neg | TP | FP | FN | precision | recall |
|---------------------|------:|------:|---:|---:|---:|----------:|-------:|
| L2-CAMP-SHAI-HULUD  |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-CRED-001         |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-POST-001         |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-OBFS-007    |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| L2-PYPI-POST-001    |     1 |     0 |  1 |  0 |  0 |      1.00 |   1.00 |
| **Aggregate**       | **3** | **4** | **5** | **0** | **0** | **1.00** | **1.00** |

### Per-fixture outcome (v2.0.8)

| fixture                       | label    | outcome | rules fired                                                          |
|-------------------------------|----------|---------|----------------------------------------------------------------------|
| malicious_npm_postinstall     | positive | PASS    | L2-POST-001, L2-CRED-001                                             |
| malicious_pypi                | positive | PASS    | L2-PYPI-POST-001, L2-PYPI-OBFS-007                                   |
| shai_hulud_named_signature    | positive | PASS    | L2-CAMP-SHAI-HULUD                                                    |
| clean_cargo_lib               | negative | PASS    | (no findings)                                                        |
| clean_go_module               | negative | PASS    | (no findings)                                                        |
| clean_npm_app                 | negative | PASS    | (no findings)                                                        |
| clean_pypi_lib                | negative | PASS    | (no findings)                                                        |

---

## Rules without fixtures (unverified)

These rules ship in 2.0.8 but have **no** positive or negative fixture in the
corpus. They are unverified — the rule code is present in `picosentry/scan/rules/`
and registered in the engine, but no test package exists that exercises it.
This list is curated from `picosentry/scan/rules/__init__.py::RULE_INFO` and
`::RULE_ID_ALIASES`.

| rule_id              | category     | severity | detector module                                |
|----------------------|--------------|----------|------------------------------------------------|
| L2-ADV-001           | vulnerability| HIGH     | `advisory_check.py`                            |
| L2-BUND-001          | dependency   | HIGH     | `bundled_shadow.py`                            |
| L2-CARGO-ADV-001     | vulnerability| HIGH     | `advisory_check.py` (cargo alias)              |
| L2-CARGO-DEPC-001    | dependency   | CRITICAL | `dep_confusion.py` (cargo alias)               |
| L2-CARGO-TYPO-001    | typosquat    | HIGH     | `typosquat.py` (cargo alias)                   |
| L2-DEPC-001          | dependency   | HIGH     | `dep_confusion.py` (npm alias)                 |
| L2-ENGIN-001         | compatibility| MEDIUM   | `engine.py`                                    |
| L2-FORK-001          | provenance   | MEDIUM   | `fork_drift.py`                                |
| L2-GO-ADV-001        | vulnerability| HIGH     | `advisory_check.py` (go alias)                 |
| L2-GO-DEPC-001       | dependency   | CRITICAL | `dep_confusion.py` (go alias)                  |
| L2-GO-TYPO-001       | typosquat    | HIGH     | `typosquat.py` (go alias)                      |
| L2-IOC-001           | supply-chain | HIGH     | `ioc_detection.py`                             |
| L2-LICENSE-001       | compliance   | MEDIUM   | `license.py`                                   |
| L2-LOCK-001          | lockfile     | MEDIUM   | `lockfile_drift.py`                            |
| L2-MAINT-001         | maintainer   | MEDIUM   | `maintainer_change.py`                         |
| L2-MANI-001          | manifest     | MEDIUM   | `manifest.py`                                  |
| L2-MANI-002          | manifest     | HIGH     | `manifest.py`                                  |
| L2-MAVEN-ADV-001     | vulnerability| HIGH     | `advisory_check.py` (maven alias)              |
| L2-MAVEN-DEPC-001    | dependency   | CRITICAL | `dep_confusion.py` (maven alias)               |
| L2-MAVEN-TYPO-001    | typosquat    | HIGH     | `typosquat.py` (maven alias)                   |
| L2-NETEX-001         | supply-chain | CRITICAL | `network_exfil.py`                             |
| L2-NUGET-ADV-001     | vulnerability| HIGH     | `advisory_check.py` (nuget alias)              |
| L2-NUGET-DEPC-001    | dependency   | CRITICAL | `dep_confusion.py` (nuget alias)               |
| L2-NUGET-TYPO-001    | typosquat    | HIGH     | `typosquat.py` (nuget alias)                   |
| L2-OBFS-001          | obfuscation  | CRITICAL | `obfuscation.py`                               |
| L2-OBFS-002          | obfuscation  | HIGH     | `obfuscation.py`                               |
| L2-OBFS-003          | obfuscation  | CRITICAL | `obfuscation.py`                               |
| L2-OBFS-004          | obfuscation  | HIGH     | `obfuscation.py`                               |
| L2-PNPM-001          | lockfile     | MEDIUM   | `pnpm_config.py`                               |
| L2-PROV-001          | provenance   | LOW      | `provenance.py`                                |
| L2-PYPI-ADV-001      | vulnerability| HIGH     | `advisory_check.py` (pypi alias)               |
| L2-PYPI-DEPC-001     | dependency   | CRITICAL | `dep_confusion.py` (pypi alias)                |
| L2-PYPI-OBFS-001     | obfuscation  | CRITICAL | `pypi_obfuscation.py`                          |
| L2-PYPI-OBFS-002     | obfuscation  | HIGH     | `pypi_obfuscation.py`                          |
| L2-PYPI-OBFS-003     | obfuscation  | HIGH     | `pypi_obfuscation.py`                          |
| L2-PYPI-OBFS-004     | obfuscation  | HIGH     | `pypi_obfuscation.py`                          |
| L2-PYPI-OBFS-005     | obfuscation  | CRITICAL | `pypi_obfuscation.py`                          |
| L2-PYPI-OBFS-006     | obfuscation  | CRITICAL | `pypi_obfuscation.py`                          |
| L2-PYPI-TYPO-001     | typosquat    | HIGH     | `typosquat.py` (pypi alias)                    |
| L2-RUBYGEMS-ADV-001  | vulnerability| HIGH     | `advisory_check.py` (rubygems alias)           |
| L2-RUBYGEMS-DEPC-001 | dependency   | CRITICAL | `dep_confusion.py` (rubygems alias)            |
| L2-RUBYGEMS-TYPO-001 | typosquat    | HIGH     | `typosquat.py` (rubygems alias)                |
| L2-SIDELOAD-001      | dependency   | HIGH     | `sideloading.py`                               |
| L2-TYPO-001          | typosquat    | HIGH     | `typosquat.py` (npm alias)                     |
| L2-WORM-001          | supply-chain | CRITICAL | `worm_propagation.py`                           |

---

## v2.0.9 expansion target

These are the acceptance criteria for the next release. Each is something
the corpus can be measured against, not aspirational language.

- [ ] ≥ 30 fixtures per rule (positive + negative combined), for **every** rule in
      the [unverified list](#rules-without-fixtures-unverified). The current 5
      rules can stay at their current count.
- [ ] ≥ 5 ecosystems exercised (npm, PyPI, Go, Cargo, Maven minimum). Today:
      npm, PyPI only.
- [ ] ≥ 5 "tricky negative" fixtures designed to *fool* the scanner — e.g. a
      benign package that uses `exec(compile(...))` to dodge the obfuscation
      rules, a clean package that happens to read `/etc/hosts`, a package with
      a typosquat on a low-popularity name (not in the top-327 corpus).
- [ ] Aggregate precision ≥ 0.95 across all rules.
- [ ] Aggregate recall ≥ 0.90 across all rules.
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
5. Update the [per-rule table](#per-rule-results-v208) and re-run the harness
   to refresh `tests/scan/fixtures/validation/REPORT.json`.
6. Open a PR. The CI gate will fail if your fixture is misclassified.

If a fixture fires a rule that is **not** in your `expected_rule_ids` (for
positive fixtures) or fires *any* rule (for negative fixtures), the harness
will report it and the CI gate will fail. The fix is to either update the
expected rule list (if the new rule firing is correct) or the rule code (if
it is a false positive).

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
fixtures: 7 (3 pos / 4 neg) | mean precision: 100.00% | mean recall: 100.00% | fixture failures: 0 | passes: True
rule_id                    tp   fp   fn     prec   recall
---------------------------------------------------------
L2-CAMP-SHAI-HULUD          1    0    0 100.00% 100.00%
L2-CRED-001                 1    0    0 100.00% 100.00%
L2-POST-001                 1    0    0 100.00% 100.00%
L2-PYPI-OBFS-007            1    0    0 100.00% 100.00%
L2-PYPI-POST-001            1    0    0 100.00% 100.00%
```

To dump the report JSON (matches `tests/scan/fixtures/validation/REPORT.json`):

```bash
picosentry scan --validate --output tests/scan/fixtures/validation/REPORT.json
```

---

## Out of scope (deferred)

- **L3 sandbox syscall-trace benchmarks** — depends on the v2.0.8 `seccomp-trace`
  backend settling in. Tracked as P1 in the project hardening backlog.
- **L4 behavioral-analysis benchmarks** — depends on the v2.0.8 trace events
  settling in. Deferred to v2.0.10.
- **Cross-language LLM-generated fixture expansion** — gated on the
  fixture-authoring review process. Deferred to v2.0.11+.
- **Auto-generating this document from the JSON dump at release time** —
  nice-to-have; v2.0.10 candidate.
