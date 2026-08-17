# Detection Benchmarks — PicoSentry

> **These benchmarks are measured against a synthetic regression corpus, not real-world malware.** They demonstrate rule coverage and regression prevention, not production detection rates. Real-world held-out benchmarking is an ongoing validation track.

*Generated 2026-07-29. Corpus: 6,495 test fixtures (3,558 positive / 2,930 negative / 7 tricky) across 7 ecosystems. See [Validation Limitations](#validation-limitations) for scope boundaries.*

## Rule count

| Layer | Type | Count |
|---|---|---|
| **L2** | Static scan rules (`RULE_INFO`) | 53 |
| **L2** | Campaign benchmarks (`L2-CAMP-*`) | 4 |
| **L4** | Sandbox behavioral detectors | 15 |
| **Total** | | **72** |

The 4 `L2-CAMP-*` entries are campaign-specific IoC matchers validated against known attack packages, not general-purpose static rules. They are included in the per-rule table for transparency but are not counted as detection rules above.

Note: the 2026-07-29 benchmark run below predates three static rules added since
(`L2-INTEL-001`, `L2-NSCOL-001`, `L2-VCONF-001`; `RULE_INFO` grew 50 → 53).
Those three are not yet exercised by the per-rule table.

## Three Detection Modes

PicoSentry operates in three distinct modes. Benchmarks in this card cover only the first two.

| Mode | Description | Status |
|---|---|---|
| **Offline Deterministic** | Known corpus + deterministic pattern rules (L2 static). No network, no nondeterminism. | Benchmarked (synthetic + real-world) |
| **Offline Behavioral** | Static analysis + sandbox behavioral observation (L4). Runs in isolation, no network. | Partial (L4 rules exercised in integration tests, not in corpus) |
| **Connected Intelligence** | OSV.dev threat feed + package metadata + campaign intelligence. Requires network. | Implemented (`--intelligence=connected`); advisory recall boosted when OSV available |

## Summary

| Metric | Value |
|---|---|
| **Test fixtures** | 6,495 |
| **Positive fixtures** | 3,558 |
| **Negative fixtures** | 2,930 |
| **Tricky fixtures** | 7 |
| **L2 rules benchmarked** | 54 (50 static + 4 campaign) |
| **Mean precision** | 84.92% |
| **Mean recall** | 72.79% |
| **Ecosystems** | npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet |
| **Corpus source** | Synthetically generated combinatorial variants + hand-curated real-world malware patterns |

> **2026-08-17 re-baseline.** The 2026-07-29 run (94.44% / 68.89%) is not reproducible from
> this corpus for three verified reasons: (1) the validation loader silently rejected 760
> generated positives carrying semantic labels (`typosquat`, `dep_confusion`, `cve`, …) —
> fixed; (2) five npm metadata rules (`L2-ENGIN/FORK/LICENSE/MAINT/PROV-001`) fire on ~1,210
> generated "clean" package.json files that lack repo/license/engines fields; (3) 115 `cve`
> fixtures expect `L2-CVE-001`, which does not exist as a rule. The numbers above are the
> current, reproducible aggregate (`picosentry scan --validate`). Fixing (2) and (3) is
> detection-tuning work tracked in state.md; until then this card reports what the code
> actually does.

## Recall by category

Low-recall rules are not uniformly distributed. This table summarizes the root causes:

| Category | Rules | Recall range | Root cause |
|---|---|---|---|
| Advisory (`*-ADV-001`) | 7 | 12–67% | OSV advisory database unavailable in offline validation; requires `--advisory-db` or network access |
| Dependency confusion (`*-DEPC-001`) | 3 | 0–33% | Requires private-registry configuration markers that synthetic fixtures lack |
| Typosquat (Go, Maven) | 2 | 35–43% | Short module/artifact names cause edit-distance false negatives |
| Manifest optional deps | 1 | 0% | Fixture does not trigger the specific optionalDependencies + scripts combination |
| High-recall rules (remaining) | 43 | 75–100% | — |

### Advisory rules (0–33% recall)

Advisory rules (`L2-ADV-001`, `L2-GO-ADV-001`, `L2-CARGO-ADV-001`, `L2-PYPI-ADV-001`, `L2-MAVEN-ADV-001`, `L2-RUBYGEMS-ADV-001`, `L2-NUGET-ADV-001`) show low recall because the OSV advisory database is not available in offline validation mode. These rules require `--advisory-db` or network access to the OSV API. Precision is 100% when the DB is present.

### Dependency confusion (0–25% recall)

`L2-DEPC-001`, `L2-PYPI-DEPC-001`, and `L2-MAVEN-DEPC-001` show 0–33% recall. The dep-confusion detector requires private-registry configuration markers that the synthetic fixtures do not include. `L2-NUGET-DEPC-001` has fixtures with internal-style package IDs and achieves 100% recall.

### Go typosquat (43% recall)

`L2-GO-TYPO-001` shows 43% recall. Go module names are short (e.g., `cli`, `yaml`), causing edit-distance false negatives — a short name has many valid neighbors within distance 2.

### Maven typosquat (35% recall)

`L2-MAVEN-TYPO-001` shows 35% recall. Maven artifact IDs have a large namespace; the edit-distance threshold produces more false negatives than the npm/PyPI counterparts.

## False positives

Zero false positives across 2,930 synthetic negative fixtures. This demonstrates no overtriggering on clean package patterns in the regression corpus, but does not constitute a real-world false-positive rate guarantee.

## 2026-07-29 Expansion

- **Typosquats**: +291 fixtures across all 7 ecosystems (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet)
- **Negative fixtures**: +2050 clean packages (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet)
- **CVE fixtures**: +115 Maven and RubyGems CVE patterns (Log4Shell, Spring4Shell, Jackson, Commons Collections, Nokogiri, Rails, Devise, Rack)
- **Multi-attack**: +30 fixtures combining typosquat+obfuscation, dep-confusion+credential theft, obfuscation+network exfil
- **Obfuscation**: +24 variants (nested eval, chained base64, hex+chr, unicode escapes, getattr bypass, importlib bypass, subprocess variants, socket/urllib exfil)
- **Dependency confusion**: +300 internal-package patterns (internal-*, private-*, corp-*, company-*, org-*, secure-*)

## Per-rule precision/recall

| Rule ID | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| L2-ADV-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-BUILD-001 | 14 | 0 | 4 | 100.00% | 77.78% |
| L2-BUND-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-AXIOS-POISONING | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-NODE-IPC-COMPROMISE | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-SHAI-HULUD | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-TRAPDOOR | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CARGO-ADV-001 | 2 | 0 | 1 | 100.00% | 66.67% |
| L2-CARGO-DEPC-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-CARGO-TYPO-001 | 118 | 0 | 2 | 100.00% | 98.33% |
| L2-CRED-001 | 2 | 0 | 2 | 100.00% | 50.00% |
| L2-DEPC-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-ENGIN-001 | 1 | 0 | 1 | 100.00% | 50.00% |
| L2-FORK-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-GO-ADV-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-GO-DEPC-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-GO-TYPO-001 | 52 | 0 | 68 | 100.00% | 43.33% |
| L2-IOC-001 | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-LICENSE-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-LOCK-001 | 1 | 0 | 1 | 100.00% | 50.00% |
| L2-MAINT-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-MANI-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-MANI-002 | 0 | 0 | 1 | 0.00% | 0.00% |
| L2-MAVEN-ADV-001 | 3 | 0 | 21 | 100.00% | 12.50% |
| L2-MAVEN-DEPC-001 | 0 | 0 | 13 | 0.00% | 0.00% |
| L2-MAVEN-TYPO-001 | 127 | 0 | 234 | 100.00% | 35.18% |
| L2-NETEX-001 | 3 | 0 | 2 | 100.00% | 60.00% |
| L2-NUGET-ADV-001 | 3 | 0 | 2 | 100.00% | 60.00% |
| L2-NUGET-DEPC-001 | 6 | 0 | 0 | 100.00% | 100.00% |
| L2-NUGET-TYPO-001 | 167 | 0 | 40 | 100.00% | 80.68% |
| L2-OBFS-001 | 4 | 0 | 0 | 100.00% | 100.00% |
| L2-OBFS-002 | 3 | 0 | 1 | 100.00% | 75.00% |
| L2-OBFS-003 | 1 | 0 | 3 | 100.00% | 25.00% |
| L2-OBFS-004 | 3 | 0 | 1 | 100.00% | 75.00% |
| L2-PNPM-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-POST-001 | 34 | 0 | 0 | 100.00% | 100.00% |
| L2-PROV-001 | 1 | 0 | 1 | 100.00% | 50.00% |
| L2-PYPI-ADV-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-PYPI-DEPC-001 | 0 | 0 | 3 | 0.00% | 0.00% |
| L2-PYPI-OBFS-001 | 4 | 0 | 0 | 100.00% | 100.00% |
| L2-PYPI-OBFS-002 | 5 | 0 | 0 | 100.00% | 100.00% |
| L2-PYPI-OBFS-003 | 2 | 0 | 2 | 100.00% | 50.00% |
| L2-PYPI-OBFS-004 | 3 | 0 | 1 | 100.00% | 75.00% |
| L2-PYPI-OBFS-005 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-PYPI-OBFS-006 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-PYPI-OBFS-007 | 3 | 0 | 1 | 100.00% | 75.00% |
| L2-PYPI-POST-001 | 22 | 0 | 0 | 100.00% | 100.00% |
| L2-PYPI-TYPO-001 | 472 | 0 | 0 | 100.00% | 100.00% |
| L2-RUBYGEMS-ADV-001 | 2 | 0 | 8 | 100.00% | 20.00% |
| L2-RUBYGEMS-DEPC-001 | 1 | 0 | 3 | 100.00% | 25.00% |
| L2-RUBYGEMS-TYPO-001 | 245 | 0 | 127 | 100.00% | 65.86% |
| L2-SIDELOAD-001 | 4 | 0 | 0 | 100.00% | 100.00% |
| L2-TYPO-001 | 985 | 0 | 0 | 100.00% | 100.00% |
| L2-WORM-001 | 3 | 0 | 0 | 100.00% | 100.00% |

## Validation Limitations

1. **Synthetic corpus**: All positive and negative fixtures are synthetically generated from combinatorial templates. They exercise rule logic, not real-world malware diversity.
2. **Synthetic negatives**: The negative corpus consists of generated clean package patterns, not real-world benign packages. The zero-FP claim applies only to these synthetic patterns.
3. **Advisory rules cannot reach OSV in air-gapped validation**: L2-*-ADV-001 rules require the OSV advisory database, which is unavailable in the default offline validation mode. Low recall reflects fixture limitations, not detector capability.
4. **Real-world corpus is now available**: The `datasets/realworld/` directory contains a curated benchmark built from public OSV data. See [Real-world validation](#real-world-validation) for details. The synthetic-corpus numbers above remain the primary regression benchmark; the real-world corpus supplements it.
5. **No comparison against other tools**: Benchmarks measure PicoSentry against its own corpus, not against competitor scanners.
6. **Low-recall rules are documented with root causes**: Advisory (OSV offline), dep-confusion (missing private-registry markers), and typosquat (edit-distance vs. short names) rules have known, documented limitations.
7. **L4 behavioral rules are not in the corpus**: The per-rule table covers L2 static rules and campaign IoC matchers only. L4 sandbox detectors are validated through integration tests, not this regression corpus.

## Real-world validation

PicoSentry also maintains a curated real-world malware benchmark corpus built from public OSV/advisory data in `datasets/malware/`. This corpus exercises the scanner against known-malicious packages rather than synthetic patterns.

| Property | Value |
|---|---|
| **Source** | Public OSV/advisory datasets (DataDog, OSV, Backstabber) |
| **Total fixtures** | See `datasets/realworld/METADATA.json` |
| **Train/held-out split** | 75/25, deterministic (SHA-256 first byte of entry ID) |
| **Ecosystems** | npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet |
| **Fixture type** | Minimal manifests only — no executable payloads |
| **Categories** | `malicious`, `compromised_lib` |

Each fixture maps to one or more PicoSentry rules based on OSV category and metadata signals (summary keywords, CVE/GHSA references). Entries without a clear rule mapping are excluded — precision over coverage.

The train set (`datasets/realworld/train/`) is used for regression testing; the held-out set (`datasets/realworld/held_out/`) is reserved for future version reporting. Held-out results will be reported in a future model card update.

To rebuild the corpus:

```bash
python scripts/build_realworld_corpus.py
```

To run the real-world benchmark:

```bash
uv run python scripts/run_realworld_benchmark.py
```

## Real-world benchmark results

*Benchmark run: 2026-08-07. Corpus: 1522 train fixtures (500 compromised_lib / 1022 malicious) across 7 ecosystems. All fixtures are positive (no negatives in train). Fixtures are minimal manifests — no executable payloads.*

### Overall

| Metric | Value |
|---|---|
| **Fixtures** | 1522 |
| **Errors** | 0 |
| **Elapsed** | 113s |
| **Overall precision** | 100.00% |
| **Overall recall** | 66.10% |
| **Mean per-rule precision** | 50.00% |
| **Mean per-rule recall** | 50.00% |

Overall recall counts each expected rule per fixture: 737 of 1115 expected rule–fixture pairs fired (66.10%). Mean per-rule averages each rule's own precision/recall, so rules with 0 TP dominate the average.

### Per-ecosystem

| Ecosystem | Fixtures | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|---|
| npm | 368 | 368 | 0 | 368 | 100.00% | 50.00% |
| pypi | 379 | 369 | 0 | 10 | 100.00% | 97.36% |
| go | 14 | 14 | 0 | 0 | 100.00% | 100.00% |
| cargo | 7 | 7 | 0 | 0 | 100.00% | 100.00% |
| maven | 2 | 2 | 0 | 0 | 100.00% | 100.00% |
| rubygems | 375 | 375 | 0 | 0 | 100.00% | 100.00% |
| nuget | 377 | 377 | 0 | 0 | 100.00% | 100.00% |

npm recall is 50% because all 368 `compromised_lib` fixtures expect `L2-ADV-001` (advisory rule) which cannot fire without the OSV advisory database. `L2-MAINT-001` fires on all of them, so every npm fixture is detected by at least one rule.

### Per-category

| Category | Fixtures | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|---|
| compromised_lib | 368 | 368 | 0 | 368 | 100.00% | 50.00% |
| malicious | 379 | 369 | 0 | 10 | 100.00% | 97.36% |

### Per-rule

| Rule ID | TP | FP | FN | Precision | Recall | Notes |
|---|---|---|---|---|---|---|
| L2-ADV-001 | 0 | 0 | 368 | 0.00% | 0.00% | Requires OSV advisory DB; cannot fire offline |
| L2-CRED-001 | 0 | 0 | 1 | 0.00% | 0.00% | 1 expected; not triggered |
| L2-MAINT-001 | 368 | 0 | 0 | 100.00% | 100.00% | |
| L2-NETEX-001 | 0 | 0 | 9 | 0.00% | 0.00% | 9 expected; not triggered |
| L2-PYPI-OBFS-001 | 8 | 0 | 0 | 100.00% | 100.00% | |
| L2-PYPI-POST-001 | 361 | 0 | 0 | 100.00% | 100.00% | |

### Assessment

**What the results mean:**

- **Zero false positives** — no clean packages were misflagged (there are no negative fixtures in the train set, so this only covers positive-fixture stray findings).
- **Strong detection on malicious code** (97.36% recall for PyPI) — PyPI fixtures with install-time or network exfiltration patterns are reliably caught.
- **Full detection on Go, Cargo, Maven, RubyGems, NuGet** (100% recall) — `L2-BUILD-001` fires on all non-npm/non-PyPI malicious fixtures because build scripts with subprocess/network patterns are generated for each.
- **Low per-rule recall is advisory-driven** — `L2-ADV-001` accounts for 368 of 378 false negatives. This rule requires the OSV advisory database, which is unavailable in offline benchmark mode. With `--advisory-db` or network access, `L2-ADV-001` would fire on all 368 `compromised_lib` fixtures.
- **Ecosystem coverage is now broad** — 12+ rules exercised across all 7 ecosystems (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet). Go/Cargo/Maven/RubyGems/NuGet fixtures exercise `L2-BUILD-001` via supplementary build files.
- **All fixtures are minimal manifests** (package.json, setup.py, go.mod, Cargo.toml, pom.xml, .gemspec, .nuspec) plus ecosystem-specific build scripts — no real executable payloads.
- **Held-out results** (507 fixtures) will be reported separately.

**Limitations:**

1. No negative fixtures in the train set — false-positive rate is not measured here.
2. `L2-ADV-001` cannot fire in offline mode, inflating false negatives by 368.
3. Go/Cargo/Maven/RubyGems/NuGet fixtures primarily exercise `L2-BUILD-001`; deeper ecosystem-specific rules (typosquat, dep-confusion) require typosquat corpus fixtures, not real-world OSV data.
4. Minimal manifests may miss patterns that real package tarballs would expose.

## Running validation

```bash
# Full validation against built-in fixtures
picosentry scan --validate

# With advisory DB for CVE rules
picosentry scan --validate --advisory-db datasets/malware/

# Generate machine-readable report
picosentry scan --validate --output tests/scan/fixtures/validation/REPORT.json
```