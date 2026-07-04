# PicoSentry — Detector Deep Review

> **Purpose:** A living catalog of known limitations, blind spots, and false-positive
tendencies in the PicoSentry static-analysis (L2) detector suite. Every entry maps
back to a rule ID and is tracked in code via `KnownLimitation.tracked_in` in
`picosentry/scan/detection_quality.py`.

> **Companion documents:**
> - [`docs/BENCHMARKS.md`](BENCHMARKS.md) — current fixture corpus, precision/recall
gate, and reproduction instructions.
> - [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — trust boundaries and layered defense
rationale.

---

## How to read this document

Each limitation is classified as one of:

- **false_positive_tendency** — the rule is expected to fire on benign inputs in
  some common contexts. Use baselines to suppress known-good cases.
- **edge_case** — the rule is broadly correct but has well-defined corner cases
  where intent cannot be determined from static analysis alone.
- **blind_spot** — the detector cannot see a class of real attacks without
  additional context or external data.

---

## L2 rule limitations

### `L2-FORK-001` — Fork detection

- **Category:** false_positive_tendency
- **Description:** Flags any package whose name matches a known popular project and
  appears to be forked. Popular packages with many legitimate forks (e.g. lodash)
  produce noisy results.
- **Impact:** High false-positive rate on projects with many forked dependencies.
- **Workaround:** Use baseline suppression for known-good forks. Suppress
  `L2-FORK-001` in default baselines for fork-heavy repositories.

### `L2-OBFS-001` — Obfuscation detection (literal-token filter)

- **Category:** false_positive_tendency
- **Description:** Uses a staged literal-token filter (`eval`, `Function`, etc.),
  so benign files without those tokens are skipped. Minified production code that
  legitimately contains the tokens can still be flagged.
- **Impact:** Moderate false-positive rate on projects bundling minified assets.
- **Workaround:** Use baseline to suppress known-good minified bundles.

### `L2-OBFS-003` — Base64 + eval detection

- **Category:** false_positive_tendency
- **Description:** Uses a staged literal-token filter (`atob`, `Buffer.from`,
  `eval`, `Function`). Webpack bundles that embed base64 data URIs and also contain
  `eval`/`Function` tokens may still be flagged.
- **Impact:** High false-positive rate on projects using webpack with data-URI
  loaders.
- **Workaround:** Suppress in baseline or set `confidence=MEDIUM` for webpack
  bundles.

### `L2-TYPO-001` — Typosquat detection

- **Category:** edge_case
- **Description:** Indexes the corpus by length and compares against compatible
  buckets for scalability. Accuracy depends on a fresh, complete corpus; stale
  corpora can miss newly popular packages or misclassify packages near the top-N
  boundary.
- **Impact:** Low false-positive rate; accuracy depends on corpus freshness and
  coverage.
- **Workaround:** Run `picosentry update --ecosystem <ecosystem>` regularly. Pin
  corpus version for reproducibility.

### `L2-DEPC-001` — Dependency confusion detection

- **Category:** blind_spot
- **Description:** Only flags packages that exist in public npm but not in private
  registries. Cannot detect misconfigured registries that resolve to wrong packages
  without a public presence.
- **Impact:** False negatives for private-only dependency-confusion vectors.
- **Workaround:** Combine with npm config checks (`L2-PNPM-001`) and lockfile
  verification.

### `L2-POST-001` — Post-install script detection

- **Category:** edge_case
- **Description:** Flags all install scripts regardless of intent. Many popular
  packages have legitimate post-install hooks.
- **Impact:** High false-positive rate; most post-install scripts are benign.
- **Workaround:** Use baseline suppression for known-good packages. Consider
  severity context from the advisory database.

### `L2-MAINT-001` — Maintainer change detection

- **Category:** false_positive_tendency
- **Description:** Flags any ownership transfer. Legitimate maintainer changes
  (e.g. project handoff) are common.
- **Impact:** Moderate false-positive rate; requires manual triage.
- **Workaround:** Suppress known-good maintainer changes via baseline.

### `L2-PROV-001` — Provenance detection

- **Category:** blind_spot
- **Description:** Requires npm provenance attestations, which are not yet widely
  adopted. Packages without provenance are flagged regardless of their actual
  trustworthiness.
- **Impact:** High false-positive rate until provenance adoption increases.
- **Workaround:** Suppress for known-good packages without provenance. Combine
  with advisory checks for risk context.

### `L2-SIDELOAD-001` — Sideloading detection

- **Category:** edge_case
- **Description:** Flags packages installed from non-registry sources (git URLs,
  local paths). This includes legitimate development workflows.
- **Impact:** Moderate false-positive rate in monorepos and development
  environments.
- **Workaround:** Suppress in dev baselines. Flag in CI/CD production scans.

---

## Cross-cutting gaps

1. **Layer coverage is L2 only.** The reviewed rules are static-analysis (L2)
   detectors plus L2-CAMP campaign detectors. Runtime enforcement (L3 kernel
   sandbox, L4 behavioral profiler, L5 prompt guard, L6 output validation) is not
   covered by the fixture corpus in this document.
2. **188 fixtures is a smoke test, not a benchmark.** See
   [`docs/BENCHMARKS.md`](BENCHMARKS.md) for the honest interpretation of the
   100% precision/recall headline.
3. **Known AST-level bypass.** The `_tricky/` corpus documents a
   `globals()['ex'+'ec'](...)` style bypass that the current regex/AST pipeline
   does not reliably catch.

---

## Maintenance

When a limitation is removed or its workaround changes, update both this file
and the corresponding `KnownLimitation` in
`picosentry/scan/detection_quality.py`. When a new rule is added with a known
caveat, add it here as well.
