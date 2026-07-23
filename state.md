# State — KirkForge-PicoSeries-picosentry (PicoSentry)

*Tracked. Updated at session close. What changed, what's pending, what's blocked.*

## Current state
- Head: `53e4458` (work/picosentry-entprise-gaps)
- Tests: 4248+ scan tests pass, corpus 1855 JSON files (1094 pos / 157 neg / 7 tricky)
- Last updated: 2026-07-23

## Session 2026-07-23 changes

### Task 1: Pentest engagement prep — DONE
- Created `docs/PENTEST-README.md` with: engagement checklist, scope definition, firm selection criteria, what to share with pentester (ADRs, security reviews, attack-surface doc), findings template, triage workflow, severity classification, post-engagement guidance
- Gate: `ls docs/PENTEST-README.md` exists ✓

### Task 2: Corpus expansion to 1500+ — DONE
- Expanded from 1048 → 1855 JSON files (1094 pos / 157 neg / 7 tricky dirs)
- Maven typosquat: 41 → 131 fixtures (prefix + swap variants for 39 popular packages)
- Maven CVE: 2 → 9 fixtures (Spring4Shell, Text4Shell, Log4Shell, Jackson, SnakeYAML, Spring OAuth)
- Maven DEPC: 3 → 8 fixtures (internal-* patterns)
- Maven malicious BUILD: 2 → 5 fixtures (antrun, gmaven, groovy)
- Maven negative: 10 → 15 fixtures
- NuGet typosquat: 39 → 68 fixtures (prefix + swap variants for 25 popular packages)
- NuGet CVE: 2 → 4 fixtures (System.Text.Json, Newtonsoft.Json)
- NuGet DEPC: 3 → 6 fixtures (internal-* patterns)
- NuGet negative: 10 → 15 fixtures
- RubyGems typosquat: 43 → 69 fixtures (prefix + swap variants for 26 popular gems)
- RubyGems CVE: 2 → 4 fixtures (Rails XSS, Sidekiq RCE)
- RubyGems DEPC: 1 → 4 fixtures (internal-* patterns)
- RubyGems negative: 10 → 15 fixtures
- Updated `docs/model-card.md` with expanded per-rule benchmarks
- Gate: `find tests/scan/fixtures -name "*.json" | wc -l` = 1855 ≥ 1500 ✓

### Task 3: Sigstore E2E verification — PARTIAL
- **sigstore verify identity** on v2.0.18 wheel: PASSED ✓
- **sigstore verify identity** on v2.0.18 sdist: PASSED ✓
- **SLSA build-provenance attestation** verified via `gh attestation verify`: PASSED ✓
- **SHA-256 checksums** verified: PASSED ✓
- **cosign verify** on Docker image `docker.io/kirkforge/picodome:v2.0.18`: FAILED — no signatures found
- The release workflow (`release.yml`) signs wheel/sdist with sigstore but does NOT sign the Docker image with cosign. This is a gap: the Docker signing step uses `docker buildx bake --push` but has no cosign signing step.
- **Action needed**: Add a cosign signing step to the Docker job in `.github/workflows/release.yml` (e.g., `cosign sign --yes docker.io/kirkforge/picodome:v${TAG}`).
- Did NOT push a v0.2.0-rc1 tag because the sigstore+cosign pipeline gap needs to be fixed first. Pushing a tag now would produce an unsigned Docker image.

## Gates verified
```
$ uv run ruff check picosentry/ tests/ scripts/ --quiet
0 errors

$ uv run ruff format --check picosentry/ tests/ scripts/
596 files already formatted

$ uv run mypy picosentry/ --ignore-missing-imports
Success: no issues found in 389 source files

$ uv run pytest tests/scan/test_corpus_index.py tests/scan/test_benchmark.py -q
20 passed in 37.62s

$ find tests/scan/fixtures -name "*.json" | wc -l
1855
```

## Pending / blocked
- **Task 3 Docker cosign signing**: The `release.yml` Docker job needs a cosign signing step. Once added, push `v0.2.0-rc1`, verify both sigstore (wheel) and cosign (Docker image) pass, then yank the RC.
- **L2-PYPI-DEPC-001**: Still 0% recall — dep-confusion detector needs private-registry config marker in fixtures.

---

## Historical LLM scratch (local-only)

# PicoSentry LLM scratch (local-only)
