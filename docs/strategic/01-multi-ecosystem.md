# 01 — Multi-Ecosystem Package Support

**Leverage:** Market reach | **Effort:** Large | **Dependency:** None (architecturally isolated)

---

## Why

The scan layer currently supports **npm/pnpm/yarn only** (366 package.json-based packages tested). Every CI pipeline is polyglot — the fastest way to get PicoSentry ignored is to only cover one ecosystem. PyPI has the same typosquat/dependency-confusion/post-install attack surface that npm had in 2018, and Go modules have a growing transparency-log attack surface that maps perfectly onto our existing Rekor instincts.

The good news: the rule engine doesn't care about ecosystems. A rule is `Callable[[Path, Path], list[Finding]]` — it takes a target directory and a corpus directory, returns findings. Adding ecosystems means adding parsers and rule functions, not changing the engine.

## Architecture

### Rule interface (already exists — no changes needed)

```python
# From engine.py line 104:
DetectorRule = Callable[[Path, Path], list[Finding]]
# target: Path — filesystem root to scan
# corpus_dir: Path — corpus data directory
# returns: list[Finding]
```

All rules are registered in `create_default_engine()` (`picosentry/scan/engine.py:393`). The engine deduplicates rule_ids → functions, collects findings, and computes `ScanStats`. Nothing in this chain is npm-specific.

### What needs to change

| Component | What | Status |
|-----------|------|--------|
| **Rule `__init__.py`** | Add ecosystem-detect logic to `create_default_engine()` | New |
| **Per-ecosystem rule modules** | `rules/pypi_*.py`, `rules/go_*.py`, etc. | New |
| **Manifest/lockfile parsers** | Parse `requirements.txt`, `poetry.lock`, `go.sum`, `go.mod`, etc. | New |
| **Iteration utilities** | Analogues of `iter_node_modules()` for site-packages, GOPATH | New |
| **Corpus files** | `corpus/pypi_top_packages.json`, `corpus/go_top_modules.json` | New |
| **IOC system** | Already ecosystem-agnostic (`package_name + version_range`) | ✅ No change |
| **Advisory DB** | Already OSV-format with `ecosystem` field — just load more data | Minor |
| **Finding model** | Add optional `ecosystem` field | Small |
| **Formatters** | Update CycloneDX/SARIF to include ecosystem in output | Small |

## Phase Plan

### Phase 1: PyPI (highest-ROI first)

Core scope — the `requirements.txt`/`pip freeze`/`poetry.lock` ecosystem sees the same supply-chain attacks as npm:

1. **PypiPackage parser** — parse `site-packages/METADATA` from installed packages
   - Walk `target/.venv/lib/python3.X/site-packages/` (analogue of `iter_node_modules()`)
   - Extract name, version from `PKG-INFO`/`METADATA`
   - Handle editable installs (`*.egg-info`, `*.dist-info` directories)
   - File: `picosentry/scan/rules/pypi_utils.py`

2. **Lockfile parsers** (three formats in order of prevalence):
   - `pip freeze` / `requirements.txt` format — simple `name==version` lines
   - `poetry.lock` — TOML, structured `[[package]]` entries
   - `uv.lock` — newer, TOML with hash arrays
   - File: `picosentry/scan/rules/pypi_lock_parser.py`

3. **Copypat rules** (port existing npm rules to PyPI ecosystem):
   - `L2-PYPI-TYPO-001` — typosquat against `pypi_top_packages.json` corpus, using Levenshtein + keyboard-adjacency + homoglyph distance (shared utility, not per-ecosystem)
   - `L2-PYPI-DEPC-001` — dependency confusion: package name in `requirements.txt` exists on PyPI but is not the expected name
   - `L2-PYPI-POST-001` — post-install script analysis: `setup.py` or `pyproject.toml [tool.setuptools.packages.find]` for suspicious commands
   - `L2-PYPI-OBFS-001` — obfuscated code in `setup.py` (base64, eval, exec patterns — same logic as npm rule)
   - `L2-PYPI-ADV-001` — advisory DB check against OSV data (already ecosystem-filterable)

   File: `picosentry/scan/rules/pypi_typosquat.py`, `picosentry/scan/rules/pypi_dep_confusion.py`, `picosentry/scan/rules/pypi_post_install.py`, `picosentry/scan/rules/pypi_obfuscation.py`, `picosentry/scan/rules/pypi_advisory_check.py`

4. **PyPI corpus** — generate `pypi_top_packages.json` from PyPI's BigQuery/dump data or PyPI's "top packages" API
   - Helper in `corpus_share.py` — same pattern as `generate_npm_top()`
   - Also generate a simple frequency-based weighting for typosquat sensitivity
   - File: `picosentry/scan/corpus/pypi_top_packages.json`

5. **Engine registration** — conditionally register PyPI rules when a `.venv/`, `requirements.txt`, or `pyproject.toml` is detected at the scan root

6. **Finding.ecosystem field** — add `ecosystem: str = "npm"` to `Finding` dataclass, defaulting to npm for backward compat
   - File: `picosentry/scan/models.py`

7. **Test suite** — for each rule, a test with a known-good and known-bad fixture:
   - Fixture packages in `tests/fixtures/pypi/`
   - Tests in `tests/scan/test_pypi_*.py`

### Phase 2: Go Modules

1. **GoModule iteration** — walk `go.mod` to discover dependencies, resolve to module paths
   - No traditional lockfile walk — Go's `go.sum` is a flat hash list
   - Parse `go.sum` entries: `module version h1:hash`
   - File: `picosentry/scan/rules/go_utils.py`

2. **Go rules**:
   - `L2-GO-TYPO-001` — typosquat module names against `go_top_modules.json`
   - `L2-GO-SUM-001` — verify `go.sum` entries against checksum DB / transparency log
   - `L2-GO-ADV-001` — OSV advisory check (Go ecosystem already well-indexed in OSV)

3. **Corpus** — `go_top_modules.json` from Go module index proxy

### Phase 3: Cargo, Maven, RubyGems, NuGet

Each follows the same pattern as PyPI:
- A `*_utils.py` for package iteration
- Lockfile/manifest parser
- Typosquat + dependency confusion + advisory rules
- Corpus JSON file

Order by estimated adoption ROI: **Cargo** (Rust's dev tooling is most receptive to security tooling) → **RubyGems** (still the most active typosquat target after npm) → **Maven** (enterprise, slower adoption cycle) → **NuGet** (.NET ecosystem)

## Ecosystem-Agnostic Cross-Cuts

### Improved typosquat utility (shared by all ecosystems)

Currently Levenshtein-only in `detect_typosquat()` (`rules/typosquat.py`). Extract into a shared utility:
- `edit_distance(a, b)` — existing Levenshtein
- `keyboard_distance(a, b)` — QWERTY adjacency cost
- `homoglyph_score(a, b)` — Unicode confusable detection
- `scope_confusion_score(name)` — `@org/pkg` vs `org-pkg` pattern
- Combined: `typosquat_score(target, corpus_name) -> float`

File: `picosentry/scan/rules/typosquat_utils.py`

### Ecosystem detection

In `create_default_engine()`, probe the target root for ecosystem-indicator files:
- `requirements.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`, `uv.lock` → PyPI
- `go.mod`, `go.sum` → Go
- `Cargo.toml`, `Cargo.lock` → Cargo
- `pom.xml`, `build.gradle` → Maven
- `Gemfile`, `Gemfile.lock` → RubyGems
- `packages.lock.json`, `*.csproj` → NuGet

Only register rules for detected ecosystems. Filter by `--ecosystem` CLI flag if user wants to constrain.

## Verification

- Unit tests: each rule against a known-bad fixture
- Integration test: `picosentry scan tests/fixtures/pypi/malicious/` returns expected findings
- Regression: existing npm tests still pass (0 breakage)
- Benchmark: scan an empty `site-packages/` dir in under 100ms (no false positives)