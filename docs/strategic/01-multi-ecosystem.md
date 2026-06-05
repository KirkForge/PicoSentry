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
| **Rule `__init__.py`** | Add ecosystem-detect logic to `create_default_engine()` | ✅ Done |
| **Per-ecosystem rule modules** | `rules/pypi_*.py`, `rules/go_*.py`, `rules/cargo_*.py`, `rules/maven_*.py`, `rules/rubygems_*.py`, `rules/nuget_*.py` | ✅ Done |
| **Manifest/lockfile parsers** | Parse `requirements.txt`, `poetry.lock`, `go.sum`, `go.mod`, `Cargo.toml`, `Cargo.lock`, `pom.xml`, `build.gradle`, `Gemfile`, `Gemfile.lock`, `*.csproj`, `packages.config`, `packages.lock.json` | ✅ Done |
| **Iteration utilities** | Analogues of `iter_node_modules()` for site-packages, GOPATH | ✅ Done |
| **Corpus files** | `pypi_top_packages.json`, `go_top_packages.json`, `cargo_top_packages.json`, `maven_top_packages.json`, `rubygems_top_packages.json`, `nuget_top_packages.json` | ✅ Done |
| **IOC system** | Already ecosystem-agnostic (`package_name + version_range`) | ✅ No change |
| **Advisory DB** | Already OSV-format with `ecosystem` field — 7 ecosystems supported | ✅ Done |
| **Finding model** | Add optional `ecosystem` field | ✅ Done |
| **Formatters** | Update CycloneDX/SARIF to include ecosystem in output | ✅ Done |

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
   - `L2-PYPI-DEPC-001` — dependency confusion
   - `L2-PYPI-POST-001` — post-install script analysis
   - `L2-PYPI-OBFS-001` through `L2-PYPI-OBFS-007` — obfuscation detection
   - `L2-PYPI-ADV-001` — advisory DB check

   Files: `picosentry/scan/rules/pypi_*.py` (8 files)

4. **PyPI corpus** — `picosentry/scan/corpus/pypi_top_packages.json` (100 packages)

5. **Engine registration** — conditionally register PyPI rules when `.venv/`, `requirements.txt`, or `pyproject.toml` detected

6. **Finding.ecosystem field** — `ecosystem: str = "npm"` default

7. **Test suite** — `tests/scan/test_pypi.py` with clean/malicious fixtures

Status: ✅ **Complete** — 10 rules, 30 tests

### Phase 2: Go Modules

1. **GoModule iteration** — walk `go.mod`, parse `go.sum` entries
   - File: `picosentry/scan/rules/go_utils.py`

2. **Go rules**: `L2-GO-TYPO-001`, `L2-GO-DEPC-001`, `L2-GO-ADV-001`

3. **Corpus** — `go_top_packages.json` (100 modules)

Status: ✅ **Complete** — 3 rules, 25 tests

### Phase 3: Cargo, Maven, RubyGems, NuGet

Each follows the same pattern:
- A `*_utils.py` for package iteration
- Lockfile/manifest parser
- Typosquat + dependency confusion + advisory rules
- Corpus JSON file
- Test suite with clean/malicious fixtures

| Ecosystem | Rules | Tests | Status |
|-----------|-------|-------|--------|
| Cargo (Rust) | 3 | 32 | ✅ |
| Maven (Java) | 3 | 34 | ✅ |
| RubyGems (Ruby) | 3 | 34 | ✅ |
| NuGet (.NET) | 3 | 33 | ✅ |

**49 total rules across 7 ecosystems — 1597 tests passing.**

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