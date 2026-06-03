# 03 — Reachability Analysis + VEX + Auto-Remediation

**Leverage:** False-positive kill + compliance | **Effort:** Medium | **Dependencies:** 01 (multi-ecosystem) for full value

---

## Why

Three tightly coupled gaps with a single solution:

1. **Alert fatigue** — "CVE-2024-XXXX in transitive dep" is noise. "Your app calls the vulnerable symbol" is signal. Reachability analysis is what separates Endor/Semgrep from traditional scanners.
2. **Compliance** — VEX (Vulnerability Exploitability eXchange) is increasingly a procurement requirement. Regulated orgs need `not_affected` justifications with machine-readable evidence.
3. **Adoption** — Detection has zero value without a remediation path. Dependabot/Renovate win on the *fix*, not the *find*. Adding `scan --fix` makes PicoSentry sticky in a real team's workflow.

## Architecture

### Current state

```
OSV advisory ──→ AdvisoryDB.check(pkg, version) → match? → Finding("fixed_version: >=X.Y.Z")
                                                                         ↓
                                                          Human reads remediation string
```

There is no reachability. VEX doesn't exist. Remediation is a free-text string.

### Target state

```
Advisory match ──→ Reachability check ──→ Reachable? ──→ Finding(call_path, ...) + VEX entry
                                                        └── Not reachable? ──→ VEX("not_affected", "reachability")
                                                                                          ↓
                                                                          scan --fix computes safe upgrade
                                                                                          ↓
                                                                          PR with SARIF + VEX artifact
```

## Phase 1: Reachability Analysis

### What it does

For a given CVE affecting a library at a known vulnerable symbol (function/class/method), check whether the scanned codebase actually imports and calls that symbol. If not, downgrade the finding confidence or suppress it with a VEX justification.

### Implementation approach

**Lightweight call-graph via AST scanning** (no heavyweight dataflow analysis):

1. Parse Python/JS/TS source files in the target into AST
2. Build import map: which files import which modules at which symbols
3. For each advisory with a known vulnerable symbol (extracted from CWE/CVE description or advisory's `affected[].ecosystem_specific.imports` field):
   - Trace: `entry_point → import chain → does it reach the package?`
   - If the vulnerable module is imported but the vulnerable function is never called → `not_affected` (reachability)
   - If the vulnerable module is never imported → `not_affected` (unreachable)

### New modules

**File:** `picosentry/scan/reachability/ast_scanner.py`
- `scan_imports(target: Path) -> ImportGraph` — walks all `.py`/`.js`/`.ts` files, builds symbol-level import map
- `ImportGraph` — `{file: {imported_module: [imported_symbols]}}`
- Pure Python stdlib (`ast` module) for Python; regex-based for JS/TS (no heavy parser dependency)

**File:** `picosentry/scan/reachability/checker.py`
- `check_reachability(pkg_name: str, vulnerable_symbols: list[str], import_graph: ImportGraph) -> ReachabilityResult`
- `ReachabilityResult` — enum: `REACHABLE`, `UNREACHABLE_IMPORT`, `UNREACHABLE_SYMBOL`, `UNKNOWN` (no source to scan)

**File:** `picosentry/scan/reachability/__init__.py`
- `ReachabilityConfig` — enable/disable, modes (strict, permissive), default enabled when source available

### Advisory enrichment

Add `vulnerable_symbols: list[str]` to `Advisory` dataclass (`picosentry/scan/advisory.py`):
```python
@dataclass
class Advisory:
    ...
    vulnerable_symbols: list[str] = field(default_factory=list)
    affected_imports: list[str] = field(default_factory=list)
```

Populated from OSV's `affected[].ecosystem_specific` or `database_specific.imports` when available.

### Finding enrichment

- If reachable: existing `Finding` with `confidence` bumped up one level (e.g., MEDIUM → HIGH)
- If unreachable: emit no finding, or emit a suppressed finding with `status = "not_affected"` for VEX

### Finding status field

Add `status: str = "affected"` to `Finding` dataclass. Values: `"affected"`, `"not_affected"`, `"fixed"`, `"under_investigation"` (mirrors VEX status). Backward-compat default is `"affected"`.

## Phase 2: VEX Generation

### OpenVEX format

Generate OpenVEX JSON alongside CycloneDX SBOM output. OpenVEX is the emerging standard (CNCF/TAG-Security endorsed, adopted by OpenSSF).

**File:** `picosentry/scan/formatters/vex.py`

```python
def format_vex(
    result: ScanResult,
    reachability_results: dict[str, ReachabilityResult],
) -> str:
    """
    Produce OpenVEX-compliant JSON document.
    
    Each finding becomes a VEX statement:
    - status: "not_affected" if reachability says UNREACHABLE
    - status: "affected" if reachability says REACHABLE
    - status: "under_investigation" if UNKNOWN
    - justification: "component_not_present" | "vulnerable_code_not_present" | ...
    """
```

### VEX statement model

```python
@dataclass
class VEXStatement:
    vuln_id: str                    # CVE/GHSA ID
    product: str                    # PURL of the scanned package
    subcomponent: str               # PURL of the affected dependency
    status: Literal["not_affected", "affected", "fixed", "under_investigation"]
    justification: str | None       # required for "not_affected"
    impact_statement: str | None    # human-readable explanation
    action: str | None              # recommended action
    timestamp: str                  # ISO 8601
    author: str                     # "PicoSentry v2.0.0"
```

### Justification values (per OpenVEX spec)

| Justification | When to use |
|---------------|-------------|
| `component_not_present` | The dependency is in the lockfile but the vulnerable code isn't installed/loaded |
| `vulnerable_code_not_present` | The vulnerable symbol is never called in the scanned source |
| `vulnerable_code_cannot_be_controlled_by_adversary` | The vulnerable symbol is called but with sanitized/trusted input only |
| `vulnerable_code_not_in_execute_path` | The call path is guarded by a flag/feature flag that's off by default |
| `inline_mitigations_already_exist` | There's a WAF/runtime guard that blocks exploitation |

### CLI flag

```
picosentry scan /path --vex --vex-out findings.vex.json
```

Also auto-included when `--format cyclonedx` is used (VEX as companion document).

### Verification

- Unit: reachability identifies known-vulnerable symbol in test fixture → `REACHABLE` → VEX status `"affected"`
- Unit: reachable but symbol not called → `UNREACHABLE_SYMBOL` → VEX status `"not_affected"` + justification `vulnerable_code_not_present`
- Golden-file: generated VEX document validates against OpenVEX JSON schema

## Phase 3: Auto-Remediation (`scan --fix`)

### What it does

```
picosentry scan /path --fix --pr --repo org/repo
```

Compute the minimal safe upgrade for each finding, apply to manifest, optionally open a PR with the VEX artifact attached.

### Implementation

**File:** `picosentry/scan/remediation.py`

```python
@dataclass
class RemediationStep:
    package: str                    # package name
    from_version: str               # current
    to_version: str                 # minimal safe version
    ecosystem: str                  # "npm", "pypi", "go"
    reason: str                     # which advisory triggered this
    confidence: Confidence          # how sure we are it's safe
    breaking_change_risk: float     # 0.0–1.0 (semver-based heuristic)
```

**`compute_remediation(result: ScanResult) -> list[RemediationStep]`**:
1. For each advisory finding with `fixed_version`, compute the minimal safe upgrade
2. For findings with `confidence >= HIGH`, treat `fixed_version` as mandatory
3. For `confidence < HIGH`, try `fixed_version` but warn
4. Resolve conflicting upgrade paths: if `pkg_a` needs `lib_x@>=2.0` and `pkg_b` needs `lib_x@>=1.5`, take the higher bound
5. Flag breaking changes: `MAJOR.MINOR.PATCH` → if `fixed_version` bumps major, set `breaking_change_risk = 1.0`

**`apply_remediation(target: Path, steps: list[RemediationStep]) -> bool`**:
- Modify `package.json` / `requirements.txt` / `go.mod` in place
- Create backup of original manifest
- Re-scan to verify fix (deterministic check)

### PR generation

When `--pr` is passed:
- Use GitHub CLI (`gh`) or API to create a PR
- PR body includes the vulnerability description + VEX document
- Branch name: `picosentry/fix/{package}-{cve-id}`
- Commit message: `fix: bump {package} from {from} to {to} ({cve})`

The PR generation is optional and separately enabled (not everyone wants a PR; some want a local manifest edit first).

### CLI additions

```
picosentry scan /path --fix                 # modify local manifests
picosentry scan /path --fix --pr            # open PR
picosentry scan /path --fix --pr --repo org/repo --token ghp_xxx
picosentry scan /path --fix --dry-run       # show what would change
picosentry scan /path --vex                 # generate VEX only
```

### Verification

- `--fix --dry-run` shows RemediationSteps for known-bad fixture
- `--fix` modifies the manifest file correctly
- Re-scan after fix produces 0 findings for the remediated CVE
- VEX document from `--vex` validates against OpenVEX JSON schema
- VEX "not_affected" entries match unreachable findings 1:1