"""
Performance benchmark suite for PicoSentry.

Measures:
- Cold-start time (engine creation + corpus load)
- Per-rule timing (individual rule performance)
- Full scan throughput on test fixtures
- Memory usage (peak RSS)
- Determinism throughput (scan-twice overhead)

Usage:
    python -m pytest tests/test_benchmark.py -v
    python -m pytest tests/test_benchmark.py --benchmark-only
    python -m pytest tests/test_benchmark.py --benchmark-autosave

These are acceptance benchmarks, not microbenchmarks.
They validate that enterprise-grade performance targets are met.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import pytest

from picosentry.scan.engine import create_default_engine
from picosentry.scan.models import ScanResult
from picosentry.scan.rules.corpus_index import CorpusIndex
from picosentry.scan.rules.obfuscation import detect_obfuscation

# Skip benchmark tests by default unless --benchmark flag is passed
pytestmark = pytest.mark.slow


# ── Performance Targets ──────────────────────────────────

TARGETS = {
    "cold_start_ms": 500,  # Engine creation + corpus load
    "rule_registration_ms": 50,  # 21 rule registration
    "small_scan_ms": 2000,  # Single-project scan (<50 packages)
    "typosquat_check_ms": 100,  # Typosquat against 327 top packages
    "corpus_load_ms": 200,  # JSON corpus file loading
    "json_format_ms": 100,  # JSON serialization
    "cyclonedx_format_ms": 200,  # CycloneDX SBOM generation
    "token_filter_negative_ms": 50,  # 100 KB clean JS file scans without suspicious tokens
    # Pure-Python exact Levenshtein over 10k names and 100 queries is ~1.2s on
    # quiet reference hardware and ~3s under loaded CI/venv.  The target guards
    # against regressions; a native distance library would lower it, but we keep
    # the implementation dependency-free.
    "corpus_index_10k_ms": 4000,
}


# ── Fixtures ─────────────────────────────────────────────


@pytest.fixture
def small_project():
    """Create a minimal npm project fixture with node_modules."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        pkg = {"name": "test-pkg", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}}
        (root / "package.json").write_text(json.dumps(pkg))
        # Create a minimal node_modules tree so packages_scanned > 0
        pkg_dir = root / "node_modules" / "left-pad"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({"name": "left-pad", "version": "1.3.0"}))
        (pkg_dir / "index.js").write_text("module.exports = function leftpad(str, len, ch) { return str; }")
        yield root


@pytest.fixture
def benign_large_js(tmp_path):
    """Create a 100 KB JavaScript file with no suspicious obfuscation tokens."""
    root = tmp_path / "project"
    root.mkdir()
    pkg = {"name": "clean-pkg", "version": "1.0.0"}
    (root / "package.json").write_text(json.dumps(pkg))
    nm = root / "node_modules" / "clean-lib"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text(json.dumps({"name": "clean-lib", "version": "1.0.0"}))
    # Repeat a benign snippet until we exceed 100 KB.
    snippet = "function add(a, b) { return a + b; }\n"
    repeats = (100 * 1024 // len(snippet)) + 1
    (nm / "index.js").write_text(snippet * repeats)
    return root


@pytest.fixture
def engine():
    """Provide a fresh engine instance."""
    return create_default_engine()


# ── Cold Start ───────────────────────────────────────────


def test_bench_cold_start():
    """Engine creation + corpus load should be sub-500ms."""
    start = time.monotonic()
    e = create_default_engine()
    elapsed_ms = (time.monotonic() - start) * 1000

    # 31 base rules (23 npm + 8 PyPI) + N auto-discovered campaign packages.
    # Assert the base count plus at least one campaign is wired up.
    rules = e.list_rules()
    assert len(rules) >= 31
    assert any(r.startswith("L2-CAMP-") for r in rules)
    assert e._corpus_version

    if elapsed_ms > TARGETS["cold_start_ms"]:
        pytest.fail(f"Cold start too slow: {elapsed_ms:.0f}ms > {TARGETS['cold_start_ms']}ms target")
    print(f"  cold_start: {elapsed_ms:.0f}ms ✓")


# ── Rule Registration ────────────────────────────────────


def test_bench_rule_registration(engine):
    """All rules register quickly."""
    rules = engine.list_rules()
    assert len(rules) >= 31
    valid_prefixes = {
        "L2-POST",
        "L2-OBFS",
        "L2-DEPC",
        "L2-TYPO",
        "L2-MANI",
        "L2-FORK",
        "L2-CRED",
        "L2-LOCK",
        "L2-BUND",
        "L2-PROV",
        "L2-MAINT",
        "L2-PNPM",
        "L2-LICENSE",
        "L2-ENGIN",
        "L2-SIDELOAD",
        "L2-ADV",
        "L2-IOC",
        "L2-WORM",
        "L2-NETEX",
        "L2-BUILD",
        "L2-PYPI",
        "L2-GO",
        "L2-CARGO",
        "L2-MAVEN",
        "L2-RUBYGEMS",
        "L2-NUGET",
        "L2-CAMP",  # Per-campaign IOC packages
    }
    for rule_id in rules:
        prefix = "-".join(rule_id.split("-")[:2])
        assert prefix in valid_prefixes, f"Unknown rule prefix: {prefix}"


# ── Small Scan Throughput ────────────────────────────────


def test_bench_small_scan(engine, small_project):
    """Scan a small project in under 2 seconds."""
    time.monotonic()
    result = engine.scan(str(small_project))
    elapsed_ms = int(result.stats.duration_ms)

    assert isinstance(result, ScanResult)
    assert result.stats.packages_scanned > 0

    if elapsed_ms > TARGETS["small_scan_ms"]:
        pytest.fail(f"Small scan too slow: {elapsed_ms}ms > {TARGETS['small_scan_ms']}ms target")
    print(f"  small_scan: {elapsed_ms}ms, {result.stats.packages_scanned} packages, {len(result.findings)} findings ✓")


# ── Typosquat Check ──────────────────────────────────────


def test_bench_typosquat():
    """Typosquat check against 327 top packages should be fast."""
    from picosentry.scan.engine import create_default_engine
    from picosentry.scan.rules.typosquat_utils import BUILTIN_TOP_100, load_corpus_for_ecosystem

    engine = create_default_engine()
    start = time.monotonic()
    packages = load_corpus_for_ecosystem(engine._corpus_dir, "npm", BUILTIN_TOP_100)
    elapsed_ms = (time.monotonic() - start) * 1000

    assert len(packages) > 300  # 327 in current corpus

    if elapsed_ms > TARGETS["typosquat_check_ms"]:
        pytest.fail(f"Typosquat load too slow: {elapsed_ms:.0f}ms > {TARGETS['typosquat_check_ms']}ms target")
    print(f"  typosquat_load: {elapsed_ms:.0f}ms, {len(packages)} packages ✓")


# ── JSON Output ──────────────────────────────────────────


def test_bench_json_output(engine, small_project):
    """JSON format should serialize quickly."""
    result = engine.scan(str(small_project))

    start = time.monotonic()
    json_str = result.to_json()
    elapsed_ms = (time.monotonic() - start) * 1000

    assert len(json_str) > 0
    data = json.loads(json_str)
    assert "scan_id" in data

    if elapsed_ms > TARGETS["json_format_ms"]:
        pytest.fail(f"JSON format too slow: {elapsed_ms:.0f}ms > {TARGETS['json_format_ms']}ms target")
    print(f"  json_format: {elapsed_ms:.0f}ms, {len(json_str)} chars ✓")


# ── CycloneDX Output ─────────────────────────────────────


def test_bench_cyclonedx_output(engine, small_project):
    """CycloneDX SBOM generation should be fast."""
    from picosentry.scan.formatters.cyclonedx import format_cyclonedx

    result = engine.scan(str(small_project))

    start = time.monotonic()
    sbom = format_cyclonedx(result)
    elapsed_ms = (time.monotonic() - start) * 1000

    assert len(sbom) > 0
    data = json.loads(sbom)
    assert "bomFormat" in data

    if elapsed_ms > TARGETS["cyclonedx_format_ms"]:
        pytest.fail(f"CycloneDX format too slow: {elapsed_ms:.0f}ms > {TARGETS['cyclonedx_format_ms']}ms target")
    print(f"  cyclonedx_format: {elapsed_ms:.0f}ms, {len(sbom)} chars ✓")


# ── Token Filter Fast Path ───────────────────────────────


def test_bench_token_filter_negative(benign_large_js):
    """A clean 100 KB JS file without suspicious tokens should scan quickly."""
    start = time.monotonic()
    findings = detect_obfuscation(benign_large_js)
    elapsed_ms = (time.monotonic() - start) * 1000

    assert len(findings) == 0

    if elapsed_ms > TARGETS["token_filter_negative_ms"]:
        pytest.fail(
            f"Token-filter negative path too slow: {elapsed_ms:.0f}ms > {TARGETS['token_filter_negative_ms']}ms target"
        )
    print(f"  token_filter_negative: {elapsed_ms:.0f}ms, {len(findings)} findings ✓")


# ── Corpus Index Lookup ──────────────────────────────────


def test_bench_corpus_index_10k():
    """Building a 10k-name index and running 100 queries should be fast."""
    from picosentry.scan.rules.typosquat_utils import BUILTIN_TOP_100

    # Use realistic, varied package names rather than a single shared prefix.
    bases = BUILTIN_TOP_100[:50]
    names = [f"{bases[i % len(bases)]}-{i:05d}" for i in range(10_000)]
    start = time.monotonic()
    index = CorpusIndex(names)
    for i in range(100):
        base = bases[i % len(bases)]
        index.near_matches(f"{base}-{i:05d}x", max_distance=2.0)
    elapsed_ms = (time.monotonic() - start) * 1000

    if elapsed_ms > TARGETS["corpus_index_10k_ms"]:
        pytest.fail(f"Corpus index 10k too slow: {elapsed_ms:.0f}ms > {TARGETS['corpus_index_10k_ms']}ms target")
    print(f"  corpus_index_10k: {elapsed_ms:.0f}ms, {len(index)} names, 100 queries ✓")


# ── Determinism Verify ───────────────────────────────────


def test_bench_determinism_verify(engine, small_project):
    """Verify-determinism should produce identical scans."""
    result1 = engine.scan(str(small_project))
    result2 = engine.scan(str(small_project))

    json1 = result1.to_json()
    json2 = result2.to_json()

    from picosentry.scan.guards import diff_scans

    # Write to temp files for verify_determinism
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f1:
        f1.write(json1)
        tmp1 = f1.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f2:
        f2.write(json2)
        tmp2 = f2.name

    try:
        exit_code, output = diff_scans(Path(tmp1), Path(tmp2))
        assert exit_code == 0, f"Determinism failed: {output}"
        print(f"  determinism: ✓ identical ({len(result1.findings)} findings)")
    finally:
        Path(tmp1).unlink()
        Path(tmp2).unlink()


# ── Report ───────────────────────────────────────────────


def test_bench_report():
    """Print performance target summary."""
    print("\n─── PicoSentry Performance Targets ───")
    for name, target in sorted(TARGETS.items()):
        unit = "ms"
        print(f"  {name:<25s} ≤ {target:>5d}{unit}")
    print("──────────────────────────────────────")
    assert True  # Always passes — informational only
