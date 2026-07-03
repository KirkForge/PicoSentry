#!/usr/bin/env python3
"""PicoSentry test doctor — run all CI-quality checks in parallel.

This is the local equivalent of the GitHub Actions matrix. It executes the
lint, type-check and per-area pytest suites concurrently, then prints a
unified pass/fail summary.

Usage:
    python scripts/test_doctor.py
    python scripts/test_doctor.py --no-format   # skip ruff format check
    python scripts/test_doctor.py --areas scan watch serve  # run only listed areas
    python scripts/test_doctor.py --fix         # auto-fix ruff issues and format
    python scripts/test_doctor.py --ci          # exact CI commands (no xdist)
    python scripts/test_doctor.py --report doctor.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Check:
    name: str
    command: list[str]
    timeout: int = 600
    ci_equivalent: str = ""


@dataclass
class Result:
    check: Check
    returncode: int
    stdout: str
    stderr: str
    elapsed: float


@dataclass
class DoctorConfig:
    areas: list[str] | None = None
    format: bool = True
    fix: bool = False
    ci: bool = False
    verbose: bool = False
    workers: int = 4
    report: str = ""

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> DoctorConfig:
        return cls(
            areas=list(args.areas) if args.areas else None,
            format=args.format,
            fix=args.fix,
            ci=args.ci,
            verbose=args.verbose,
            workers=args.workers,
            report=args.report or "",
        )


def _run_check(check: Check) -> Result:
    start = time.monotonic()
    proc = subprocess.run(
        check.command,
        capture_output=True,
        text=True,
        timeout=check.timeout,
        cwd=ROOT,
        env={**os.environ, "PYTEST_TIMEOUT": "120"},
        check=False,
    )
    elapsed = time.monotonic() - start
    return Result(
        check=check,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        elapsed=elapsed,
    )


def _python() -> str:
    return sys.executable


def _pytest_xdist_workers(config: DoctorConfig) -> str:
    """Choose pytest-xdist workers for each area.

    When the doctor runs many areas concurrently we can easily oversubscribe
    the machine and make timing-sensitive tests flaky. Cap each pytest
    process to a fair slice of the CPU count so the total pytest worker
    count stays close to the available cores.
    """
    if config.ci:
        # CI runs each area serially; match that locally when --ci is used.
        return "0"
    if config.workers <= 1:
        return "auto"
    cores = os.cpu_count() or 4
    # Reserve a little headroom for the main thread and non-pytest checks.
    return str(max(1, cores // config.workers))


def _pytest_common_args(_config: DoctorConfig, xdist: str) -> list[str]:
    args = [_python(), "-m", "pytest", "-v", "--tb=short", "--timeout=120"]
    if xdist != "0":
        args.extend(["-n", xdist, "--dist=loadfile"])
    return args


def build_checks(config: DoctorConfig) -> list[Check]:
    checks: list[Check] = []

    if config.fix:
        checks.append(
            Check(
                "ruff fix",
                ["ruff", "check", "--fix", "picosentry/", "tests/", "scripts/"],
                ci_equivalent="ruff check --fix picosentry/ tests/ scripts/",
            )
        )
        checks.append(
            Check(
                "ruff format",
                ["ruff", "format", "picosentry/", "tests/", "scripts/"],
                ci_equivalent="ruff format picosentry/ tests/ scripts/",
            )
        )
    else:
        checks.append(
            Check(
                "ruff check",
                ["ruff", "check", "picosentry/", "tests/", "scripts/"],
                ci_equivalent="ruff check picosentry/ tests/ scripts/",
            )
        )
        if config.format:
            checks.append(
                Check(
                    "ruff format",
                    ["ruff", "format", "--check", "picosentry/", "tests/", "scripts/"],
                    ci_equivalent="ruff format --check picosentry/ tests/ scripts/",
                )
            )

    checks.append(
        Check(
            "mypy",
            ["mypy", "picosentry/", "--ignore-missing-imports"],
            timeout=300,
            ci_equivalent="mypy picosentry/ --ignore-missing-imports",
        )
    )

    xdist = _pytest_xdist_workers(config)

    areas = config.areas or ["scan", "watch", "serve", "sandbox", "integration"]
    for area in areas:
        path = ROOT / "tests" / area
        if area == "integration":
            path = ROOT / "tests" / "integration"
        if not path.exists():
            continue
        cmd = [*_pytest_common_args(config, xdist), str(path)]
        checks.append(
            Check(
                f"pytest tests/{area}",
                cmd,
                timeout=900,
                ci_equivalent=f"python -m pytest tests/{area}/ -v --tb=short",
            )
        )

    # Top-level repository tests that live outside the per-area folders.
    if not config.areas:
        top_level = list((ROOT / "tests").glob("test_*.py"))
        if top_level:
            cmd = _pytest_common_args(config, xdist) + [str(p) for p in top_level]
            checks.append(
                Check(
                    "pytest top-level",
                    cmd,
                    timeout=600,
                    ci_equivalent="python -m pytest tests/test_*.py -v --tb=short",
                )
            )

    return checks


def _short_output(result: Result) -> str:
    text = (result.stdout + "\n" + result.stderr).strip()
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) <= 40:
        return text
    head = "\n".join(lines[:20])
    tail = "\n".join(lines[-20:])
    return f"{head}\n... ({len(lines) - 40} lines omitted) ...\n{tail}"


def _write_report(path: str, results: list[Result], config: DoctorConfig) -> None:
    payload: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "areas": config.areas,
            "format": config.format,
            "fix": config.fix,
            "ci": config.ci,
            "verbose": config.verbose,
            "workers": config.workers,
        },
        "results": [
            {
                "name": r.check.name,
                "command": r.check.command,
                "ci_equivalent": r.check.ci_equivalent,
                "returncode": r.returncode,
                "elapsed": round(r.elapsed, 3),
                "passed": r.returncode == 0,
                "stdout": r.stdout,
                "stderr": r.stderr,
            }
            for r in results
        ],
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.returncode == 0),
            "failed": sum(1 for r in results if r.returncode != 0),
            "wall_time": round(sum(r.elapsed for r in results), 3),
        },
    }
    out = Path(path)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nReport written to {out}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PicoSentry CI checks in parallel")
    parser.add_argument("--areas", nargs="+", help="Limit to these test areas")
    parser.add_argument("--no-format", dest="format", action="store_false", default=True, help="Skip ruff format check")
    parser.add_argument("--fix", action="store_true", help="Auto-fix ruff issues and apply ruff format")
    parser.add_argument("--ci", action="store_true", help="Run CI-equivalent commands (no pytest-xdist)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full output for passing checks too")
    parser.add_argument("--workers", type=int, default=min(8, (os.cpu_count() or 4)), help="Parallel workers")
    parser.add_argument("--report", help="Write a JSON report to this path")
    args = parser.parse_args()

    config = DoctorConfig.from_args(args)
    checks = build_checks(config)
    if not checks:
        print("No checks to run.")
        return 0

    mode = "CI-equivalent" if config.ci else "local-parallel"
    print(f"Running {len(checks)} checks with up to {config.workers} workers ({mode}) ...\n")

    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=config.workers) as pool:
        futures = {pool.submit(_run_check, c): c for c in checks}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.check.name)

    failed: list[Result] = []
    print("=" * 70)
    for result in results:
        status = "PASS" if result.returncode == 0 else "FAIL"
        symbol = "✓" if result.returncode == 0 else "✗"
        print(f"{symbol} {status:4} {result.check.name:30} ({result.elapsed:.1f}s)")
        if result.returncode != 0:
            failed.append(result)
        elif config.verbose:
            short = _short_output(result)
            if short:
                print(f"       {short[:200].replace(chr(10), ' ')}")
    print("=" * 70)

    if failed:
        print(f"\n{len(failed)} check(s) failed. Details:\n")
        for result in failed:
            print(f"--- {result.check.name} ---")
            print(_short_output(result))
            print()
        return 1

    total = sum(r.elapsed for r in results)
    print(f"\nAll checks passed in {total:.1f}s (wall time).")

    if config.report:
        _write_report(config.report, results, config)

    return 0


if __name__ == "__main__":
    sys.exit(main())
