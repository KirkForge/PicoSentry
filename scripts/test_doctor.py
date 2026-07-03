#!/usr/bin/env python3
"""PicoSentry test doctor — run all CI-quality checks in parallel.

This is the local equivalent of the GitHub Actions matrix. It executes the
lint, type-check and per-area pytest suites concurrently, then prints a
unified pass/fail summary.

Usage:
    python scripts/test_doctor.py
    python scripts/test_doctor.py --no-format   # skip ruff format check
    python scripts/test_doctor.py --areas scan watch serve  # run only listed areas
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Check:
    name: str
    command: list[str]
    timeout: int = 600


@dataclass
class Result:
    check: Check
    returncode: int
    stdout: str
    stderr: str
    elapsed: float


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


def _pytest_xdist_workers(args: argparse.Namespace) -> str:
    """Choose pytest-xdist workers for each area.

    When the doctor runs many areas concurrently we can easily oversubscribe
    the machine and make timing-sensitive tests flaky. Cap each pytest
    process to a fair slice of the CPU count so the total pytest worker
    count stays close to the available cores.
    """
    if args.workers <= 1:
        return "auto"
    cores = os.cpu_count() or 4
    # Reserve a little headroom for the main thread and non-pytest checks.
    return str(max(1, cores // args.workers))


def build_checks(args: argparse.Namespace) -> list[Check]:
    checks: list[Check] = []

    checks.append(Check("ruff check", ["ruff", "check", "picosentry/", "tests/", "scripts/"]))

    if args.format:
        checks.append(Check("ruff format", ["ruff", "format", "--check", "picosentry/", "tests/", "scripts/"]))

    checks.append(Check("mypy", ["mypy", "picosentry/", "--ignore-missing-imports"], timeout=300))

    xdist = _pytest_xdist_workers(args)

    areas = args.areas or ["scan", "watch", "serve", "sandbox", "integration"]
    for area in areas:
        path = ROOT / "tests" / area
        if area == "integration":
            path = ROOT / "tests" / "integration"
        if not path.exists():
            continue
        checks.append(
            Check(
                f"pytest tests/{area}",
                [
                    _python(),
                    "-m",
                    "pytest",
                    str(path),
                    "-v",
                    "--tb=short",
                    "--timeout=120",
                    "-n",
                    xdist,
                    "--dist=loadfile",
                ],
                timeout=900,
            )
        )

    # Top-level repository tests that live outside the per-area folders.
    if not args.areas:
        top_level = list((ROOT / "tests").glob("test_*.py"))
        if top_level:
            checks.append(
                Check(
                    "pytest top-level",
                    [_python(), "-m", "pytest"]
                    + [str(p) for p in top_level]
                    + ["-v", "--tb=short", "--timeout=120", "-n", xdist, "--dist=loadfile"],
                    timeout=600,
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PicoSentry CI checks in parallel")
    parser.add_argument("--areas", nargs="+", help="Limit to these test areas")
    parser.add_argument("--no-format", dest="format", action="store_false", default=True, help="Skip ruff format check")
    parser.add_argument("--workers", type=int, default=min(8, (os.cpu_count() or 4)), help="Parallel workers")
    args = parser.parse_args()

    checks = build_checks(args)
    if not checks:
        print("No checks to run.")
        return 0

    print(f"Running {len(checks)} checks with up to {args.workers} workers ...\n")

    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
