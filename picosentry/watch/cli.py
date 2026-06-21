from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from picosentry.watch import __version__
from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.health import health_check
from picosentry.watch.output_guard import OutputGuard
from picosentry.watch.prompt_guard import PromptGuard


def _scan_prompt(args: argparse.Namespace, config: PicoWatchConfig) -> None:
    guard = PromptGuard(config=config)

    if args.text:
        text = args.text
    elif args.file:
        try:
            text = Path(args.file).read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            print("Error: Provide --text or --file, or pipe input to stdin", file=sys.stderr)
            sys.exit(1)
        text = sys.stdin.read()

    result = guard.check(text)

    output = {
        "blocked": result.blocked,
        "score": result.score,
        "verdict": result.verdict.value,
        "rules_matched": result.rules_matched,
        "corpus_hash": result.corpus_hash,
        "corpus_version": result.corpus_version,
        "duration_ms": result.duration_ms,
    }

    print(json.dumps(output, indent=2))

    if args.verify_determinism:
        result2 = guard.check(text)
        if result.score != result2.score or result.rules_matched != result2.rules_matched:
            print("DETERMINISM CHECK FAILED: results differ between runs", file=sys.stderr)
            sys.exit(1)
        else:
            print("DETERMINISM CHECK PASSED: results identical", file=sys.stderr)

    if result.blocked:
        sys.exit(2)  # Exit code 2 = blocked prompt


def _validate_output(args: argparse.Namespace, config: PicoWatchConfig) -> None:
    guard = OutputGuard(config=config)

    try:
        schema_text = Path(args.schema).read_text(encoding="utf-8")
        schema = json.loads(schema_text)
    except FileNotFoundError:
        print(f"Error: Schema file not found: {args.schema}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON schema: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        output_text = Path(args.output).read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"Error: Output file not found: {args.output}", file=sys.stderr)
        sys.exit(1)

    result = guard.validate(output_text, schema=schema)

    output = {
        "valid": result.valid,
        "score": result.score,
        "verdict": result.verdict.value,
        "violations": result.violations,
        "corpus_hash": result.corpus_hash,
        "corpus_version": result.corpus_version,
        "duration_ms": result.duration_ms,
        "redacted": result.redacted,
    }

    print(json.dumps(output, indent=2))

    if not result.valid:
        sys.exit(2)  # Exit code 2 = invalid output


def _serve(args: argparse.Namespace, config: PicoWatchConfig) -> None:
    from picosentry.watch.server import run_server

    print(f"PicoWatch {__version__} starting on {args.host}:{args.port}", file=sys.stderr)

    guard = PromptGuard(config=config)
    h = health_check(
        rules_loaded=len(guard.rules),
        corpus_hash=guard.corpus_hash,
        corpus_version=guard.corpus_version,
    )
    health_info = {
        "healthy": h.healthy,
        "rules_loaded": h.rules_loaded,
        "corpus_hash": h.corpus_hash,
    }
    print(f"Health: {json.dumps(health_info, indent=2)}", file=sys.stderr)

    auth_status = "enabled" if config.api_key else "disabled (set PICOWATCH_API_KEY to enable)"
    print(f"API key auth: {auth_status}", file=sys.stderr)

    print("Endpoints:", file=sys.stderr)
    print("  POST /v1/scan/prompt  — Scan prompt for injection", file=sys.stderr)
    print("  POST /v1/scan/output  — Validate LLM output", file=sys.stderr)
    print("  GET  /v1/health       — Health check", file=sys.stderr)
    print("  GET  /metrics          — Prometheus metrics", file=sys.stderr)
    print("  GET  /v1/rules         — List active rules", file=sys.stderr)
    print("  GET  /v1/rules/:id     — Rule detail", file=sys.stderr)

    run_server(config=config, host=args.host, port=args.port)


def _rules(_args: argparse.Namespace, config: PicoWatchConfig) -> None:
    guard = PromptGuard(config=config)
    rules_list = [
        {"id": r.id, "category": r.category, "weight": r.weight, "description": r.description} for r in guard.rules
    ]
    print(json.dumps(rules_list, indent=2))


def _run_picoshogun_plugin() -> None:
    from picosentry.watch.picoshogun import PicoWatchPlugin

    plugin = PicoWatchPlugin()
    h = plugin.health()
    print(f"PicoWatch PicoShogun plugin v{h['version']} loaded", file=sys.stderr)
    print("  Layers: L5 (prompt guard) + L6 (output guard)", file=sys.stderr)
    print(f"  Rules loaded: {h['rules_loaded']}", file=sys.stderr)
    print(f"  Corpus hash: {h['corpus_hash']}", file=sys.stderr)
    print(f"  Corpus version: {h['corpus_version']}", file=sys.stderr)
    print("Ready for PicoShogun event bus integration.", file=sys.stderr)

    print(json.dumps({"plugin": "picowatch", "status": "ready", **h}, indent=2))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="picowatch",
        description="PicoWatch — LLM defender with telemetry",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--verify-determinism", action="store_true", help="Run twice and compare results")
    parser.add_argument("--picoshogun-plugin", action="store_true", help="Run as PicoShogun plugin (ADR-005)")
    parser.add_argument("--version", action="version", version=f"PicoWatch {__version__}")
    sub = parser.add_subparsers(dest="command")

    sp = sub.add_parser("scan-prompt", help="Scan a prompt for injection patterns")
    sp.add_argument("--text", "-t", help="Prompt text to scan")
    sp.add_argument("--file", "-f", help="File containing prompt text")

    vo = sub.add_parser("validate-output", help="Validate LLM output against a schema")
    vo.add_argument("--schema", "-s", required=True, help="JSON schema file")
    vo.add_argument("--output", "-o", required=True, help="LLM output file")

    se = sub.add_parser("serve", help="Start HTTP daemon (FastAPI + uvicorn)")
    se.add_argument("--host", default="127.0.0.1", help="Bind host")
    se.add_argument("--port", "-p", type=int, default=8766, help="Bind port")

    sub.add_parser("rules", help="List active defense rules")

    sub.add_parser("health", help="Show health status")

    args = parser.parse_args(argv)
    config = PicoWatchConfig.from_env()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.picoshogun_plugin:
        _run_picoshogun_plugin()
    elif args.command == "scan-prompt":
        _scan_prompt(args, config)
    elif args.command == "validate-output":
        _validate_output(args, config)
    elif args.command == "serve":
        _serve(args, config)
    elif args.command == "rules":
        _rules(args, config)
    elif args.command == "health":
        guard = PromptGuard(config=config)
        h = health_check(
            rules_loaded=len(guard.rules),
            corpus_hash=guard.corpus_hash,
            corpus_version=guard.corpus_version,
        )
        print(
            json.dumps(
                {
                    "healthy": h.healthy,
                    "version": h.version,
                    "rules_loaded": h.rules_loaded,
                    "corpus_hash": h.corpus_hash,
                    "corpus_version": h.corpus_version,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
