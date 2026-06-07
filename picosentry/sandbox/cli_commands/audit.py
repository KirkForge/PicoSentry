"""`audit` subcommand — query the audit log.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/cli.py``.
"""
from __future__ import annotations

import argparse
import json
import sys

NAME = "audit"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Query the audit log")
    parser.add_argument("--event-type", help="Filter by event type")
    parser.add_argument("--actor", help="Filter by actor")
    parser.add_argument("--target", help="Filter by target")
    parser.add_argument("--since", help="Events after this ISO timestamp")
    parser.add_argument("--until", help="Events before this ISO timestamp")
    parser.add_argument("--limit", type=int, default=100, help="Max results")
    parser.add_argument("--verify", action="store_true", help="Verify chain integrity")
    parser.add_argument("--stats", action="store_true", help="Show audit log statistics")


def cmd(args: argparse.Namespace) -> int:
    """Query the audit log."""
    from picosentry.sandbox.audit import AuditEventType, get_audit_logger

    audit = get_audit_logger()

    if args.verify:
        violations = audit.verify_chain()
        if violations:
            print("✗ Audit log chain integrity VIOLATED:")
            for v in violations:
                print(f"  - {v}")
            return 1
        else:
            print("✓ Audit log chain integrity verified")
            return 0

    if args.stats:
        stats = audit.get_stats()
        print(json.dumps(stats, sort_keys=True, indent=2))
        return 0

    event_type = None
    if args.event_type:
        try:
            event_type = AuditEventType(args.event_type)
        except ValueError:
            print(f"Unknown event type: {args.event_type}", file=sys.stderr)
            return 1

    events = audit.query(
        event_type=event_type,
        actor=args.actor,
        target=args.target,
        since=args.since,
        until=args.until,
        limit=args.limit,
    )

    for evt in events:
        print(f"[{evt.timestamp}] {evt.event_type.value} actor={evt.actor} target={evt.target}")
        if evt.detail:
            print(f"  {evt.detail}")

    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
