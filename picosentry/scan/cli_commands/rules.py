from __future__ import annotations

import argparse
import json

NAME = "rules"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="List available detector rules")
    parser.add_argument("--json", "-j", action="store_true", dest="json_output", help="Output rules as JSON")


def cmd(args: argparse.Namespace) -> int:
    from picosentry.scan.rules import RULE_INFO

    rule_ids = sorted(RULE_INFO.keys())
    if args.json_output:
        rules_data = []
        for rule_id in rule_ids:
            info = RULE_INFO[rule_id]
            rules_data.append(
                {
                    "rule_id": rule_id,
                    "name": info.get("name", ""),
                    "description": info.get("description", ""),
                    "severity": info.get("severity", ""),
                    "category": info.get("category", ""),
                    "helpUri": info.get("helpUri", ""),
                }
            )
        print(json.dumps(rules_data, indent=2, sort_keys=False))
    else:
        print(f"Available detector rules ({len(rule_ids)}):\n")
        for rule_id in rule_ids:
            info = RULE_INFO[rule_id]
            desc = info.get("description", "No description")
            sev = info.get("severity", "?")
            cat = info.get("category", "?")
            name = info.get("name", "?")
            print(f"  {rule_id}  {name:<25} [{sev:>8}]  {desc}  ({cat})")
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
