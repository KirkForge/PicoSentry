"""Unified CLI command registry for `picosentry`.

Each subcommand lives in its own module and exports two symbols:

- `add_arguments(subparsers: argparse._SubParsersAction) -> None`
- `cmd(args: argparse.Namespace) -> int | None` — returns exit code, or None
  for commands that handle their own exit.

This keeps `picosentry.cli` focused on dispatch and avoids the God-module
problem of wiring every subcommand by hand.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any


class CommandModule:
    """Small wrapper around a command module for type safety."""

    def __init__(self, name: str, add_arguments: Callable[[argparse._SubParsersAction], None], cmd: Callable[[argparse.Namespace], Any]):
        self.name = name
        self.add_arguments = add_arguments
        self.cmd = cmd


_COMMANDS: dict[str, CommandModule] = {}


def register(name: str, add_arguments: Callable[[argparse._SubParsersAction], None], cmd: Callable[[argparse.Namespace], Any]) -> None:
    """Register a top-level subcommand."""
    _COMMANDS[name] = CommandModule(name, add_arguments, cmd)


def registered_commands() -> dict[str, CommandModule]:
    """Return a snapshot of registered commands."""
    return dict(_COMMANDS)


def add_all_arguments(subparsers: argparse._SubParsersAction) -> None:
    """Wire every registered command into the root parser."""
    for module in _COMMANDS.values():
        module.add_arguments(subparsers)


def run(command: str, args: argparse.Namespace) -> Any:
    """Dispatch to a registered command."""
    module = _COMMANDS.get(command)
    if module is None:
        raise KeyError(f"Unknown command: {command}")
    return module.cmd(args)
