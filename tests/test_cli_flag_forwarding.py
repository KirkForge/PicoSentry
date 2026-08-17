"""Unified CLI must forward flags to the inner sandbox/watch commands instead of dropping them."""

from __future__ import annotations

import argparse
from unittest.mock import patch

from picosentry.cli_commands import sandbox, watch  # noqa: F401
from picosentry.cli_commands import add_all_arguments, run


def _dispatch(argv: list[str]) -> object:
    parser = argparse.ArgumentParser(prog="picosentry")
    subparsers = parser.add_subparsers(dest="command")
    add_all_arguments(subparsers)
    args = parser.parse_args(argv)
    return run(args.command, args)


def test_sandbox_analyze_forwards_flags() -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        code = _dispatch(["sandbox", "analyze", "--input", "events.json", "--format", "json", "--exit-code"])
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[0] == "analyze"
    assert argv[argv.index("--input") + 1] == "events.json"
    assert argv[argv.index("--format") + 1] == "json"
    assert "--exit-code" in argv


def test_sandbox_analyze_rejects_unsupported_flag(capsys) -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        code = _dispatch(["sandbox", "analyze", "--input", "events.json", "--policy", "p.json"])
    assert code == 2
    assert "not supported by 'sandbox analyze'" in capsys.readouterr().err
    inner.assert_not_called()


def test_sandbox_pipeline_forwards_flags_and_command() -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        code = _dispatch(
            ["sandbox", "pipeline", "echo", "hi", "--policy", "p.json", "--backend", "subprocess", "--timeout", "5"]
        )
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[0] == "pipeline"
    assert argv[argv.index("--policy") + 1] == "p.json"
    assert argv[argv.index("--backend") + 1] == "subprocess"
    assert argv[argv.index("--timeout") + 1] == "5"
    assert argv[argv.index("--") + 1 :] == ["echo", "hi"]


def test_sandbox_pipeline_rejects_unsupported_flag(capsys) -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        code = _dispatch(["sandbox", "pipeline", "echo", "hi", "--verify-determinism"])
    assert code == 2
    assert "not supported by 'sandbox pipeline'" in capsys.readouterr().err
    inner.assert_not_called()


def test_watch_forwards_verify_determinism() -> None:
    with patch("picosentry.watch.cli.main", return_value=None) as inner:
        code = _dispatch(["watch", "--verify-determinism", "scan-prompt", "--text", "hello"])
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[0] == "--verify-determinism"
    assert argv[1] == "scan-prompt"
    assert argv[argv.index("--text") + 1] == "hello"


def test_watch_forwards_picoshogun_plugin() -> None:
    with patch("picosentry.watch.cli.main", return_value=None) as inner:
        code = _dispatch(["watch", "--picoshogun-plugin", "scan-prompt", "--text", "hello"])
    assert code == 0
    assert "--picoshogun-plugin" in inner.call_args[0][0]
