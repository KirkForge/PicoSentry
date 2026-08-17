"""Unified CLI must forward flags to the inner sandbox/watch commands instead of dropping them."""

from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest

from picosentry.cli_commands import sandbox, scan, watch  # noqa: F401
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


# ─── `picosentry check` → `picosentry.scan check` ────────────────────────


def test_check_forwards_flags_and_target() -> None:
    with patch("picosentry.scan.cli.main", return_value=0) as inner:
        code = _dispatch(["check", "myproj", "--fail-on", "high", "--check-corpus-age", "7"])
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[0] == "check"
    assert argv[argv.index("--fail-on") + 1] == "high"
    assert argv[argv.index("--check-corpus-age") + 1] == "7"
    assert argv[-1] == "myproj"


def test_check_forwards_rule_list_and_booleans() -> None:
    with patch("picosentry.scan.cli.main", return_value=0) as inner:
        code = _dispatch(["check", "--rules", "L2-POST-001", "L2-OBFS-001", "--enterprise"])
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[argv.index("--rules") + 1 : argv.index("--rules") + 3] == ["L2-POST-001", "L2-OBFS-001"]
    assert "--enterprise" in argv


def test_check_forwards_defaults_not_at_all() -> None:
    with patch("picosentry.scan.cli.main", return_value=0) as inner:
        _dispatch(["check"])
    assert inner.call_args[0][0] == ["check"]


def test_check_rejects_unsupported_flag(capsys) -> None:
    with patch("picosentry.scan.cli.main", return_value=0) as inner, pytest.raises(SystemExit) as excinfo:
        _dispatch(["check", "--format", "json", "."])
    assert excinfo.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
    inner.assert_not_called()


# ─── `picosentry advisories fetch` → `picosentry.scan advisories fetch` ──


def test_advisories_fetch_forwards_url_and_flags() -> None:
    with patch("picosentry.scan.cli.main", return_value=0) as inner:
        code = _dispatch(["advisories", "fetch", "https://example.com/db.zip", "--verify-crypto", "-o", "/tmp/adv"])
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[0:2] == ["advisories", "fetch"]
    assert argv[argv.index("--output") + 1] == "/tmp/adv"
    assert "--verify-crypto" in argv
    assert "https://example.com/db.zip" in argv


def test_advisories_without_action_forwards_for_usage() -> None:
    with patch("picosentry.scan.cli.main", return_value=1) as inner:
        code = _dispatch(["advisories"])
    assert code == 1
    assert inner.call_args[0][0] == ["advisories"]


# ─── `picosentry cluster <sub>` → `picosentry.sandbox cluster <sub>` ─────


def test_cluster_join_forwards_flags_and_peer() -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        code = _dispatch(["cluster", "join", "10.0.0.2:8444", "--port", "9444", "--backend", "sqlite"])
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[0:2] == ["cluster", "join"]
    assert argv[argv.index("--port") + 1] == "9444"
    assert argv[argv.index("--backend") + 1] == "sqlite"
    assert argv[-1] == "10.0.0.2:8444"


def test_cluster_status_forwards_format() -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        code = _dispatch(["cluster", "status", "--format", "json"])
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[0:2] == ["cluster", "status"]
    assert argv[argv.index("--format") + 1] == "json"


def test_cluster_rotate_token_forwards_flags() -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        code = _dispatch(["cluster", "rotate-token", "--new-token", "tok-2", "--retire-after", "60"])
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[0:2] == ["cluster", "rotate-token"]
    assert argv[argv.index("--new-token") + 1] == "tok-2"
    assert argv[argv.index("--retire-after") + 1] == "60"


def test_cluster_leave_forwards_bare() -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        code = _dispatch(["cluster", "leave"])
    assert code == 0
    assert inner.call_args[0][0] == ["cluster", "leave"]


def test_cluster_join_env_default_token_not_forwarded(monkeypatch) -> None:
    """Token from env stays implicit — the inner CLI re-applies its own env default."""
    monkeypatch.setenv("PICODOME_CLUSTER_TOKEN", "env-secret")
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        _dispatch(["cluster", "join", "peer:8444"])
    argv = inner.call_args[0][0]
    assert "--cluster-token" not in argv


def test_cluster_join_explicit_token_forwarded(monkeypatch) -> None:
    monkeypatch.setenv("PICODOME_CLUSTER_TOKEN", "env-secret")
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        _dispatch(["cluster", "join", "peer:8444", "--cluster-token", "explicit"])
    argv = inner.call_args[0][0]
    assert argv[argv.index("--cluster-token") + 1] == "explicit"


def test_cluster_join_rejects_unsupported_flag(capsys) -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner, pytest.raises(SystemExit) as excinfo:
        _dispatch(["cluster", "join", "peer:8444", "--policy", "p.json"])
    assert excinfo.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
    inner.assert_not_called()


# ─── `--backend landlock` forwarding ─────────────────────────────────────


def test_sandbox_pipeline_backend_landlock_forwarded() -> None:
    with patch("picosentry.sandbox.cli.main", return_value=0) as inner:
        code = _dispatch(["sandbox", "pipeline", "echo", "hi", "--backend", "landlock"])
    assert code == 0
    argv = inner.call_args[0][0]
    assert argv[argv.index("--backend") + 1] == "landlock"


def test_unified_parser_accepts_backend_landlock() -> None:
    parser = argparse.ArgumentParser(prog="picosentry")
    subparsers = parser.add_subparsers(dest="command")
    add_all_arguments(subparsers)
    args = parser.parse_args(["sandbox", "--backend", "landlock"])
    assert args.backend == "landlock"
