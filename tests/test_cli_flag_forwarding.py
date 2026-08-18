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
    with patch("picosentry.scan.cli_commands.check.cmd", return_value=0) as inner:
        code = _dispatch(["check", "myproj", "--fail-on", "high", "--check-corpus-age", "7"])
    assert code == 0
    ns = inner.call_args[0][0]
    assert ns.target == "myproj"
    assert ns.fail_on == "high"
    assert ns.check_corpus_age == 7


def test_check_forwards_rule_list_and_booleans() -> None:
    with patch("picosentry.scan.cli_commands.check.cmd", return_value=0) as inner:
        code = _dispatch(["check", "--rules", "L2-POST-001", "L2-OBFS-001", "--enterprise"])
    assert code == 0
    ns = inner.call_args[0][0]
    assert ns.rules == ["L2-POST-001", "L2-OBFS-001"]
    assert ns.enterprise is True


def test_check_defaults_reach_inner_cmd() -> None:
    with patch("picosentry.scan.cli_commands.check.cmd", return_value=0) as inner:
        _dispatch(["check"])
    ns = inner.call_args[0][0]
    assert ns.target == "."
    assert ns.fail_on == "medium"
    assert ns.check_corpus_age is None


def test_check_rejects_unsupported_flag(capsys) -> None:
    with patch("picosentry.scan.cli_commands.check.cmd", return_value=0) as inner, pytest.raises(SystemExit) as excinfo:
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
    with patch("picosentry.sandbox.cli_commands.cluster.cmd", return_value=0) as inner:
        code = _dispatch(["cluster", "join", "10.0.0.2:8444", "--port", "9444", "--backend", "sqlite"])
    assert code == 0
    ns = inner.call_args[0][0]
    assert ns.cluster_action == "join"
    assert ns.peer_address == "10.0.0.2:8444"
    assert ns.port == 9444
    assert ns.backend == "sqlite"


def test_cluster_status_forwards_format() -> None:
    with patch("picosentry.sandbox.cli_commands.cluster.cmd", return_value=0) as inner:
        code = _dispatch(["cluster", "status", "--format", "json"])
    assert code == 0
    ns = inner.call_args[0][0]
    assert ns.cluster_action == "status"
    assert ns.format == "json"


def test_cluster_rotate_token_forwards_flags() -> None:
    with patch("picosentry.sandbox.cli_commands.cluster.cmd", return_value=0) as inner:
        code = _dispatch(["cluster", "rotate-token", "--new-token", "tok-2", "--retire-after", "60"])
    assert code == 0
    ns = inner.call_args[0][0]
    assert ns.cluster_action == "rotate-token"
    assert ns.new_token == "tok-2"
    assert ns.retire_after == 60


def test_cluster_leave_forwards_bare() -> None:
    with patch("picosentry.sandbox.cli_commands.cluster.cmd", return_value=0) as inner:
        code = _dispatch(["cluster", "leave"])
    assert code == 0
    assert inner.call_args[0][0].cluster_action == "leave"


def test_cluster_join_env_default_token(monkeypatch) -> None:
    """Token from env is applied by the shared inner parser — no forwarding step to drift."""
    monkeypatch.setenv("PICODOME_CLUSTER_TOKEN", "env-secret")
    with patch("picosentry.sandbox.cli_commands.cluster.cmd", return_value=0) as inner:
        _dispatch(["cluster", "join", "peer:8444"])
    assert inner.call_args[0][0].cluster_token == "env-secret"


def test_cluster_join_explicit_token_overrides_env(monkeypatch) -> None:
    monkeypatch.setenv("PICODOME_CLUSTER_TOKEN", "env-secret")
    with patch("picosentry.sandbox.cli_commands.cluster.cmd", return_value=0) as inner:
        _dispatch(["cluster", "join", "peer:8444", "--cluster-token", "explicit"])
    assert inner.call_args[0][0].cluster_token == "explicit"


def test_cluster_join_rejects_unsupported_flag(capsys) -> None:
    with (
        patch("picosentry.sandbox.cli_commands.cluster.cmd", return_value=0) as inner,
        pytest.raises(SystemExit) as excinfo,
    ):
        _dispatch(["cluster", "join", "peer:8444", "--policy", "p.json"])
    assert excinfo.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
    inner.assert_not_called()


# ─── wrapper/inner argparse parity (WO5.0.0-025 item 8) ──────────────────


def _parser_help(add_arguments, argv: list[str], prog: str) -> str:
    import contextlib
    import io

    parser = argparse.ArgumentParser(prog=prog)
    subparsers = parser.add_subparsers(dest="command")
    add_arguments(subparsers)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            parser.parse_args(argv)
    except SystemExit as exc:
        assert exc.code == 0
    return buf.getvalue()


def test_check_help_matches_inner_scan_check() -> None:
    """`picosentry check --help` must equal `python -m picosentry.scan check --help`.

    The unified wrapper reuses the inner add_arguments, so the surfaces
    cannot drift (the hand-duplicated wrapper was the drift class).
    """
    from picosentry.scan.cli_commands import check as inner_check

    unified = _parser_help(_add_check, ["check", "--help"], prog="picosentry")
    inner = _parser_help(inner_check.add_arguments, ["check", "--help"], prog="picosentry")
    assert unified == inner


@pytest.mark.parametrize(
    "sub", [[], ["join", "--help"], ["status", "--help"], ["leave", "--help"], ["rotate-token", "--help"]]
)
def test_cluster_help_matches_inner_sandbox_cluster(sub: list[str]) -> None:
    """`picosentry cluster [<sub>] --help` must equal the inner module's help.

    The inner `python -m picosentry.sandbox` entry uses prog "picodome" (two
    chars shorter — argparse wraps usage lines by prog length), so parity is
    asserted by building both parsers with the same prog; any difference in
    flags, help strings, or defaults is real drift.
    """
    from picosentry.sandbox.cli_commands import cluster as inner_cluster

    unified = _parser_help(_add_cluster, ["cluster", *sub, "--help"], prog="picosentry")
    inner = _parser_help(inner_cluster.add_arguments, ["cluster", *sub, "--help"], prog="picosentry")
    assert unified == inner


def _add_check(subparsers: argparse._SubParsersAction) -> None:
    from picosentry.cli_commands import scan as scan_wrapper

    scan_wrapper.add_check_arguments(subparsers)


def _add_cluster(subparsers: argparse._SubParsersAction) -> None:
    from picosentry.cli_commands import sandbox as sandbox_wrapper

    sandbox_wrapper.add_cluster_arguments(subparsers)


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
