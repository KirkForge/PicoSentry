"""WO7.0.0-023: CLI flag forwarding parity — unified wrappers forward all
inner-module flags."""

from __future__ import annotations

import argparse

import pytest


def _flags_from_subparser(mod) -> set[str]:
    """All --flags the given module's add_arguments declares on its subparser."""
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    mod.add_arguments(sub)
    # The flags are on the subparser created by add_arguments, not the top parser.
    # Find the subparser action and collect its child parser's actions.
    actions = set()
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            for child_parser in a.choices.values():
                for ca in child_parser._actions:
                    if ca.option_strings:
                        actions.add(ca.option_strings[0])
    return actions


def _unified_flags(command: str) -> set[str]:
    """All --flags the unified wrapper's parser declares."""
    mod = __import__(f"picosentry.cli_commands.{command}", fromlist=["add_arguments"])
    return _flags_from_subparser(mod)


def _inner_flags(command: str) -> set[str]:
    """All --flags the inner sandbox module's parser declares."""
    mod = __import__(f"picosentry.sandbox.cli_commands.{command}", fromlist=["add_arguments"])
    return _flags_from_subparser(mod)


@pytest.mark.parametrize("command", ["admission", "daemon"])
def test_unified_forwards_all_inner_flags(command: str):
    """Every flag on the inner module's parser must appear on the unified wrapper."""
    unified = _unified_flags(command)
    inner = _inner_flags(command)
    missing = inner - unified
    assert not missing, f"unified {command} wrapper missing flags: {missing}"


def test_admission_forwards_scan_fail_closed():
    unified = _unified_flags("admission")
    assert "--scan-fail-closed" in unified


def test_daemon_forwards_redis_and_cluster_flags():
    unified = _unified_flags("daemon")
    for flag in [
        "--store-backend",
        "--cluster-token",
        "--cluster-address",
        "--cluster-port",
        "--cluster-backend",
        "--cluster-heartbeat-interval",
        "--cluster-heartbeat-timeout",
        "--cluster-tls-cert",
        "--cluster-tls-key",
        "--cluster-tls-ca",
    ]:
        assert flag in unified, f"daemon wrapper missing {flag}"


def test_daemon_store_backend_includes_redis():
    """The unified daemon wrapper's --store-backend must accept 'redis'."""
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    from picosentry.cli_commands import daemon as daemon_mod

    daemon_mod.add_arguments(sub)
    # Find the --store-backend action in the subparser
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            for child_parser in a.choices.values():
                for ca in child_parser._actions:
                    if "--store-backend" in ca.option_strings:
                        assert "redis" in ca.choices
                        return
    pytest.fail("--store-backend not found in daemon parser")


def test_watch_forwards_verbose():
    """The unified watch wrapper must declare --verbose."""
    from picosentry.cli_commands import watch as watch_mod

    flags = _flags_from_subparser(watch_mod)
    assert "--verbose" in flags


def test_watch_cmd_forwards_verbose_to_argv(monkeypatch):
    """The watch cmd() must include --verbose in the forwarded argv."""
    from picosentry.cli_commands import watch as watch_mod

    captured: list[list[str]] = []

    def _fake_main(argv):
        captured.append(list(argv))

    def _fake_import_or_warn(import_fn, extra, what):
        return _fake_main

    monkeypatch.setattr("picosentry.cli_commands.watch.import_or_warn", _fake_import_or_warn)

    args = argparse.Namespace(
        verbose=True,
        verify_determinism=False,
        picoshogun_plugin=False,
        watch_command="health",
    )
    watch_mod.cmd(args)
    assert captured, "watch main was not called"
    assert "--verbose" in captured[0]
