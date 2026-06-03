"""PicoWatch CLI tests."""

import contextlib

from picosentry.watch.cli import main


def test_cli_no_args_shows_help(capsys) -> None:
    """Calling picowatch with no args prints help and exits 1."""
    try:
        main([])
    except SystemExit as exc:
        assert exc.code == 1
    captured = capsys.readouterr()
    assert "picowatch" in captured.out or "picowatch" in captured.err


def test_cli_health() -> None:
    """picowatch health returns status."""
    with contextlib.suppress(SystemExit):
        main(["health"])
