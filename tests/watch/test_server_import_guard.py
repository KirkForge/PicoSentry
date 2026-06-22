"""Tests for the optional-dependency import guard in picosentry.watch.server."""

from __future__ import annotations

import builtins
import importlib
import sys
from unittest import mock

import pytest


def test_require_watch_server_extra_fastapi():
    from picosentry.watch.server import _require_watch_server_extra

    exc = ModuleNotFoundError("No module named 'fastapi'")
    with pytest.raises(ImportError, match=r"'watch-server'.*pip install 'picosentry\[watch-server\]'"):
        _require_watch_server_extra("fastapi", exc, what="run_server()")


def test_require_watch_server_extra_pydantic():
    from picosentry.watch.server import _require_watch_server_extra

    exc = ModuleNotFoundError("No module named 'pydantic'")
    with pytest.raises(ImportError, match=r"pydantic.*pip install 'picosentry\[serve\]'"):
        _require_watch_server_extra("pydantic", exc, what="run_server()")


def test_require_watch_server_extra_pydantic_core():
    from picosentry.watch.server import _require_watch_server_extra

    exc = ModuleNotFoundError("No module named 'pydantic_core'")
    with pytest.raises(ImportError, match=r"pydantic.*pip install 'picosentry\[serve\]'"):
        _require_watch_server_extra("pydantic_core", exc, what="run_server()")


def test_require_watch_server_extra_unknown_re_raises():
    from picosentry.watch.server import _require_watch_server_extra

    exc = ModuleNotFoundError("No module named 'something_odd'")
    with pytest.raises(ModuleNotFoundError, match="something_odd"):
        _require_watch_server_extra("something_odd", exc, what="run_server()")


def test_module_import_guard_fastapi():
    """Importing watch.server without fastapi gives a clear install hint."""
    real_import = builtins.__import__
    server_mod_name = "picosentry.watch.server"

    def fake_import(name, *args, **kwargs):
        if name == "fastapi":
            raise ModuleNotFoundError("No module named 'fastapi'", name="fastapi")
        return real_import(name, *args, **kwargs)

    sys.modules.pop(server_mod_name, None)
    with (
        mock.patch("builtins.__import__", fake_import) as _,
        pytest.raises(ImportError, match=r"pip install 'picosentry\[watch-server\]'") as _,
    ):
        importlib.import_module(server_mod_name)

    sys.modules.pop(server_mod_name, None)
