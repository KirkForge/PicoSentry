"""Verify the top-level public API surface of picosentry."""

from __future__ import annotations


def test_top_level_public_api_all():
    """__all__ explicitly limits the supported top-level exports."""
    import picosentry

    assert picosentry.__all__ == ["__version__"]


def test_top_level_public_api_version():
    """__version__ is available and follows a dotted-numeric scheme."""
    import picosentry

    assert picosentry.__version__.count(".") == 2
    parts = picosentry.__version__.split(".")
    assert all(part.isdigit() for part in parts)
