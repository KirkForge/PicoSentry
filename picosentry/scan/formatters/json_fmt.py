"""
JSON formatter — deterministic output with sorted keys.

Produces the same JSON for the same ScanResult, every time.
"""

from picosentry.scan.models import ScanResult


def format_json(result: ScanResult, indent: int = 2, deterministic_output: bool = False) -> str:
    """
    Format a ScanResult as deterministic JSON.

    Same input = same output. Sorted keys, no random IDs.
    When deterministic_output=True, omits timestamps and timing for byte-stable output.
    """
    return result.to_json(indent=indent, deterministic_output=deterministic_output)
