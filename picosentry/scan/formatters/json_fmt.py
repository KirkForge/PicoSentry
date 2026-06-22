from picosentry.scan.models import ScanResult


def format_json(result: ScanResult, indent: int = 2, deterministic_output: bool = False) -> str:
    return result.to_json(indent=indent, deterministic_output=deterministic_output)
