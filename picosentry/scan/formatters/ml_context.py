from picosentry.scan.models import ScanResult


def format_ml_context(result: ScanResult, token_budget: int = 4096) -> str:
    return result.to_ml_context(token_budget=token_budget)
