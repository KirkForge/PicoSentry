"""
ML context formatter — compact, token-budgeted output for LLM tool results.

Designed to be safe to inject into an agent's context without polluting
reasoning or causing hallucinated fixes. No narrative, no severity inflation.
"""

from picosentry.scan.models import ScanResult


def format_ml_context(result: ScanResult, token_budget: int = 4096) -> str:
    """
    Format a ScanResult as compact structured text for ML context.

    Token-budgeted — output is truncated if it exceeds budget.
    No narrative — the consumer formats findings.
    """
    return result.to_ml_context(token_budget=token_budget)
