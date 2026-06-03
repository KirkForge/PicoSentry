"""PicoWatch engine — standalone rule engine + normalizer (PR-04).

Extracted from prompt_guard for decoupled, injectable use.
Same rule set + same input = same matches. Always.
"""

from picosentry.watch.engine.normalizer import Normalizer
from picosentry.watch.engine.rule_engine import RuleEngine

__all__ = ["Normalizer", "RuleEngine"]
