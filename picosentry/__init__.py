"""PicoSentry: unified supply-chain security suite.

PicoSentry is intentionally **CLI-first**. The supported interface is the
``picosentry`` command line (and the per-component commands ``picowatch``,
``picodome``, etc.). The Python modules under ``picosentry.*`` are internal
implementation details and may change without notice; there is no stable
programmatic public API today.
"""

__version__ = "2.0.18"

__all__ = ["__version__"]
