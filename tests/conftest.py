"""
Shared test configuration.

Ensures subprocess-based CLI tests can find picosentry without requiring
an editable install.  The ``pythonpath = ["picosentry", "tests"]`` directive
in pyproject.toml handles in-process imports, but ``subprocess.run([sys.executable,
"-m", "picosentry", ...])`` does not inherit that — it needs PYTHONPATH pointing
at the *project root* (the parent of the package directory), not the package
directory itself.  ``python -m picosentry`` resolves the package by name from
sys.path, so the package's parent must be on the path, not the package.
"""

import os
from pathlib import Path

# Add the project root (parent of the picosentry/ package dir) to PYTHONPATH so
# that `python -m picosentry` works in subprocess calls even without
# `pip install -e .`.  In-process imports are handled by pyproject.toml's
# `pythonpath = ["picosentry", ...]`, which pytest does NOT forward to child
# processes — env vars are the only mechanism that crosses the subprocess
# boundary.  The previous version of this line accidentally pointed at the
# inner package dir, so `python -m picosentry` failed with
# "No module named picosentry" in any subprocess that didn't inherit an
# editable install's site-packages entry.
_src = str(Path(__file__).resolve().parent.parent)
_existing = os.environ.get("PYTHONPATH", "")
if _src not in _existing.split(os.pathsep):
    os.environ["PYTHONPATH"] = f"{_src}{os.pathsep}{_existing}" if _existing else _src
