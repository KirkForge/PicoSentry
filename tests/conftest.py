"""
Shared test configuration.

Ensures subprocess-based CLI tests can find picosentry without requiring
an editable install.  The ``pythonpath = ["src"]`` directive in pyproject.toml
handles in-process imports, but ``subprocess.run([sys.executable, "-m",
"picosentry", ...])`` does not inherit that — it needs PYTHONPATH.
"""

import os
from pathlib import Path

# Add picosentry/ to PYTHONPATH so that `python -m picosentry` works in subprocess
# calls even without `pip install -e .`
_src = str(Path(__file__).resolve().parent.parent / "picosentry")
_existing = os.environ.get("PYTHONPATH", "")
if _src not in _existing.split(os.pathsep):
    os.environ["PYTHONPATH"] = f"{_src}{os.pathsep}{_existing}" if _existing else _src
