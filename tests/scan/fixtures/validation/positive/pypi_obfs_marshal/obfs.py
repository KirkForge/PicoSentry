"""obfs.py: marshal.loads() — exercises L2-PYPI-OBFS-006."""

import marshal

_ = marshal.loads(b"\x00\x00")
