"""setup.py fixture exercising all six PyPI obfuscation detectors."""
import base64
import marshal
import zlib

# L2-PYPI-OBFS-001: exec/eval
exec("print('hi')")

# L2-PYPI-OBFS-002: base64.b64decode
_ = base64.b64decode("aGVsbG8=")

# L2-PYPI-OBFS-003: hex-escaped string (4+ escapes)
s = "\x41\x42\x43\x44\x45"

# L2-PYPI-OBFS-004: chr+chr joined by +
c = chr(65) + chr(66)

# L2-PYPI-OBFS-005: __import__('zlib')
_ = __import__("zlib")

# L2-PYPI-OBFS-006: marshal.loads
_ = marshal.loads(b"\x00\x00")

from setuptools import setup
setup(name="evil-obfs", version="0.1.0")
