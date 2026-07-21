import base64
from setuptools import setup
data = base64.decodestring(b'cHJpbnQoInRlc3QiKQ==')
exec(data)
setup(name="evil-pkg", version="1.0.0")
