import base64
from setuptools import setup
data = base64.b64decode('ZXZhbCgicHJpbnQoMSsxKSI=')
exec(data)
setup(name="evil-pkg", version="1.0.0")
