from setuptools import setup
data = bytes.fromhex('7072696e74282268656c6c6f2229')
exec(data)
setup(name="evil-pkg", version="1.0.0")
