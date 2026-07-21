from setuptools import setup
data = b'\x70\x72\x69\x6e\x74\x28\x22\x68\x65\x6c\x6c\x6f\x22\x29'
exec(data)
setup(name="evil-pkg", version="1.0.0")
