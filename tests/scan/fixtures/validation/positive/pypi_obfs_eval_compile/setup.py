from setuptools import setup
code = compile('import os; os.system("id")', '<string>', 'exec')
exec(code)
setup(name="evil-pkg", version="1.0.0")
