"""setup.py with exec(compile(...)) — should fire L2-PYPI-OBFS-001."""
# This is a tricky pattern: the inner exec(compile(...)) is a common way
# to obfuscate source code, but the detector's EVAL_PATTERN matches
# the literal "exec(" token, so it correctly fires.
src = "print('hi from compiled code')"
exec(compile(src, "<string>", "exec"))
