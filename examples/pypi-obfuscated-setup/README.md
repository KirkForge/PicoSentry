# PyPI Obfuscated Setup — example vulnerability

This project demonstrates PicoSentry's ability to detect obfuscated
`setup.py` files that hide malicious behavior.

## What it does

The `setup.py` uses base64-encoded strings and eval() to hide a
post-install data exfiltration payload. This is a real pattern used
by typosquatted packages on PyPI.

## What PicoSentry catches

```bash
picosentry scan examples/pypi-obfuscated-setup/
```

Expected findings (rule IDs as of v2.1.1):

- **L2-PYPI-POST-001**: setup.py with install-time code execution
- **L2-PYPI-OBFS-001**: eval()/exec() dynamic execution in setup.py
- **L2-PYPI-OBFS-002**: Base64-decoded payloads
- **L2-PYPI-OBFS-007**: Base64 decode followed by exec/eval
