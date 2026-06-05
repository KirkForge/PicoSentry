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

Expected findings:
- **L2-EVAL-001**: Eval/dynamic execution in setup.py
- **L2-OBF-001**: Base64-encoded strings in setup files
- **L2-EXFIL-001**: Network call during install