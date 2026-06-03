# L2-PYPI-OBFS-002: Base64-Decoded Strings

**Severity:** HIGH  
**Category:** obfuscation  
**Since:** v1.1.0

## What It Detects

`base64.b64decode()`, `base64.decodestring()`, and `binascii.unhexlify()` calls that could hide malicious payload strings.

## Remediation

Remove base64-encoded payloads from source code. All data should be readable in plain text.