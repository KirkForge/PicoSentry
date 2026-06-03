# L2-PYPI-OBFS-005: Compressed Payload Import

**Severity:** CRITICAL  
**Category:** obfuscation  
**Since:** v1.1.0

## What It Detects

Import of zlib (or other compression modules) followed by potential code execution. Compressed payloads are used to bypass static analysis by shipping obfuscated code that's decompressed at runtime.

## Remediation

Remove zlib-compressed payloads from source code. All package logic should be readable in plain text.