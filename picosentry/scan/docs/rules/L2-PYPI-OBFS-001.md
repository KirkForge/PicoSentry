# L2-PYPI-OBFS-001: Dynamic Code Execution via exec/eval

**Severity:** CRITICAL  
**Category:** obfuscation  
**Since:** v1.1.0

## What It Detects

`exec()` and `eval()` calls in Python packages. These functions execute arbitrary code from strings and are the most common obfuscation vector.

## Why It Matters

Dynamic code execution is frequently used to hide malicious intent. A call to `exec(base64_decode("..."))` is a telltale sign of a compromised package.

## Remediation

Remove exec/eval calls. Use static imports or type-safe configuration instead.