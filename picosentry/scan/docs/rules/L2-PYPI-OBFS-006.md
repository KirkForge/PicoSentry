# L2-PYPI-OBFS-006: Marshal Deserialization

**Severity:** CRITICAL  
**Category:** obfuscation  
**Since:** v1.1.0

## What It Detects

`marshal.loads()` or `marshal.load()` calls. Python's marshal module can deserialize arbitrary code objects, making it a vector for code execution from serialised payloads.

## Why It Matters

Marshal deserialization can execute arbitrary Python code. Malicious packages ship serialized code objects as binary data and deserialize them at runtime to evade detection.

## Remediation

Replace marshal.loads() with safe deserialization (e.g., JSON, pickle with restrictions).