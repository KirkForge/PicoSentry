# L2-PYPI-OBFS-007: Base64 Decode Followed by exec/eval

**Severity:** CRITICAL  
**Category:** obfuscation  
**Since:** v1.1.0

## What It Detects

A base64/b64decode/unhexlify call whose result is passed to exec() or eval(). This is a strong indicator of malicious intent.

## Why It Matters

This is the most definitive obfuscation pattern in Python supply chain attacks. The attacker encodes malicious code in base64 to hide it from reviewers, then decodes and executes it at runtime.

## Remediation

Never decode base64 and exec the result. Replace with static configuration.