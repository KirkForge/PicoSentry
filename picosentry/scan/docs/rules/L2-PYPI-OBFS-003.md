# L2-PYPI-OBFS-003: Hex-Encoded Strings

**Severity:** HIGH  
**Category:** obfuscation  
**Since:** v1.1.0

## What It Detects

Hex-encoded strings (e.g., `\x48\x65\x6c\x6c\x6f`) spanning 4+ consecutive escape sequences, which are commonly used to hide URLs, domain names, or payloads.

## Remediation

Decode the hex string and replace with a readable literal.