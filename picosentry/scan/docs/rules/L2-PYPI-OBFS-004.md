# L2-PYPI-OBFS-004: Unicode Character Arithmetic Obfuscation

**Severity:** HIGH  
**Category:** obfuscation  
**Since:** v1.1.0

## What It Detects

`chr()`/`ord()` character arithmetic used to construct strings character-by-character. This pattern is commonly used to hide URLs, hostnames, or payload strings from string-based detection.

## How It Works

Detects patterns like `chr(104) + chr(116) + chr(116) + chr(112)` which build strings dynamically to evade static analysis.

## Remediation

Replace chr()/ord() arithmetic with readable string literals.