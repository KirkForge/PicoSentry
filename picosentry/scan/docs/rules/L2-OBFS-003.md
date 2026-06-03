# L2-OBFS-003: Base64 + exec Patterns in Install Scripts

**Severity:** CRITICAL  
**Category:** obfuscation  
**Since:** v0.1.0

## What It Detects

Patterns where base64-encoded strings are decoded and executed inside install scripts. This includes `atob()` + `eval()`, `Buffer.from(data, 'base64')` + `Function()`, and similar patterns.

## Why It Matters

Base64 + exec is the most dangerous obfuscation pattern in supply chain attacks:

- The attacker hides malicious code in a base64 string that's invisible to code review
- At install time, the string is decoded and executed with full system access
- This is the exact pattern used in multiple real-world npm attacks
- Even security auditors can miss it — the payload is just a string of characters

## How to Fix

1. **Do not install**: This pattern is almost never legitimate
2. **Decode the payload**: If you must investigate, decode the base64 string to see the hidden code
3. **Report the package**: If the decoded payload is malicious, report it to npm security

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-OBFS-003: HIGH  # extremely rare to downgrade
```

## References

- [npm malicious packages: base64 obfuscation](https://blog.npmjs.org/post/185680440530/npm-audit-identify-and-fix-vulnerabilities)