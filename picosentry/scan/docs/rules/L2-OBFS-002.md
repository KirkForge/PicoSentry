# L2-OBFS-002: Hex-Encoded Strings in Install Scripts

**Severity:** HIGH  
**Category:** obfuscation  
**Since:** v0.1.0

## What It Detects

Hex-encoded strings inside install scripts. This includes `\x48\x65\x6c\x6c\x6f` style hex escape sequences in JavaScript string literals.

## Why It Matters

Hex-encoding is used to hide the true intent of code from casual inspection:

- Legitimate packages don't need hex-encoded strings in their install scripts
- Attackers use hex encoding to disguise URLs, commands, or malicious payloads
- Combined with `eval()` or `Function()`, hex strings become a complete code obfuscation pipeline

## How to Fix

1. **Decode the string**: Convert hex to ASCII to see what's being hidden
2. **Do not install**: If the decoded content reveals network calls or file system access, treat as malicious
3. **Find an alternative**: Legitimate packages are transparent about what they run

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-OBFS-002: MEDIUM  # only if you've decoded and verified the content
```

## References

- [Supply chain attack patterns: obfuscation](https://blog.npmjs.org/post/185680440530/npm-audit-identify-and-fix-vulnerabilities)