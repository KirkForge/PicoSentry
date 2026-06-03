# L2-OBFS-001: eval() Calls in Install Scripts

**Severity:** CRITICAL  
**Category:** obfuscation  
**Since:** v0.1.0

## What It Detects

`eval()` calls inside install scripts (`install`, `postinstall`, `preinstall`). This includes `eval()`, `new Function()`, and indirect eval patterns.

## Why It Matters

`eval()` in an install script is a strong indicator of malicious intent or obfuscation:

- Legitimate packages rarely need `eval()` in their install process
- Malicious packages use `eval()` to hide their true payload from static analysis
- `eval()` can decode and execute arbitrary strings at runtime, bypassing code review

## How to Fix

1. **Do not install**: Any package using `eval()` in install scripts should be treated as suspicious
2. **Audit the argument**: If the eval source is a static string, inspect what it evaluates to
3. **Find an alternative**: In nearly all cases, there's a safer package that doesn't need eval

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-OBFS-001: HIGH  # only if you've audited the specific package
```

## References

- [MDN: eval() — never use it](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval)
- [OWASP: Code Injection](https://owasp.org/www-community/attacks/Code_Injection)