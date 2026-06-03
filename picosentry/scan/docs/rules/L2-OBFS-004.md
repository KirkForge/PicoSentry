# L2-OBFS-004: Unicode Escape Sequences in Install Scripts

**Severity:** HIGH  
**Category:** obfuscation  
**Since:** v0.1.0

## What It Detects

Unicode escape sequences (`\u0048\u0065\u006c\u006c\u006f`) inside install scripts that could be used to hide malicious code from code review.

## Why It Matters

Unicode escapes are a JavaScript feature that allows representing any character as `\uXXXX`:

- Attackers use unicode escapes to make code unreadable to humans
- A single `eval("\u0063\u006f\u0064\u0065")` can hide an entire malicious payload
- Combined with eval/exec patterns, unicode escapes complete the obfuscation toolkit

## How to Fix

1. **Decode the string**: Convert unicode escapes to readable characters
2. **Do not install**: If decoded content reveals malicious patterns
3. **Find an alternative**: Legitimate packages don't need unicode obfuscation

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-OBFS-004: MEDIUM
```

## References

- [JavaScript unicode escapes](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Lexical_grammar#escape_sequences)