# Prompt Injection — example vulnerability

This project demonstrates PicoSentry's ability to detect prompt
injection and prompt leaking in LLM-powered applications.

## What it does

Contains sample prompts and outputs that show common LLM attack
patterns: system prompt extraction, role-playing jailbreaks,
and malicious instruction injection.

## What PicoSentry catches

```bash
picosentry watch scan-prompt --file examples/prompt-injection/jailbreak.txt
picosentry watch scan-prompt --file examples/prompt-injection/prompt-leak.txt
```

Expected findings:
- **L5-PI-001**: System prompt extraction attempt
- **L5-PI-002**: Role-playing jailbreak
- **L5-PI-003**: Direct instruction override
- **L5-OV-001**: Sensitive data in LLM output