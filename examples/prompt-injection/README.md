# Prompt Injection — example vulnerability

This project demonstrates PicoSentry's ability to detect prompt
injection and prompt leaking in LLM-powered applications.

## What it does

Contains sample prompts and outputs that show common LLM attack
patterns: system prompt extraction, role-playing jailbreaks,
and malicious instruction override.

## What PicoSentry catches

```bash
picosentry watch scan-prompt --file examples/prompt-injection/jailbreak.txt
picosentry watch scan-prompt --file examples/prompt-injection/instruction-override.txt
```

Expected: `verdict: block`. When regex rules fire their `inj_*` IDs appear in
`rules_matched` (e.g. `inj_extract_system`, `inj_override_ignore`); a
classifier-only block (e.g. `instruction-override.txt`) can leave
`rules_matched` empty — PicoWatch rules use `inj_*` IDs, not L5-numbers.
`sensitive-output.txt` is an output-guard sample for
`picosentry watch validate-output`.
