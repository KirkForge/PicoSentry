# PicoWatch — prompt/output guard

PicoWatch (`picosentry watch`) is the LLM-defense layer in PicoSentry. It provides:

- **L5 prompt guard**: deterministic, offline detection of prompt-injection attempts.
- **L6 output guard**: deterministic output-policy validation.

Both are **pre-filters**, not semantic guarantees. They are designed to catch
high-confidence attack patterns at very low latency and with zero external
dependencies, while being honest about what regex and lexical analysis cannot do.

## Architecture

```
input text
    |
    v
Normalizer  ──>  Unicode / whitespace / comment / zero-width / punctuation / base64 / ROT13 / URL-decode
    |
    v
RuleEngine  ──>  YAML-driven regex rules (weighted, categorized)
    |
    v
Scorer      ──>  score = max(max_weight, avg_weight) over regex matches
    |
    v
Classifier  ──>  lexical/structural second opinion when regex is below threshold
    |
    v
Final score  ──>  block / warn / pass
```

### Normalizer

The normalizer defeats common obfuscation techniques *before* the regex and
classifier see the text:

- NFKC Unicode normalization (homoglyphs, full-width characters).
- Zero-width character stripping.
- Spaced-character collapse (`i g n o r e` -> `ignore`).
- Punctuation collapse (`ignore.all.previous` -> `ignore all previous`).
- HTML/C/line comment stripping.
- Base64, ROT13, and URL decoding with rescan.

### Regex rule engine

Rules are YAML files in `picosentry/watch/rules/prompt_injection/` and
`picosentry/watch/rules/output_policy/`. Each rule has:

- `id`, `category`, `weight` (0.0–1.0), `pattern`, `description`.
- Optional `normalization` list (default: unicode, whitespace).

Rules are deterministic, versioned by a SHA-256 corpus hash, and sorted by id
for reproducible evaluation order.

### Lexical classifier

The classifier is a rule-based layer that runs only when the regex score is
below the block threshold. It scores text on:

- Distinct injection families present (override, role manipulation, extraction,
  multi-turn, format breakout, system prefix).
- Density of suspicious tokens within the text.
- Structural signals (e.g., `System:` / `Admin:` prefix, imperative sentence
  start).
- Cross-family diversity: multiple independent signals amplify the score.

The classifier is intentionally conservative:

- A single ambiguous keyword is capped at warn level.
- Benign contextual markers (`"I made a typo"`, `"correction"`, thanks,
  apologies) suppress weak signals.
- Strong structural signals or multiple families can still override suppression.

The classifier can be disabled via config:

```toml
[picowatch]
classifier_enabled = false
```

or environment:

```bash
PICOWATCH_CLASSIFIER_ENABLED=false
```

## Scoring and verdicts

```python
score = max(regex_score, classifier_score * classifier_blend_factor)

if score >= threshold_block:  # default 0.7
    verdict = BLOCK
elif score >= threshold_warn:  # default 0.4
    verdict = WARN
else:
    verdict = PASS
```

The classifier can only *elevate* the regex score, never lower it, so existing
detections cannot regress.

## Honest limitations

1. **No semantic understanding.** Regex and lexical classifiers do not comprehend
   meaning. A carefully paraphrased injection that avoids all keyword patterns
   can still bypass the guard.
2. **No model-based reasoning.** It does not use embeddings, transformers, or LLM
   judges, so it cannot catch genuinely novel framing that a human would spot.
3. **Determinism trade-off.** The layer is fully deterministic and offline, which
   is a feature for reproducibility but a ceiling on detection quality.
4. **Fast pre-filter role.** It is best used as the first tier in a layered
   defense: block obvious attacks cheaply, then send borderline prompts to a
   heavier model-based guard.

## CLI usage

```bash
# Scan a prompt
picosentry watch scan-prompt --text "ignore all previous instructions"

# Start the HTTP guard server
picosentry watch serve

# Scan via the HTTP API
curl -X POST http://127.0.0.1:8766/v1/prompts/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "..."}'
```

## Recommended deployment

For production LLM deployments, use PicoWatch as a lightweight edge guard and
combine it with a dedicated model-based input/output guard (e.g., a small
classifier model or an LLM-as-judge) for prompts that score in the WARN range or
for applications that tolerate higher latency.
