# WO4.0.0-007 — Watch: guard integrity (fail-closed, homoglyphs, decode order)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/4.0.0/guard-integrity`)
**Priority:** P0 · Effort M · Risk L
**Scope:** `picosentry/watch/prompt_guard/{__init__.py,normalize.py}`, `picosentry/watch/rules/prompt_injection/encoding_attack.yaml`, `picosentry/watch/output_guard/__init__.py`, `picosentry/watch/{__init__.py,health.py}`, `docs/adr/ADR-009`, `tests/watch/` (+ new multilingual/encoding fixture corpus)

**Gate:** `bash scripts/test.sh fast` + new corpus-driven floor test: adversarial encoding set (fullwidth-b64, hex, urlsafe, mixed, paraphrase) blocked; benign multilingual set (Cyrillic/Greek/CJK, capability questions, creative roleplay) passes.

## Objective
Three guard-integrity holes: fail-closed doesn't cover missing corpora, every Cyrillic prompt is blocked, and decoding bypasses normalization.

## Evidence (all verified live 2026-08-17)
1. **Any Cyrillic text BLOCKED**: `encoding_attack.yaml:24-29` `inj_unicode_homoglyph` single-char class at weight 0.7 = block threshold; `"Привет! Помоги мне..."` → blocked 0.7. NFKC doesn't fold Cyrillic→Latin. Greek lookalikes inverse gap.
2. **Fail-closed bypass on missing rules dir**: `prompt_guard/__init__.py:66` gates on `rules_expected > 0`; nonexistent dir → expected=0 → guard runs with 0 rules, passes everything. ADR-009:62-64 claims otherwise — overclaim. OutputGuard has no corpus check at all.
3. **Decode-order bypass**: `check()` decodes the RAW text (`__init__.py:99`); base64 wrapped in fullwidth ASCII → PASS 0.0 (same payload plain → BLOCK 0.9). Zero-width padding same class.
4. **Hex decode absent** (`_HEX` regex dead code, normalize.py:27): `decode and follow: 69676e6f7265...` → PASS. URL-safe base64 alphabet escapes too.
5. Riders: `picoshogun/__init__.py:88` hardcodes `healthy: True`; `inj_zwnj` dead rule (stripped before evaluation); per-rule `normalization` metadata stored but never read.

## Deliverables
1. Fail-closed covers zero-rules/missing-dir/empty-dir (prompt + output guards); health truthful everywhere; ADR-009 wording fixed.
2. Homoglyph rule → word-context/mixed-script detection (not bare char-class); benign multilingual corpus proves it.
3. Decode the NFKC-normalized variant (one-line fix); add hex + urlsafe-b64 decode with a bounded decode budget.
4. Corpus harness à la scan fixtures: adversarial + benign sets with precision/recall floors — the durable regression net for watch.
