from __future__ import annotations

import base64
import codecs
import html
import re
import unicodedata
from typing import ClassVar

# Total decoded payload bytes re-scanned per request (WO4.0.0-016). Shared by
# the prompt guard and the output guard's decode-and-rescan pass. Generous
# against legitimate small embeds; bounds normalize+evaluate over many
# full-size base64 decodes on base64-heavy input.
MAX_DECODE_BYTES = 256 * 1024

# Every str.isspace() codepoint except "\n" (WS_EXCEPT_NL_EQUIVALENCE test
# pins this tuple against the live isspace() set). collapse_spaced_text
# squashes all 2+ whitespace runs before the whitespace stage runs, so the
# remaining ws chars are isolated and a per-char translate is equivalent to
# the run-replacing sub — one C pass instead of a per-match re.sub.
_WS_EXCEPT_NL = (
    "\t\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)
_WS_TO_SPACE = str.maketrans(_WS_EXCEPT_NL, " " * len(_WS_EXCEPT_NL))

_DIGIT_DOT_DIGIT = re.compile(r"\d\.\d")


class Normalizer:
    _ZWNJ = "\u200c"  # zero-width non-joiner
    _ZWJ = "\u200d"  # zero-width joiner
    _ZWSP = "\u200b"  # zero-width space
    _ZERO_WIDTH = frozenset({_ZWNJ, _ZWJ, _ZWSP, "\ufeff", "\u200e", "\u200f"})
    _ZERO_WIDTH_TABLE: ClassVar[dict[int, None]] = {ord(ch): None for ch in _ZERO_WIDTH}

    _LINE_COMMENT = re.compile(
        r"(?<![\'\"/:])//(?!/).*$",
        re.MULTILINE,
    )

    _LINE_COMMENT_MARK = re.compile(r"(?<![\'\"/:])//(?!/)")

    # Short base64 strings can encode short injection directives (e.g. "ignore"
    # is 6 bytes / 8 base64 chars). Keep the threshold low enough to catch them
    # while still avoiding trivial false positives.
    _BASE64 = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")

    # URL-safe alphabet (- and _ instead of + and /) used by JWTs and friends.
    _BASE64_URLSAFE = re.compile(r"[A-Za-z0-9_-]{12,}={0,2}")

    _HEX = re.compile(r"(?:0x)?[0-9a-fA-F]{20,}")

    # ponytail: decode work is bounded by a per-request variant budget, not
    # input size — a 1MB payload of 12-char b64-looking runs would otherwise
    # produce ~80k decodes per scan. Raise if legitimate traffic needs more.
    _MAX_DECODE_VARIANTS = 32

    # Decoded candidates containing any of these literals bypass the benign
    # variant cap: flooding benign decodes cannot starve the real payload out
    # of the re-scan window (WO5.0.0-011 decode-budget dial). Hints only
    # prioritize keeping — the rule engine still decides the verdict.
    _DECODE_HINTS = (
        "ignore",
        "disregard",
        "override",
        "forget",
        "instruction",
        "system prompt",
        "reveal",
        "secret",
        "password",
        "private key",
        "aws_",
        "api_key",
        "api key",
        "credential",
        "token",
    )

    # ROT13 of the common injection vocabulary from the rule corpus. Gated so
    # benign English is never rot13-decoded (an FP source); the gate runs on
    # every decode layer, not just the original text (WO5.0.0-011). The
    # previous pattern misspelled five entries (qvfrertnq/cezcg/sbez/fgbp/bff)
    # so real rot13 "disregard"/"system prompt"/"from now on"/"stop being"/
    # "turn off" never matched.
    # ceiling: the gate is decomposed into per-word `in` checks plus tiny
    # first-char-skippable phrase regexes — one big-alternation re.search cost
    # ~230ms/200KB because every branch was retried at every position.
    # _ROT13_GATE_PHRASES must stay an exact branch-for-branch decomposition
    # of the original alternation (WO5.0.0-029). WO6.0.0-002 restored three
    # misspelled entries (ercnpg->ercrng, rkgenpx->rkgenpg, erfbyhgr->erfbyir)
    # reintroduced by the WO5-029 gate fan-out.
    _ROT13_GATE_WORDS: ClassVar[frozenset[str]] = frozenset(
        {
            "vtaber",
            "sbetrg",
            "qvfertneq",
            "bireevqr",
            "qvfnoyr",
            "ercrng",
            "rivy",
            "znyvpvbhf",
            "unpxre",
            "pbafrag",
            "cebzcg",
            "rkgenpg",
            "erfbyir",
            "qroht",
            "hfre",
            "vachg",
            "grkg",
            "genafsre",
            "erdhrfg",
            "dhrel",
            "naq",
        }
    )
    _ROT13_GATE_PHRASES: ClassVar[tuple[tuple[tuple[str, ...], re.Pattern[str]], ...]] = tuple(
        (words, re.compile(pattern, re.IGNORECASE))
        for words, pattern in (
            (("flfgrz", "cebzcg"), r"flfgrz\s+cebzcg"),
            (("gheavat", "bss"), r"gheavat\s+bss"),
            (("lbh", "ner"), r"lbh\s+ner"),
            (("npg", "nf"), r"npg\s+nf"),
            (("sebz", "abj", "ba"), r"sebz\s+abj\s+ba"),
            (("fgbc", "orvat"), r"fgbc\s+orvat"),
            (("fubj", "lbhe"), r"fubj\s+lbhe"),
            (("ghea", "bss"), r"ghea\s+bss"),
            (("naq", "gura"), r"naq\s+gura"),
        )
    )

    # HTML entity gate: Python's html.unescape decodes semicolon-less numeric
    # refs (&#111 / &#x6f) too, so the gate must match them or an entity-
    # encoded payload slips past the decode activation (WO6.0.0-002). Named
    # entities still require the semicolon — unescape does too.
    _HTML_ENTITY = re.compile(r"&#(?:[0-9]{2,}|x[0-9a-fA-F]{2,});?|&[a-zA-Z]{2,8};")

    _URL_ENC = re.compile(r"%[0-9a-fA-F]{2}")

    # Spaced-single-char collapse fused into one whole-text pass: the inner
    # separator is a SINGLE whitespace char because runs of 2+ whitespace
    # acted as segment boundaries in the original split-based implementation
    # (a \s unit cannot step into a 2+ run — the next char would fail \w).
    # The multi-space squash runs afterwards, replacing the old split/join
    # separator handling.
    _SPACED_SINGLE_CHAR = re.compile(r"(?:^|(?<=\s))(\w)(?:\s(\w)){2,}(?=\s|$|[,.;!?])")

    _SEPARATOR_PUNCT = re.compile(r"(?<=\w)[.\-_/](?=\w)")

    # ponytail: separator REMOVAL (not →space) rejoins multi-char fragments
    # split by a single separator — `orig.inal` → `original`. The spaced
    # substitution handles the `ignore-all-previous` case (separate words);
    # removal handles the `orig.inal` obfuscation (one word split). Both
    # variants are scanned (WO6.0.0-002). Ceiling: this is a second full
    # normalize+evaluate pass when separators are present — gated on
    # `_SEPARATOR_PUNCT.search` so clean text pays nothing.
    _SEPARATOR_REMOVED = re.compile(r"(?<=\w)[.\-_/](?=\w)")

    _LLM_TOKEN_MARKER = re.compile(r"<\|[^|]+\|>")

    _IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    _URL_SCHEME = re.compile(r"(?:https?|ftp|postgres|mysql|mongodb|redis|mssql)://")

    def normalize(self, text: str) -> str:
        # ceiling: fused pipeline — collapse_spaced_text has already squashed
        # every 2+ whitespace run, so \r\n pairs and \n{3,} runs cannot exist
        # here and the whitespace stage reduces to one \r->\n replace, one
        # per-char ws translate (isolated chars only) and strip. The
        # standalone normalize_whitespace keeps its run-replacing semantics
        # for direct callers (WO5.0.0-029).
        result = text
        result = self.normalize_unicode(result)
        result = self.collapse_spaced_text(result)
        result = self.collapse_separator_punctuation(result)
        result = result.replace("\r", "\n")
        result = result.translate(_WS_TO_SPACE)
        result = result.strip()
        result = self.strip_comments(result)
        return self.deobfuscate_markdown(result)

    def decode_and_rescan(self, text: str, *, byte_budget: int | None = None) -> list[str]:
        return self._decode_candidates(text, byte_budget=byte_budget)[0]

    def _decode_candidates(self, text: str, *, byte_budget: int | None = None) -> tuple[list[str], bool]:
        """Breadth-first decode over at most two layers (WO5.0.0-011).

        Layer-N candidates are re-decoded at layer N+1 so composed encodings
        (b64-of-urlencode, b64-of-rot13, b64-of-entities, url-of-b64) are
        peeled — the single-pass decode only ever saw the original text.
        Returns ``(candidates, budget_exhausted)``; the flag is true when a
        decodable candidate was dropped (variant cap or byte budget), so a
        clean/WARN verdict can admit it may have missed encoded content.

        WO6.0.0-016: hint-carrying candidates are processed BEFORE benign
        ones within each layer so a flood of benign b64 fillers cannot
        starve the real payload out of the byte budget. The variant cap
        bypass already existed; the byte budget did not.
        """
        budget = byte_budget if byte_budget is not None else self._MAX_DECODE_VARIANTS * 64_000
        seen = {text}
        kept: list[str] = []
        benign_slots = self._MAX_DECODE_VARIANTS
        exhausted = False
        frontier = [text]
        for _layer in range(3):
            next_frontier: list[str] = []
            for item in frontier:
                cands = self._decode_pass(item)
                # Hint-first ordering: hint-carrying candidates consume the
                # byte budget before benign ones so a benign filler flood
                # cannot starve the payload (WO6.0.0-016).
                cands.sort(key=lambda c: not self._hints_hit(c))
                for cand in cands:
                    if cand in seen:
                        continue
                    seen.add(cand)
                    budget -= len(cand)
                    if budget <= 0:
                        return kept, True
                    next_frontier.append(cand)
                    if self._hints_hit(cand):
                        kept.append(cand)
                    elif benign_slots > 0:
                        benign_slots -= 1
                        kept.append(cand)
                    else:
                        exhausted = True
            frontier = next_frontier
        return kept, exhausted

    @classmethod
    def _hints_hit(cls, text: str) -> bool:
        lowered = text.lower()
        return any(hint in lowered for hint in cls._DECODE_HINTS)

    def _decode_pass(self, text: str) -> list[str]:
        """One decode layer: single-level b64, gated rot13/url, hex, entities.

        Kept uncapped here — the caller's byte budget is the bound; the old
        per-collection variant cap consumed in document order was an attacker
        dial (32 benign fillers pushed the payload out of the window).

        ceiling: b64 runs are found once per alphabet and hex runs are sub-
        scanned inside the standard-alphabet runs (every hex run uses a subset
        of the b64 charset and is >= its length threshold, so it is always
        contained in one) — three independent full-text scans per layer became
        two plus bounded sub-scans (WO5.0.0-029).
        """
        out: list[str] = []
        seen: set[str] = set()

        def add(cand: str) -> None:
            if cand and cand != text and cand not in seen:
                seen.add(cand)
                out.append(cand)

        std_runs = [m.group() for m in self._BASE64.finditer(text)]
        for run in std_runs:
            self._add_decoded(run, base64.b64decode, add)
        for m in self._BASE64_URLSAFE.finditer(text):
            self._add_decoded(m.group(), base64.urlsafe_b64decode, add)

        if self._rot13_gate_hits(text):
            add(self.decode_rot13(text))

        if self._URL_ENC.search(text):
            add(self.decode_url(text))

        for run in std_runs:
            for match in self._HEX.finditer(run):
                try:
                    raw = bytes.fromhex(match.group().removeprefix("0x"))
                except ValueError:
                    continue
                payload = raw.decode("utf-8", errors="ignore")
                if self._is_textlike(raw, payload):
                    add(self._strip_control_chars(payload))

        if self._HTML_ENTITY.search(text):
            add(html.unescape(text))

        return out

    def _rot13_gate_hits(self, text: str) -> bool:
        lowered = text.lower()
        if any(word in lowered for word in self._ROT13_GATE_WORDS):
            return True
        for words, phrase in self._ROT13_GATE_PHRASES:
            if all(w in lowered for w in words) and phrase.search(text):
                return True
        return False

    @staticmethod
    def _add_decoded(run: str, decoder, add) -> None:
        try:
            raw = decoder(run)
        except (ValueError, UnicodeDecodeError):
            return
        payload = raw.decode("utf-8", errors="ignore")
        if Normalizer._is_textlike(raw, payload):
            add(Normalizer._strip_control_chars(payload))

    def normalize_unicode(self, text: str) -> str:
        return unicodedata.normalize("NFKC", text)

    def normalize_whitespace(self, text: str) -> str:

        result = text.replace("\r\n", "\n").replace("\r", "\n")

        result = re.sub(r"[^\S\n]+", " ", result)

        result = re.sub(r"\n{3,}", "\n\n", result)
        return result.strip()

    def collapse_spaced_text(self, text: str) -> str:
        # ceiling: two whole-text passes; the previous split-on-\s{2,} walk
        # issued per-segment re.match+re.sub calls (~3.7k subs per 200KB)
        # (WO5.0.0-029). _rejoin is unchanged and sees the same spans.
        def _rejoin(match: re.Match[str]) -> str:
            raw = match.group(0)
            collapsed = re.sub(r"(\w)\s+(?=\w)", r"\1", raw)

            word_len = len(collapsed)
            if word_len < 3:
                return raw

            if raw[0].isupper() and all(c.islower() or c.isspace() for c in raw[1:]):
                return collapsed[0] + collapsed[1:].lower()
            return collapsed

        result = self._SPACED_SINGLE_CHAR.sub(_rejoin, text)
        return re.sub(r"\s{2,}", " ", result)

    def collapse_separator_punctuation(self, text: str) -> str:

        placeholders: dict[str, str] = {}
        # Necessary-condition gates: each protection scan runs only when a
        # literal core of its pattern could be present (WO5.0.0-029).
        if "<|" in text:
            for idx, match in enumerate(self._LLM_TOKEN_MARKER.finditer(text)):
                placeholder = f"\x00LLMTOKEN{idx}\x00"
                placeholders[placeholder] = match.group()

        if _DIGIT_DOT_DIGIT.search(text) is not None:
            for idx, match in enumerate(self._IP_ADDRESS.finditer(text)):
                placeholder = f"\x00IPADDR{idx}\x00"
                placeholders[placeholder] = match.group()

        if "://" in text:
            for idx, match in enumerate(self._URL_SCHEME.finditer(text)):
                placeholder = f"\x00URLSCHEME{idx}\x00"
                placeholders[placeholder] = match.group()

        result = text
        for placeholder, original in placeholders.items():
            result = result.replace(original, placeholder)

        result = self._SEPARATOR_PUNCT.sub(" ", result)

        result = self.collapse_spaced_text(result)

        for placeholder, original in placeholders.items():
            result = result.replace(placeholder, original)

        return result

    def decode_base64(self, text: str) -> list[str]:
        """Single-level base64 decode; composed layers are peeled by _decode_candidates."""
        return self._b64_payloads(text)[: self._MAX_DECODE_VARIANTS]

    def _b64_payloads(self, text: str) -> list[str]:
        # Standard and URL-safe alphabets overlap on [A-Za-z0-9]; runs without
        # +//-_/_ match both patterns and dedupe to one entry downstream.
        payloads: list[str] = []
        seen: set[str] = set()
        for pattern, decoder in (
            (self._BASE64, base64.b64decode),
            (self._BASE64_URLSAFE, base64.urlsafe_b64decode),
        ):
            for match in pattern.finditer(text):
                try:
                    raw = decoder(match.group())
                except (ValueError, UnicodeDecodeError):
                    continue
                payload = raw.decode("utf-8", errors="ignore")
                if self._is_textlike(raw, payload):
                    cleaned = self._strip_control_chars(payload)
                    if cleaned not in seen:
                        seen.add(cleaned)
                        payloads.append(cleaned)
        return payloads

    # Non-printable ASCII (Cc + DEL): for pure-ASCII payloads this is exactly
    # the complement of str.isprintable, countable with one C-level translate.
    # Used both to count the printable ratio and to strip control chars from
    # decoded payloads so diluted b64 (control chars every Nth byte) still
    # reaches the rule engine as clean text (WO6.0.0-002).
    _NONPRINTABLE_ASCII_DEL: ClassVar[dict[int, None]] = dict.fromkeys(range(32))
    _NONPRINTABLE_ASCII_DEL[0x7F] = None

    @staticmethod
    def _is_textlike(raw: bytes, payload: str) -> bool:
        """Text gate for decoded runs.

        errors="ignore" shrinking the decode means the run was not text:
        hash/blob bytes decode to a few stray printable chars that rule
        noise then fires on (WO5.0.0-013 FP fallout). Real wrapped payloads
        are printable text surviving the decode intact. Ceiling: non-ASCII
        multibyte payloads (survival ~1/3) are dropped — the rule corpus is
        ASCII-pattern based regardless.

        WO6.0.0-002: the ratio floor was 0.95 — a diluted payload with one
        control char every 16th byte (93% printable) was dropped, evading
        the decode path. Lowered to 0.6 with the rule engine as the FP gate:
        random binary noise that crosses 60% printable does not match the
        injection rule corpus. Control chars are stripped from the returned
        payload by the caller so \\x01 between words doesn't break \\s+ gaps.
        Binary rejection uses a 0.7 survival floor (raw bytes that decode to
        < 70% of their length are binary blobs like PNG/image data, not
        diluted text — diluted text survives at ~1.0 because control chars
        are valid single-byte UTF-8).
        """
        if len(payload) < 6 or len(payload) / len(raw) < 0.7:
            return False
        # ceiling: per-char isprintable genexpr cost ~3us/char dominated
        # base64-heavy scans (WO5.0.0-029); ASCII payloads count non-printables
        # via one C translate instead. Non-ASCII takes the exact slow path.
        if payload.isascii():
            printable = len(payload.translate(Normalizer._NONPRINTABLE_ASCII_DEL))
            return printable / len(payload) >= 0.6
        return sum(ch.isprintable() for ch in payload) / len(payload) >= 0.6

    @staticmethod
    def _strip_control_chars(payload: str) -> str:
        """Remove non-printable ASCII from a decoded payload so control-char
        dilution between words doesn't break rule patterns (WO6.0.0-002)."""
        return payload.translate(Normalizer._NONPRINTABLE_ASCII_DEL)

    def decode_hex(self, text: str) -> list[str]:
        """Decode long hex runs; non-printable results (hashes, IDs) are dropped."""
        return self._hex_payloads(text)[: self._MAX_DECODE_VARIANTS]

    def _hex_payloads(self, text: str) -> list[str]:
        payloads: list[str] = []
        seen: set[str] = set()
        for match in self._HEX.finditer(text):
            try:
                raw = bytes.fromhex(match.group().removeprefix("0x"))
            except ValueError:
                continue
            payload = raw.decode("utf-8", errors="ignore")
            if self._is_textlike(raw, payload):
                cleaned = self._strip_control_chars(payload)
                if cleaned not in seen:
                    seen.add(cleaned)
                    payloads.append(cleaned)
        return payloads

    def has_zero_width(self, text: str) -> bool:
        if text.isascii():  # every zero-width char is non-ASCII
            return False
        return not self._ZERO_WIDTH.isdisjoint(text)

    def decode_rot13(self, text: str) -> str:
        return codecs.encode(text, "rot_13")

    def decode_url(self, text: str) -> str:
        import urllib.parse

        return urllib.parse.unquote(text)

    def strip_comments(self, text: str) -> str:
        result = self._strip_delimited(text, "<!--", "-->")
        result = self._strip_delimited(result, "/*", "*/")
        return self._LINE_COMMENT.sub("", result)

    @staticmethod
    def _strip_delimited(text: str, start_mark: str, end_mark: str) -> str:
        # ponytail: find-based loop instead of lazy regex — `re` retries the
        # scan at every marker position (O(k*n) on marker floods); str.find
        # consumes matched regions so total work stays linear.
        parts: list[str] = []
        i = 0
        while True:
            s = text.find(start_mark, i)
            if s < 0:
                parts.append(text[i:])
                break
            e = text.find(end_mark, s + len(start_mark))
            if e < 0:
                parts.append(text[i:])
                break
            parts.append(text[i:s])
            i = e + len(end_mark)
        return "".join(parts)

    def neutralize_comment_markers(self, text: str) -> str:
        result = text.replace("<!--", " ").replace("-->", " ")
        result = result.replace("/*", " ").replace("*/", " ")
        return self._LINE_COMMENT_MARK.sub("  ", result)

    def has_separator_punct(self, text: str) -> bool:
        """Necessary-condition gate for the separator-removed variant (WO6.0.0-002)."""
        return self._SEPARATOR_REMOVED.search(text) is not None

    def normalize_separator_removed(self, text: str) -> str:
        """Normalize with separators REMOVED instead of spaced (WO6.0.0-002).

        `orig.inal` → `original` (rejoined); the standard normalize path
        spaces it to `orig inal` which breaks word-anchored rules. This
        variant is scanned alongside the standard normalized text so both
        obfuscation shapes (separate-words-joined and one-word-split) are
        caught.
        """
        placeholders: dict[str, str] = {}
        if "<|" in text:
            for idx, match in enumerate(self._LLM_TOKEN_MARKER.finditer(text)):
                placeholder = f"\x00LLMTOKEN{idx}\x00"
                placeholders[placeholder] = match.group()
        if _DIGIT_DOT_DIGIT.search(text) is not None:
            for idx, match in enumerate(self._IP_ADDRESS.finditer(text)):
                placeholder = f"\x00IPADDR{idx}\x00"
                placeholders[placeholder] = match.group()
        if "://" in text:
            for idx, match in enumerate(self._URL_SCHEME.finditer(text)):
                placeholder = f"\x00URLSCHEME{idx}\x00"
                placeholders[placeholder] = match.group()

        result = text
        for placeholder, original in placeholders.items():
            result = result.replace(original, placeholder)

        result = self._SEPARATOR_REMOVED.sub("", result)
        result = self.collapse_spaced_text(result)

        for placeholder, original in placeholders.items():
            result = result.replace(placeholder, original)

        return self.normalize(result)

    def deobfuscate_markdown(self, text: str) -> str:

        # str.translate runs in C; the former per-char genexpr was a measurable
        # fraction of every normalize pass (WO4.0.0-016).
        return text.translate(self._ZERO_WIDTH_TABLE)
