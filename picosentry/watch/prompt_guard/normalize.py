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
    _ROT13_GATE = re.compile(
        r"vtaber|sbetrg|qvfertneq|bireevqr|flfgrz\s+cebzcg|"
        r"gheavat\s+bss|qvfnoyr|lbh\s+ner|npg\s+nf|sebz\s+abj\s+ba|"
        r"fgbc\s+orvat|ercrng|rivy|znyvpvbhf|unpxre|pbafrag|"
        r"cebzcg|rkgenpx|erfbyhgr|fubj\s+lbhe|qroht|ghea\s+bss|"
        r"hfre|vachg|grkg|genafsre|erdhrfg|dhrel|naq|naq\s+gura",
        re.IGNORECASE,
    )

    _HTML_ENTITY = re.compile(r"&#?[0-9a-zA-Z]{2,8};")

    _URL_ENC = re.compile(r"%[0-9a-fA-F]{2}")

    _SPACED_SINGLE_CHAR = re.compile(r"(?:^|(?<=\s))(\w)(?:\s+(\w)){2,}(?=\s|$|[,.;!?])")

    _SEPARATOR_PUNCT = re.compile(r"(?<=\w)[.\-_/](?=\w)")

    _LLM_TOKEN_MARKER = re.compile(r"<\|[^|]+\|>")

    _IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    _URL_SCHEME = re.compile(r"(?:https?|ftp|postgres|mysql|mongodb|redis|mssql)://")

    def normalize(self, text: str) -> str:
        result = text
        result = self.normalize_unicode(result)
        result = self.collapse_spaced_text(result)
        result = self.collapse_separator_punctuation(result)
        result = self.normalize_whitespace(result)
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
                for cand in self._decode_pass(item):
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
        """
        out: list[str] = []
        seen: set[str] = set()

        def add(cand: str) -> None:
            if cand and cand != text and cand not in seen:
                seen.add(cand)
                out.append(cand)

        for payload in self._b64_payloads(text):
            add(payload)

        if self._ROT13_GATE.search(text):
            add(self.decode_rot13(text))

        if self._URL_ENC.search(text):
            add(self.decode_url(text))

        for payload in self._hex_payloads(text):
            add(payload)

        if self._HTML_ENTITY.search(text):
            add(html.unescape(text))

        return out

    def normalize_unicode(self, text: str) -> str:
        return unicodedata.normalize("NFKC", text)

    def normalize_whitespace(self, text: str) -> str:

        result = text.replace("\r\n", "\n").replace("\r", "\n")

        result = re.sub(r"[^\S\n]+", " ", result)

        result = re.sub(r"\n{3,}", "\n\n", result)
        return result.strip()

    def collapse_spaced_text(self, text: str) -> str:

        segments = re.split(r"(\s{2,})", text)
        result_parts = []
        for segment in segments:
            if re.match(r"^\s{2,}$", segment):
                result_parts.append(" ")
            else:

                def _rejoin(match: re.Match[str]) -> str:
                    raw = match.group(0)
                    collapsed = re.sub(r"(\w)\s+(?=\w)", r"\1", raw)

                    word_len = len(collapsed)
                    if word_len < 3:
                        return raw

                    if raw[0].isupper() and all(c.islower() or c.isspace() for c in raw[1:]):
                        return collapsed[0] + collapsed[1:].lower()
                    return collapsed

                result_parts.append(self._SPACED_SINGLE_CHAR.sub(_rejoin, segment))

        return "".join(result_parts)

    def collapse_separator_punctuation(self, text: str) -> str:

        placeholders: dict[str, str] = {}
        for idx, match in enumerate(self._LLM_TOKEN_MARKER.finditer(text)):
            placeholder = f"\x00LLMTOKEN{idx}\x00"
            placeholders[placeholder] = match.group()

        for idx, match in enumerate(self._IP_ADDRESS.finditer(text)):
            placeholder = f"\x00IPADDR{idx}\x00"
            placeholders[placeholder] = match.group()

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
                    payload = decoder(match.group()).decode("utf-8", errors="ignore")
                except (ValueError, UnicodeDecodeError):
                    continue
                if len(payload) > 5 and self._is_mostly_printable(payload) and payload not in seen:
                    # skip trivial/garbage decodes
                    seen.add(payload)
                    payloads.append(payload)
        return payloads

    def decode_hex(self, text: str) -> list[str]:
        """Decode long hex runs; non-printable results (hashes, IDs) are dropped."""
        return self._hex_payloads(text)[: self._MAX_DECODE_VARIANTS]

    def _hex_payloads(self, text: str) -> list[str]:
        payloads: list[str] = []
        seen: set[str] = set()
        for match in self._HEX.finditer(text):
            try:
                payload = bytes.fromhex(match.group().removeprefix("0x")).decode("utf-8", errors="ignore")
            except ValueError:
                continue
            if len(payload) > 5 and self._is_mostly_printable(payload) and payload not in seen:
                seen.add(payload)
                payloads.append(payload)
        return payloads

    @staticmethod
    def _is_mostly_printable(text: str) -> bool:
        if not text:
            return False
        return sum(ch.isprintable() for ch in text) / len(text) >= 0.9

    def has_zero_width(self, text: str) -> bool:
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

    def deobfuscate_markdown(self, text: str) -> str:

        # str.translate runs in C; the former per-char genexpr was a measurable
        # fraction of every normalize pass (WO4.0.0-016).
        return text.translate(self._ZERO_WIDTH_TABLE)
