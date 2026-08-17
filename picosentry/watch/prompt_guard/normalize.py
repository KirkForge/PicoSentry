from __future__ import annotations

import base64
import codecs
import re
import unicodedata


class Normalizer:
    _ZWNJ = "\u200c"  # zero-width non-joiner
    _ZWJ = "\u200d"  # zero-width joiner
    _ZWSP = "\u200b"  # zero-width space
    _ZERO_WIDTH = frozenset({_ZWNJ, _ZWJ, _ZWSP, "\ufeff", "\u200e", "\u200f"})

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

    def decode_and_rescan(self, text: str) -> list[str]:
        candidates: list[str] = list(self.decode_base64(text))

        # ROT13 is self-inverting and commonly used to hide injection words.
        # The original keyword gate was too narrow (only five strings), so
        # non-keyword ROT13 payloads bypassed decoding. The expanded list
        # below covers the common injection vocabulary from the PicoWatch
        # rule corpus while still avoiding a full always-decode path that
        # would false-positive on benign English containing "ignore" etc.
        rot13_pattern = re.compile(
            r"vtaber|sbetrg|qvfrertnq|bireevqr|flfgrz\s+cezcg|"
            r"gheavat\s+bss|qvfnoyr|lbh\s+ner|npg\s+nf|sbez\s+abj\s+ba|"
            r"fgbc\s+orvat|ercrng|rivy|znyvpvbhf|unpxre|pbafrag|"
            r"cebzcg|rkgenpg|erfbyhgr|fubj\s+lbhe|qroht|ghea\s+bff|"
            r"hfre|vachg|grkg|genafsre|erdhrfg|dhrel|naq|naq\s+gura",
            re.IGNORECASE,
        )
        if rot13_pattern.search(text):
            rot13 = self.decode_rot13(text)
            if rot13 != text:
                candidates.append(rot13)
                # Recursively consider nested encoding layers from the decoded text.
                candidates.extend(self.decode_base64(rot13, max_depth=2))

        if self._URL_ENC.search(text):
            url_decoded = self.decode_url(text)
            if url_decoded != text:
                candidates.append(url_decoded)

        candidates.extend(self.decode_hex(text))

        # Dedupe (standard and urlsafe alphabets overlap) and bound the budget.
        seen: set[str] = set()
        decoded_texts: list[str] = []
        for item in candidates:
            if item in seen:
                continue
            seen.add(item)
            decoded_texts.append(item)
            if len(decoded_texts) >= self._MAX_DECODE_VARIANTS:
                break
        return decoded_texts

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

    def decode_base64(self, text: str, max_depth: int = 3, _depth: int = 0) -> list[str]:
        if _depth >= max_depth:
            return []

        decoded: list[str] = []
        # Standard and URL-safe alphabets overlap on [A-Za-z0-9]; runs without
        # +//-_/_ match both patterns and dedupe to one entry downstream.
        for pattern, decoder in (
            (self._BASE64, base64.b64decode),
            (self._BASE64_URLSAFE, base64.urlsafe_b64decode),
        ):
            for match in pattern.finditer(text):
                if len(decoded) >= self._MAX_DECODE_VARIANTS:
                    return decoded
                try:
                    payload = decoder(match.group()).decode("utf-8", errors="ignore")
                    if len(payload) > 5 and self._is_mostly_printable(payload):  # skip trivial/garbage decodes
                        decoded.append(payload)
                        # Recursively decode nested base64 layers.
                        decoded.extend(self.decode_base64(payload, max_depth=max_depth, _depth=_depth + 1))
                except (ValueError, UnicodeDecodeError):
                    continue
        return decoded

    def decode_hex(self, text: str) -> list[str]:
        """Decode long hex runs; non-printable results (hashes, IDs) are dropped."""
        decoded: list[str] = []
        for match in self._HEX.finditer(text):
            if len(decoded) >= self._MAX_DECODE_VARIANTS:
                break
            try:
                payload = bytes.fromhex(match.group().removeprefix("0x")).decode("utf-8", errors="ignore")
            except ValueError:
                continue
            if len(payload) > 5 and self._is_mostly_printable(payload):
                decoded.append(payload)
        return decoded

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

        return "".join(ch for ch in text if ch not in self._ZERO_WIDTH)
