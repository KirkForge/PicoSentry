
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


    _HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)

    _C_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


    _LINE_COMMENT = re.compile(
        r"(?<![\'\"/:])//(?!/).*$",
        re.MULTILINE,
    )


    _BASE64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


    _HEX = re.compile(r"(?:0x)?[0-9a-fA-F]{20,}")


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
        decoded_texts = list(self.decode_base64(text))


        rot13_pattern = re.compile(
            r"vtaber|sbetrg|qvfrertnq|bireevqr|flfgrz cezcg",
            re.IGNORECASE,
        )
        if rot13_pattern.search(text):
            rot13 = self.decode_rot13(text)
            if rot13 != text:
                decoded_texts.append(rot13)


        if self._URL_ENC.search(text):
            url_decoded = self.decode_url(text)
            if url_decoded != text:
                decoded_texts.append(url_decoded)

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

    def decode_base64(self, text: str) -> list[str]:
        decoded = []
        for match in self._BASE64.finditer(text):
            try:
                payload = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
                if len(payload) > 5:  # skip trivially short decodes
                    decoded.append(payload)
            except Exception:
                continue
        return decoded

    def decode_rot13(self, text: str) -> str:
        return codecs.encode(text, "rot_13")

    def decode_url(self, text: str) -> str:
        import urllib.parse

        return urllib.parse.unquote(text)

    def strip_comments(self, text: str) -> str:
        result = self._HTML_COMMENT.sub("", text)
        result = self._C_COMMENT.sub("", result)
        return self._LINE_COMMENT.sub("", result)

    def deobfuscate_markdown(self, text: str) -> str:

        return "".join(ch for ch in text if ch not in self._ZERO_WIDTH)
