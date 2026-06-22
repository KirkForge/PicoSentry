from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from ..models import Confidence, Finding, Severity

__all__ = ["PatternScanner", "TokenPattern"]


@dataclass(frozen=True)
class TokenPattern:
    """A regex-based detection pattern paired with cheap literal-token pre-filters.

    Before the (relatively expensive) ``compiled_pattern`` is executed against a
    body of text, the scanner checks that every token in ``required_tokens`` is
    present.  If any required token is missing, the pattern is skipped.  This
    turns broad file-content scans from ``O(regexes x bytes)`` into
    ``O(tokens + regexes_that_pass_filter x bytes)``.

    Fields:
        rule_id: Rule identifier emitted on the ``Finding``.
        pattern: Compiled regular expression used when the token filter passes.
        severity: Severity assigned to each produced finding.
        message: Human-readable message; ``{func}`` is replaced with the text
            preceding the first ``(`` in the match when present.
        remediation: Remediation guidance stored on the finding.
        required_tokens: Lowercase literal substrings that must all appear in the
            text before ``pattern`` is evaluated.  An empty set means the regex
            always runs (no fast-path rejection).
        confidence: Confidence level assigned to produced findings.
        references: Optional list of reference URLs.
        ecosystem: Ecosystem tag for the finding (default "npm" to match Finding).
    """

    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    message: str
    remediation: str
    required_tokens: frozenset[str] = field(default_factory=frozenset)
    confidence: Confidence = Confidence.HIGH
    references: list[str] = field(default_factory=list)
    ecosystem: str = "npm"

    def has_message_template(self) -> bool:
        return "{func}" in self.message


@dataclass(frozen=True)
class PatternScanner:
    """Run a collection of ``TokenPattern`` rules against text or files.

    The scanner centralises the guard logic that is duplicated across the
    file-content rules (binary-extension skip, size limit, symlink skip, build
    directory skip) and adds the literal-token pre-filter described in
    ``TokenPattern``.
    """

    patterns: Sequence[TokenPattern]

    def __post_init__(self) -> None:
        # Index every token we might ever look for so we can build a single
        # presence map per text body instead of scanning the text once per
        # pattern.
        all_tokens: set[str] = set()
        for p in self.patterns:
            all_tokens.update(p.required_tokens)
        object.__setattr__(self, "_all_tokens", frozenset(all_tokens))

    @property
    def _all_tokens_set(self) -> frozenset[str]:
        # __post_init__ sets this attribute on the frozen dataclass via
        # object.__setattr__ so the scanner remains hashable/immutable.
        return getattr(self, "_all_tokens", frozenset())

    def _present_tokens(self, text: str) -> set[str]:
        text_lower = text.lower()
        return {token for token in self._all_tokens_set if token in text_lower}

    def _pattern_passes_filter(self, pattern: TokenPattern, present_tokens: set[str]) -> bool:
        if not pattern.required_tokens:
            return True
        return pattern.required_tokens <= present_tokens

    def scan_text(
        self,
        text: str,
        package_label: str,
        source_path: str,
        *,
        present_tokens: set[str] | None = None,
    ) -> list[Finding]:
        """Run all configured patterns against ``text``.

        Args:
            text: Body of text to scan.
            package_label: Package identifier stored on findings.
            source_path: File path or other source identifier stored on findings.
            present_tokens: Optional pre-computed token presence map.  When
                scanning many patterns against the same text, compute it once
                with ``_present_tokens`` and reuse it.
        """
        if present_tokens is None:
            present_tokens = self._present_tokens(text)

        findings: list[Finding] = []
        for pat in self.patterns:
            if not self._pattern_passes_filter(pat, present_tokens):
                continue

            for match in pat.pattern.finditer(text):
                matched_text = match.group(0)[:120]
                line_num = text[: match.start()].count("\n") + 1

                message = pat.message
                if pat.has_message_template():
                    func = matched_text.split("(")[0] if "(" in matched_text else matched_text[:20]
                    message = message.format(func=func)

                findings.append(
                    Finding(
                        rule_id=pat.rule_id,
                        severity=pat.severity,
                        confidence=pat.confidence,
                        package=package_label,
                        file=source_path,
                        line=line_num,
                        message=message,
                        evidence=matched_text,
                        remediation=pat.remediation,
                        references=pat.references,
                        ecosystem=pat.ecosystem,
                    )
                )

        return findings

    def scan_file(
        self,
        file_path: Path,
        package_label: str,
        *,
        max_bytes: int = 512_000,
        skip_extensions: Iterable[str] | None = None,
        skip_dirs: Iterable[str] | None = None,
    ) -> list[Finding]:
        """Read ``file_path`` and run the configured patterns against it.

        Returns an empty list for symlinks, files in skipped directories,
        files with skipped extensions, files larger than ``max_bytes``, or
        files that cannot be read.
        """
        skip_extensions = frozenset(skip_extensions or ())
        skip_dirs = frozenset(skip_dirs or ())

        if file_path.is_symlink():
            return []

        if file_path.suffix in skip_extensions:
            return []

        if any(part in skip_dirs for part in file_path.parts):
            return []

        try:
            size = file_path.stat().st_size
        except OSError:
            return []

        if size > max_bytes:
            return []

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        return self.scan_text(text, package_label, str(file_path))

    def scan_files(
        self,
        files: Iterable[Path],
        package_label: str,
        *,
        max_bytes: int = 512_000,
        skip_extensions: Iterable[str] | None = None,
        skip_dirs: Iterable[str] | None = None,
        max_files: int | None = None,
    ) -> list[Finding]:
        """Run the configured patterns over an iterable of files.

        ``max_files`` caps the number of files read; once the cap is reached any
        remaining files are silently ignored.  This matches the existing
        ``MAX_FILES_PER_PACKAGE`` behaviour in the individual rules.
        """
        findings: list[Finding] = []
        for count, f in enumerate(files):
            if max_files is not None and count >= max_files:
                break
            findings.extend(
                self.scan_file(
                    f,
                    package_label,
                    max_bytes=max_bytes,
                    skip_extensions=skip_extensions,
                    skip_dirs=skip_dirs,
                )
            )
        return findings
