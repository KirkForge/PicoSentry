"""Adversarial source-code mutations for scanner robustness testing.

These mutations model cheap evasions an attacker might apply to hand-crafted
malicious source files. They are *semantic-preserving* in intent: the mutated
file should still represent the same attack, but the literal tokens shift enough
to stress regex-based detectors.

The benchmark harness copies a fixture tree into a temporary directory,
mutates eligible source files, and runs the scanner. The recall floor measures
how many expected rules still fire after mutation.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

# Files the scanner treats as dependency / project manifests. Mutating them
# risks breaking ecosystem detection, so the harness copies them unchanged.
PROTECTED_NAMES: frozenset[str] = frozenset(
    {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        ".npmrc",
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "poetry.lock",
        "uv.lock",
        "Pipfile",
        "Pipfile.lock",
        "METADATA",
        "PKG-INFO",
        "go.mod",
        "go.sum",
        "go.env",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "settings.gradle",
        "Gemfile",
        "Gemfile.lock",
        "packages.config",
        "packages.lock.json",
        "nuget.config",
    }
)

# Eligible source extensions. Manifest-ish files are excluded even if they
# share an extension (e.g. .json, .xml, .toml) because ecosystem detection and
# advisory parsing depend on their exact contents.
MUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".py",
        ".go",
        ".rs",
        ".rb",
        ".sh",
        ".bash",
        ".md",
    }
)


@dataclass(frozen=True)
class MutationResult:
    """Outcome of applying a set of mutators to a single file."""

    original: str
    mutated: str
    applied: tuple[str, ...]


Mutator = Callable[[str, random.Random], str | None]


# ── Individual mutators ─────────────────────────────────────────────────────


def _split_keep_delimiter(pattern: re.Pattern[str], text: str) -> list[str]:
    """Split *text* on *pattern* while keeping the delimiters in the result."""
    parts: list[str] = []
    cursor = 0
    for match in pattern.finditer(text):
        start, end = match.span()
        if start > cursor:
            parts.append(text[cursor:start])
        parts.append(text[start:end])
        cursor = end
    if cursor < len(text):
        parts.append(text[cursor:])
    return parts


def mutate_insert_comments(text: str, rng: random.Random) -> str | None:
    """Insert benign comments between statements / at line boundaries."""
    lines = text.splitlines()
    if not lines:
        return None
    comments = [
        "/* safe */",
        "// noop",
        "# defensive comment",
        "/* legit utility code */",
        "// logging helper",
    ]
    inserted = 0
    result: list[str] = []
    for line in lines:
        result.append(line)
        if line.strip() and rng.random() < 0.15:
            indent = line[: len(line) - len(line.lstrip())]
            result.append(f"{indent}{rng.choice(comments)}")
            inserted += 1
    if inserted == 0:
        return None
    return "\n".join(result) + ("\n" if text.endswith("\n") else "")


def mutate_pad_whitespace(text: str, rng: random.Random) -> str | None:
    """Add extra whitespace around punctuation and parentheses."""
    changed = False
    chars: list[str] = []
    for ch in text:
        if ch in {"(", ")", "{", "}", "[", "]", ",", ";"} and rng.random() < 0.25:
            chars.append(" " * rng.randint(0, 3))
            chars.append(ch)
            chars.append(" " * rng.randint(0, 3))
            changed = True
        else:
            chars.append(ch)
    if not changed:
        return None
    return "".join(chars)


def mutate_quote_swap(text: str, rng: random.Random) -> str | None:
    """Swap matching pairs of single / double / backtick string quotes."""
    quotes = ["'", '"', "`"]
    changed = False
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] in quotes:
            quote = text[i]
            end = text.find(quote, i + 1)
            if end == -1:
                out.append(text[i])
                i += 1
                continue
            new_quote = rng.choice([q for q in quotes if q != quote])
            segment = text[i + 1 : end]
            # Escape the new delimiter if it appears inside the literal.
            if new_quote == "'":
                segment = segment.replace("'", "\\'")
            elif new_quote == '"':
                segment = segment.replace('"', '\\"')
            elif new_quote == "`":
                segment = segment.replace("`", "\\`")
            out.append(new_quote)
            out.append(segment)
            out.append(new_quote)
            i = end + 1
            changed = True
        else:
            out.append(text[i])
            i += 1
    if not changed:
        return None
    return "".join(out)


def mutate_rename_common_identifiers(text: str, rng: random.Random) -> str | None:
    """Rename a few common local identifiers (not keywords or builtins)."""
    # A small allow-list of names that are safe to replace in a static context.
    candidates = {
        "data": "d",
        "payload": "p",
        "config": "cfg",
        "result": "res",
        "response": "resp",
        "options": "opts",
        "callback": "cb",
        "error": "err",
        "value": "v",
        "element": "el",
        "index": "idx",
    }
    changed = False
    for old, new in candidates.items():
        if rng.random() < 0.5:
            # Match the identifier as a whole word, excluding dotted access that
            # might be an API call.
            pattern = re.compile(rf"\b{re.escape(old)}\b(?![\w\.])")
            if pattern.search(text):
                text = pattern.sub(new, text)
                changed = True
    return text if changed else None


def mutate_hex_escape_strings(text: str, rng: random.Random) -> str | None:
    """Hex-escape the contents of some string literals (JS-style \\xNN)."""
    # Only apply to JS-family sources where \xNN is valid syntax.
    quote_re = re.compile(r"(['\"`])(.*?)\1")
    changed = False

    def _escape(match: re.Match[str]) -> str:
        nonlocal changed
        quote, inner = match.group(1), match.group(2)
        if not inner or rng.random() > 0.3:
            return match.group(0)
        escaped = "".join(f"\\x{ord(c):02x}" for c in inner)
        changed = True
        return f"{quote}{escaped}{quote}"

    result = quote_re.sub(_escape, text)
    return result if changed else None


def mutate_base64_eval_wrap(text: str, rng: random.Random) -> str | None:
    """Wrap a line containing eval/Function in a synthetic atob+eval wrapper.

    This is adversarial *augmentation* rather than evasion: it adds the exact
    L2-OBFS-003 pattern on top of existing dynamic-code calls. Useful for
    measuring whether mutation increases detections.
    """
    lines = text.splitlines(keepends=True)
    if not lines:
        return None
    changed = False
    out: list[str] = []
    for line in lines:
        out.append(line)
        if re.search(r"\b(?:eval|Function)\s*\(", line, re.IGNORECASE) and rng.random() < 0.3:
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f'{indent}eval(atob("YWxlcnQoMSk="));\n')
            changed = True
    return "".join(out) if changed else None


def mutate_add_dead_code(text: str, rng: random.Random) -> str | None:
    """Insert no-op statements that do not alter execution semantics."""
    dead_snippets = [
        "if (false) { console.log('noop'); }",
        "void 0;",
        "null;",
        "0 && console.log('dead');",
        "const __unused = 1;",
        "# pragma: no cover",
    ]
    lines = text.splitlines(keepends=True)
    if not lines:
        return None
    inserted = 0
    result: list[str] = []
    for line in lines:
        result.append(line)
        if line.strip() and rng.random() < 0.10:
            indent = line[: len(line) - len(line.lstrip())]
            result.append(f"{indent}{rng.choice(dead_snippets)}\n")
            inserted += 1
    if inserted == 0:
        return None
    return "".join(result)


def mutate_reorder_independent_lines(text: str, rng: random.Random) -> str | None:
    """Shuffle non-empty, non-brace-only lines in small contiguous windows."""
    lines = text.splitlines(keepends=True)
    if len(lines) < 6:
        return None
    window = rng.randint(3, min(8, len(lines)))
    start = rng.randint(0, len(lines) - window)
    chunk = lines[start : start + window]
    stripped = [ln.strip() for ln in chunk]
    # Avoid moving braces that could break block structure.
    if any(ln in {"{", "}"} for ln in stripped):
        return None
    rng.shuffle(chunk)
    lines[start : start + window] = chunk
    return "".join(lines)


# ── Registry ─────────────────────────────────────────────────────────────────


MUTATORS: dict[str, Mutator] = {
    "insert_comments": mutate_insert_comments,
    "pad_whitespace": mutate_pad_whitespace,
    "quote_swap": mutate_quote_swap,
    "rename_common_identifiers": mutate_rename_common_identifiers,
    "hex_escape_strings": mutate_hex_escape_strings,
    "base64_eval_wrap": mutate_base64_eval_wrap,
    "add_dead_code": mutate_add_dead_code,
    "reorder_independent_lines": mutate_reorder_independent_lines,
}


def apply_mutations(
    text: str,
    mutators: Sequence[str],
    seed: int = 0,
) -> MutationResult:
    """Apply the named mutators in order to *text*.

    Each mutator may return ``None`` to indicate it had no effect; such
    mutators are not recorded in ``MutationResult.applied``. The random state
    is seeded deterministically from *seed* so runs are reproducible.
    """
    rng = random.Random(seed)
    applied: list[str] = []
    current = text
    for name in mutators:
        fn = MUTATORS.get(name)
        if fn is None:
            continue
        result = fn(current, rng)
        if result is not None:
            current = result
            applied.append(name)
    return MutationResult(original=text, mutated=current, applied=tuple(applied))


def can_mutate_file(path: str | Path) -> bool:
    """Return True if the file is eligible for mutation.

    Manifest / lock files and files without a known source extension are
    skipped so ecosystem detection and advisory parsing keep working.
    """
    p = Path(path) if isinstance(path, str) else path
    if p.name in PROTECTED_NAMES:
        return False
    return p.suffix.lower() in MUTABLE_EXTENSIONS
