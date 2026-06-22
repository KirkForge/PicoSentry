#!/usr/bin/env python3
"""PicoSentry source minifier — strips comments, docstrings, blank-line runs.

Mirrors the kirkforge-CLI philosophy (hand-rolled, conservative) but tailored
to PicoSentry's Python-only codebase. Goals:

  - Strip whole-line ``#`` comments that are not tool directives.
  - Strip module/class/function docstrings (detected via :mod:`ast` so the
    parser itself guarantees the docstring boundaries are correct).
  - Collapse runs of 3+ blank lines down to 1.
  - Preserve the module docstring of ``picosentry/cli.py`` (it is consumed by
    :mod:`argparse` as the program ``description``/``epilog``).

What this script NEVER touches:

  - Trailing inline comments (``x = 1  # why``).
  - Lines inside string literals — detected via :mod:`tokenize` so ``#``-lines
    inside multi-line triple-quoted strings are preserved.
  - Tool directive comments (``# noqa``, ``# type: ignore``, ``# coding:``,
    ``# pragma:``, ``# mypy:``, ``# pylint:``, ``# isort:``, ``# flake8:``,
    ``# fmt:``, ``# ruff:``).
  - Tests under ``tests/`` (kirkforge only ever reads ``picosentry/``; tests
    are run by pytest directly).

This script is idempotent — running it twice on the same file is a no-op.
"""
from __future__ import annotations

import argparse
import ast
import io
import re
import sys
import tokenize
from pathlib import Path

# Whole-line comments whose body matches any of these regexes are preserved.
# Match the directive keyword, then optionally ": " or just whitespace — this
# catches `# noqa`, `# noqa: F401`, `# noqa,F401`, `# type: ignore`, etc.
KEEP_COMMENT_RE = re.compile(
    r"\s*(?:" + "|".join(
        [
            r"noqa\b",
            r"type\s*:\s*ignore\b",
            r"coding\s*[=:]\s*",
            r"pragma\s*:",
            r"isort\s*:",
            r"flake8\s*:",
            r"pylint\s*:",
            r"mypy\s*:",
            r"ruff\s*:",
            r"fmt\s*:",
        ]
    ) + r")",
    re.IGNORECASE,
)

# Files whose module docstring must be preserved verbatim.
PRESERVE_MODULE_DOCSTRING_IN: set[Path] = {
    Path("picosentry/cli.py"),
}


def find_docstring_lines(source: str) -> set[int]:
    """Return 1-indexed line numbers occupied by module/function/class docstrings.

    Uses :func:`ast.parse` so the boundaries are exactly what Python would
    treat as a docstring — no false positives on triple-quoted strings inside
    expressions or f-strings.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    targets: list[ast.AST] = [tree]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            targets.append(node)

    line_set: set[int] = set()
    for node in targets:
        body = getattr(node, "body", None)
        if not body or len(body) < 2:
            # If the only statement is a docstring, stripping it would leave
            # an empty class/function body (SyntaxError). Keep the docstring.
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            for ln in range(first.lineno, (first.end_lineno or first.lineno) + 1):
                line_set.add(ln)
    return line_set


def classify_lines(source: str) -> tuple[set[int], set[int], set[int]]:
    """Tokenize ``source`` and return (whole_comment_lines, string_lines, any_comment_lines).

    - ``whole_comment_lines``: lines where the ONLY non-whitespace content is
      a ``#`` comment (i.e. ``# foo`` or ``    # foo``). Safe to strip.
    - ``string_lines``: lines inside a string literal. Never touched.
    - ``any_comment_lines``: lines that contain a ``#`` comment anywhere
      (including trailing inline comments like ``pass  # why``). Used to
      distinguish the two cases above — if a line is in ``any_comment_lines``
      but NOT in ``whole_comment_lines``, the ``#`` is a trailing comment and
      the line's code must be preserved.
    """
    whole_comment_lines: set[int] = set()
    string_lines: set[int] = set()
    any_comment_lines: set[int] = set()
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenizeError:
        return whole_comment_lines, string_lines, any_comment_lines

    # First pass: collect string_lines and any_comment_lines.
    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            for ln in range(tok.start[0], tok.end[0] + 1):
                any_comment_lines.add(ln)
        elif tok.type == tokenize.STRING:
            for ln in range(tok.start[0], tok.end[0] + 1):
                string_lines.add(ln)

    # Second pass: for each line in any_comment_lines, check whether the
    # COMMENT token is the ONLY non-whitespace content of that line.
    # If the line contains any non-whitespace, non-COMMENT, non-NL token
    # before the COMMENT, the comment is trailing and the line has code.
    for tok in tokens:
        if tok.type != tokenize.COMMENT:
            continue
        ln = tok.start[0]
        if ln not in any_comment_lines or ln in string_lines:
            # Inside a string — not a "real" comment.
            continue
        comment_col = tok.start[1]
        # Check tokens on the same line: any non-NL, non-COMMENT token
        # that starts before ``comment_col`` means the comment is trailing.
        has_code_before = False
        for other in tokens:
            if other.type in (tokenize.NL, tokenize.COMMENT, tokenize.NEWLINE, tokenize.ENCODING):
                continue
            if other.start[0] != ln:
                continue
            if other.start[1] < comment_col:
                has_code_before = True
                break
        if not has_code_before:
            whole_comment_lines.add(ln)
    return whole_comment_lines, string_lines, any_comment_lines


def is_keep_comment(line: str) -> bool:
    """Return True if ``line`` is a whole-line ``#`` comment that must be kept
    (matches a tool directive).
    """
    stripped = line.lstrip()
    if not stripped.startswith("#"):
        return False
    return bool(KEEP_COMMENT_RE.search(stripped))


def is_import_line(line: str) -> bool:
    """Return True if the line is an ``import`` or ``from ... import`` statement."""
    stripped = line.lstrip()
    return stripped.startswith("import ") or stripped.startswith("from ") or stripped == "import" or stripped == "from"


def preserve_import_group_blanks(text: str) -> str:
    """Re-insert blank lines that the blank-line collapse may have eaten:

    - One blank line between import statements (ruff's ``I001``/isort).
    - Two blank lines between top-level ``def``/``class``/``async def``
      statements (PEP 8). Without these, linters and formatters see the
      block as "un-formatted" and want to re-flow it.
    """
    lines = text.split("\n")
    out: list[str] = []
    for i, line in enumerate(lines):
        if line.strip() == "" and 0 < i < len(lines) - 1:
            prev = lines[i - 1]
            next_ = lines[i + 1]
            if is_import_line(prev) and is_import_line(next_):
                out.append(line)
                continue
            if is_def_line(prev) and is_def_line(next_):
                # Two blanks between top-level defs.
                out.append(line)
                if not (i > 0 and lines[i - 1].strip() == ""):
                    out.append("")
                continue
        out.append(line)
    return "\n".join(out)


def is_def_line(line: str) -> bool:
    """Return True if the line is a top-level def/class/async def statement
    (or a decorator line for one).
    """
    if not line or line[0] in (" ", "\t"):
        return False
    stripped = line.lstrip()
    return stripped.startswith(("def ", "async def ", "class ", "@"))


def minify_source(
    source: str,
    *,
    preserve_module_docstring: bool = False,
) -> str:
    """Return the minified source, or ``source`` unchanged if minification
    would not be safe (e.g. file fails to parse as Python).
    """
    try:
        ast.parse(source)
    except SyntaxError as exc:
        raise ValueError(f"source does not parse as Python: {exc}") from exc

    lines = source.split("\n")
    whole_comment_lines, string_lines, _ = classify_lines(source)

    # Compute which docstring lines to strip.
    if preserve_module_docstring:
        module_doc_lines: set[int] = set()
        try:
            tree = ast.parse(source)
            if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(
                tree.body[0].value, ast.Constant
            ) and isinstance(tree.body[0].value.value, str):
                first = tree.body[0]
                for ln in range(first.lineno, (first.end_lineno or first.lineno) + 1):
                    module_doc_lines.add(ln)
        except SyntaxError:
            pass
        all_doc_lines = find_docstring_lines(source) - module_doc_lines
    else:
        all_doc_lines = find_docstring_lines(source)

    out: list[str] = []
    for idx, line in enumerate(lines, start=1):
        # Drop docstring lines.
        if idx in all_doc_lines:
            continue
        # Never touch lines that are inside string literals — tokenize tells
        # us this authoritatively.
        if idx in string_lines:
            out.append(line)
            continue
        # Whole-line comments: keep tool directives, drop the rest.
        if idx in whole_comment_lines:
            if is_keep_comment(line):
                out.append(line)
            else:
                out.append("")
            continue
        # Regular code line: leave as-is.
        out.append(line.rstrip())

    text = "\n".join(out)
    # Collapse 4+ consecutive newlines (3+ blank lines) down to 2 newlines
    # (1 blank line). We preserve 1 and 2 blank lines so PEP 8 conventions
    # (1 blank between import groups, 2 blanks between top-level defs) are
    # not disturbed. Only runs of 3+ blanks are common enough to be worth
    # stripping — they appear in long docstrings, not in code.
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    text = preserve_import_group_blanks(text)
    text = text.rstrip("\n") + "\n"
    return text


def minify_file(
    path: Path,
    *,
    preserve_module_docstring: bool = False,
    dry_run: bool = False,
) -> tuple[int, int]:
    """Minify a single file. Returns (original_lines, new_lines)."""
    orig = path.read_text(encoding="utf-8")
    try:
        new = minify_source(orig, preserve_module_docstring=preserve_module_docstring)
    except ValueError:
        return len(orig.splitlines()), len(orig.splitlines())
    orig_lines = len(orig.splitlines())
    new_lines = len(new.splitlines())
    if new != orig and not dry_run:
        path.write_text(new, encoding="utf-8")
    return orig_lines, new_lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "roots",
        nargs="*",
        type=Path,
        default=[Path("picosentry")],
        help="Root directories to walk (default: picosentry/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be stripped without writing any files",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-file output; print only the summary",
    )
    args = parser.parse_args(argv)

    total_orig = 0
    total_new = 0
    files_changed = 0
    skipped = 0
    for root in args.roots:
        if not root.exists():
            print(f"warning: {root} does not exist, skipping", file=sys.stderr)
            continue
        if root.is_file():
            candidates = [root]
        else:
            candidates = sorted(root.rglob("*.py"))
        for py_file in candidates:
            if "__pycache__" in py_file.parts:
                continue
            preserve = py_file in PRESERVE_MODULE_DOCSTRING_IN
            orig_lines, new_lines = minify_file(
                py_file, preserve_module_docstring=preserve, dry_run=args.dry_run
            )
            total_orig += orig_lines
            total_new += new_lines
            if orig_lines == new_lines:
                skipped += 1
            else:
                files_changed += 1
                if not args.quiet:
                    saved = orig_lines - new_lines
                    pct = saved * 100 // orig_lines if orig_lines else 0
                    print(f"  -{saved:5d}  -{pct:3d}%  {py_file}")

    saved = total_orig - total_new
    pct = saved * 100 / total_orig if total_orig else 0
    print(
        f"\ndone: {files_changed} files changed, "
        f"{skipped} unchanged, {total_orig} -> {total_new} lines "
        f"(-{saved}, -{pct:.1f}%)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
