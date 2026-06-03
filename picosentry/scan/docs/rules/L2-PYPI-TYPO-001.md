# L2-PYPI-TYPO-001: PyPI Typosquatting Detection

**Severity:** HIGH / MEDIUM / LOW  
**Category:** typosquat  
**Since:** v1.1.0

## What It Detects

Package names within edit distance ≤2 of popular PyPI packages. Attackers register misspelled names to trick developers into installing malicious code.

## Why It Matters

PyPI typosquatting is a growing attack vector. Attackers register names like `requsts` (typo of `requests`) or `numpyy` (typo of `numpy`) to catch developers making typing errors during pip install.

## How It Works

1. Loads the PyPI top-packages corpus (`pypi_top_packages.json`, ~200 packages)
2. Collects all dependency names from pyproject.toml, requirements.txt, and installed site-packages
3. Computes Levenshtein edit distance between each dependency name and all corpus entries
4. Flags any dependency within distance ≤2 of a popular package name

## False Positive Mitigation

- Short names (≤4 chars) are capped at MEDIUM/LOW severity
- Known legitimate names (e.g., `python-dateutil`, `typing-extensions`) are exempted
- Names that exactly match a corpus entry are not flagged