"""
L2-TYPO-001: Typosquatting detection.

Flags packages whose names are within edit distance ≤2 of popular
npm packages. Attackers register misspelled names to trick developers
into installing malicious code.

Pure function: (target_path, corpus_dir) → List[Finding]

Corpus: npm_top_packages.json (327 packages, offline, versioned).
Falls back to built-in TOP_100 if corpus file is missing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import get_dep_names, load_package_json

__all__ = ["detect_typosquat"]
logger = logging.getLogger("picosentry.typosquat")

# Packages that are themselves popular/legitimate despite being near another
# popular name. Never flag these as typosquats.
KNOWN_LEGITIMATE: frozenset[str] = frozenset({
    "preact", "remix", "vite", "vitest", "svelte", "solid-js",
    "pino", "ora", "got", "prettier", "knex", "mobx", "zod",
})


# Built-in fallback corpus (top-100 npm packages by download count).
# Used when the corpus file is unavailable.
# The canonical corpus is picosentry/corpus/npm_top_packages.json (327 packages).
BUILTIN_TOP_100: list[str] = sorted(
    [
        "react",
        "react-dom",
        "next",
        "typescript",
        "eslint",
        "lodash",
        "axios",
        "express",
        "vue",
        "angular",
        "webpack",
        "babel-core",
        "jest",
        "mocha",
        "chalk",
        "commander",
        "inquirer",
        "dotenv",
        "nodemon",
        "npm",
        "yarn",
        "gulp",
        "grunt",
        "bower",
        "babel-loader",
        "core-js",
        "rxjs",
        "tslib",
        "prop-types",
        "styled-components",
        "material-ui",
        "emotion",
        "tailwindcss",
        "postcss",
        "sass",
        "prettier",
        "eslint-config-airbnb",
        "eslint-plugin-react",
        "babel-preset-env",
        "babel-preset-react",
        "webpack-dev-server",
        "copy-webpack-plugin",
        "html-webpack-plugin",
        "mini-css-extract-plugin",
        "terser-webpack-plugin",
        "fork-ts-checker-webpack-plugin",
        "css-loader",
        "style-loader",
        "file-loader",
        "url-loader",
        "uuid",
        "moment",
        "dayjs",
        "date-fns",
        "date-fns-tz",
        "jquery",
        "bootstrap",
        "popper.js",
        "d3",
        "chart.js",
        "three",
        "phaser",
        "pixi.js",
        "gsap",
        "hammerjs",
        "socket.io",
        "ws",
        "mqtt",
        "kafkajs",
        "amqplib",
        "mongoose",
        "pg",
        "mysql2",
        "redis",
        "ioredis",
        "prisma",
        "sequelize",
        "typeorm",
        "knex",
        "sqlite3",
        "passport",
        "jsonwebtoken",
        "bcrypt",
        "crypto-js",
        "helmet",
        "cors",
        "morgan",
        "winston",
        "pino",
        "debug",
        "bluebird",
        "q",
        "zod",
        "joi",
        "ajv",
        "class-validator",
        "yup",
        "io-ts",
        "runtypes",
    ]
)


def _load_corpus(corpus_dir: Path) -> set[str]:
    """Load package corpus from file. Falls back to BUILTIN_TOP_100."""
    corpus_file = corpus_dir / "npm_top_packages.json"
    if corpus_file.is_file():
        try:
            data = json.loads(corpus_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return set(data)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "Corpus file %s is corrupt (%s), falling back to built-in top-100. "
                "Run 'picosentry update' to regenerate.",
                corpus_file,
                e,
            )
    else:
        logger.info(
            "No corpus file at %s, using built-in top-100. Run 'picosentry update' to download the full corpus.",
            corpus_file,
        )
    return set(BUILTIN_TOP_100)


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance — O(len(a)*len(b))."""
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (ca != cb)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def _check_typosquat(dep_name: str, corpus: set[str]) -> list[tuple[str, int]]:
    """Return list of (popular_package, edit_distance) tuples for matches.

    Optimized with length filter: edit distance ≥ |len(a) - len(b)|,
    so entries differing by > 2 in length can't match and are skipped.
    This reduces comparisons by ~80% for typical dependency lists.
    """
    # Skip scoped packages — typosquatting targets unscoped names
    if dep_name.startswith("@"):
        return []

    name_len = len(dep_name)
    matches: list[tuple[str, int]] = []
    for popular in sorted(corpus):  # sorted for determinism
        if popular == dep_name:
            continue
        # Length filter: edit distance ≥ |len(a) - len(b)|, so skip if > 2
        if abs(name_len - len(popular)) > 2:
            continue
        dist = _edit_distance(dep_name, popular)
        if dist <= 2:
            matches.append((popular, dist))
    return matches


def _typosquat_severity_confidence(dep_name: str, match_name: str, distance: int) -> tuple[Severity, Confidence]:
    """Determine severity and confidence for a typosquat match.

    Short names (≤4 chars) are extremely prone to false positives because
    almost any 3-4 char string is within edit distance 2 of some other
    short name. We cap these at LOW/MEDIUM to avoid noisy HIGH-severity
    findings that break CI with --fail-on high.

    For normal-length names, edit distance 1 is HIGH (likely a real squat),
    edit distance 2 is MEDIUM (could be coincidence).
    """
    min_len = min(len(dep_name), len(match_name))
    length_ratio = min_len / max(len(dep_name), len(match_name))

    if min_len <= 4:
        # Short names: edit distance 2 at LOW, distance 1 at MEDIUM
        if distance >= 2:
            return Severity.LOW, Confidence.LOW
        return Severity.MEDIUM, Confidence.MEDIUM

    if distance == 1 and length_ratio >= 0.8:
        return Severity.HIGH, Confidence.HIGH
    if distance == 2 and length_ratio >= 0.6:
        return Severity.MEDIUM, Confidence.MEDIUM
    # Distance 2 with low length ratio — likely coincidental
    return Severity.LOW, Confidence.LOW


def detect_typosquat(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect typosquatting — dependency names close to popular packages.
    No network calls. Pure filesystem + corpus scan.
    """
    findings: list[Finding] = []
    corpus = _load_corpus(corpus_dir)

    root_pkg = target / "package.json"
    if not root_pkg.is_file():
        return findings

    pkg = load_package_json(root_pkg)
    if not pkg:
        return findings

    # Check the package's own name first (malicious packages ARE the typosquat)
    pkg_name = pkg.get("name", "")
    if pkg_name and not pkg_name.startswith("@") and pkg_name not in corpus and pkg_name not in KNOWN_LEGITIMATE:
        close_matches = _check_typosquat(pkg_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = _typosquat_severity_confidence(pkg_name, best_match, best_dist)
            findings.append(
                Finding(
                    rule_id="L2-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=pkg_name,
                    file=str(root_pkg),
                    message=(
                        f"Package '{pkg_name}' may be a typosquat of popular package(s): {', '.join(m[0] for m in close_matches)}"
                    ),
                    evidence=f"package_name({pkg_name}) is edit_distance {best_dist} from {best_match}",
                    remediation=(
                        f"Verify that '{pkg_name}' is the intended package, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the npm page and author before installing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks-on-npm/",
                    ],
                )
            )

    all_deps = get_dep_names(pkg)

    # Also check node_modules packages
    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            pkg_json = child / "package.json"
            if pkg_json.is_file():
                dep_data = load_package_json(pkg_json)
                if dep_data:
                    all_deps.update(get_dep_names(dep_data))

            # Scoped packages
            if child.name.startswith("@") and child.is_dir():
                for scoped_child in sorted(child.iterdir()):
                    if not scoped_child.is_dir():
                        continue
                    scoped_pkg = scoped_child / "package.json"
                    if scoped_pkg.is_file():
                        dep_data = load_package_json(scoped_pkg)
                        if dep_data:
                            all_deps.update(get_dep_names(dep_data))

    for dep_name in sorted(all_deps):
        # Skip packages that ARE in the corpus — they're legitimate, not typosquats
        if dep_name in corpus or dep_name in KNOWN_LEGITIMATE:
            continue
        close_matches = _check_typosquat(dep_name, corpus)
        if close_matches:
            best_match, best_dist = close_matches[0]
            severity, confidence = _typosquat_severity_confidence(dep_name, best_match, best_dist)
            findings.append(
                Finding(
                    rule_id="L2-TYPO-001",
                    severity=severity,
                    confidence=confidence,
                    package=dep_name,
                    file=str(root_pkg),
                    message=(
                        f"Dependency '{dep_name}' may be a typosquat of popular package(s): {', '.join(m[0] for m in close_matches)}"
                    ),
                    evidence=f"edit_distance({dep_name}, {best_match}) = {best_dist}",
                    remediation=(
                        f"Verify that '{dep_name}' is the intended package, "
                        f"not a misspelling of '{best_match}'. "
                        "Check the npm page and author before installing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks-on-npm/",
                    ],
                )
            )

    return findings
