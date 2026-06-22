from __future__ import annotations

import re


class PromptClassifier:
    """Deterministic lexical classifier for prompt-injection signals.

    This is intentionally *not* a learned model. It sits behind the regex rule
    engine and scores text on structural/lexical signals that regex alone can
    miss: paraphrased overrides, role-manipulation framing, extraction framing,
    and multi-turn / encoding combos.

    The classifier is fully deterministic and has no external dependencies, so it
    preserves PicoWatch's offline + reproducible guarantees.
    """

    # Lexical signals grouped by attack family.
    _OVERRIDE_TOKENS = frozenset(
        [
            "ignore",
            "forget",
            "disregard",
            "override",
            "bypass",
            "disable",
            "dismiss",
            "neglect",
            "pay no attention",
            "do not follow",
            "stop following",
            "new instruction",
            "new directive",
            "new rule",
            "from now on",
            "starting now",
            "effective immediately",
            "moving forward",
            "everything you were told",
            "all previous instructions",
            "all prior instructions",
            "previous instructions",
            "prior instructions",
            "without any restrictions",
            "without restrictions",
            "no restrictions",
            "unrestricted",
        ]
    )

    _ROLE_TOKENS = frozenset(
        [
            "you are now",
            "you are no longer",
            "act as",
            "behave as",
            "behave like",
            "roleplay",
            "role play",
            "persona",
            "character",
            "simulation",
            "simulated",
            "pretend to be",
            "pretend you are",
            "stop being",
            "stop acting",
            "new role",
        ]
    )

    _EXTRACTION_TOKENS = frozenset(
        [
            "system prompt",
            "system message",
            "instructions above",
            "rules above",
            "initial prompt",
            "training data",
            "training set",
            "configuration",
            "config file",
            "reveal",
            "repeat back",
            "echo back",
            "print the above",
            "show me the",
            "what were you told",
        ]
    )

    _MULTITURN_TOKENS = frozenset(
        [
            "part 2",
            "part two",
            "concatenate",
            "combine these",
            "piece together",
            "according to the document",
            "as stated in",
            "the document says",
            "encode this as",
        ]
    )

    _FORMAT_BREAKOUT = frozenset(["]]", "```", "<|", "|>", "[end", "[system", "(system"])

    # Benign contextual markers that suppress weak override signals. Polite
    # prefixes like "please" are intentionally *not* here — a polite wrapper
    # around an override attempt is still an override attempt.
    _BENIGN_MARKERS = frozenset(
        [
            "i made a typo",
            "i made an error",
            "i misspoke",
            "correction",
            "thank you",
            "thanks",
            "sorry",
            "i apologize",
            "as a user",
            "i'm asking",
            "i am asking",
            "i want to",
            "i would like",
            "not a real",
            "just curious",
            "for my understanding",
        ]
    )

    _BENIGN_OVERRIDE_CONTEXT = re.compile(
        r"\b(?:i made a typo|i made an error|i misspoke|correction|ignore that)\b",
        re.IGNORECASE,
    )

    _SYSTEM_PREFIX = re.compile(
        r"(?:^|\n)\s*(?:system|admin|root|developer|debug)\s*[:\-\]]\s*",
        re.IGNORECASE,
    )

    _IMPERATIVE_START = re.compile(
        r"(?:^|\n)\s*(?:ignore|forget|disregard|override|bypass|disable|reveal|repeat|echo|print|show|stop|start|act|behave|pretend)\s+",
        re.IGNORECASE,
    )

    def __init__(self, blend_factor: float = 1.0) -> None:
        if not 0.0 <= blend_factor <= 1.0:
            raise ValueError(f"blend_factor must be in [0, 1], got {blend_factor}")
        self._blend_factor = blend_factor

    @property
    def blend_factor(self) -> float:
        return self._blend_factor

    def classify(self, text: str, matched_categories: set[str] | None = None) -> tuple[float, dict[str, float]]:
        """Return a secondary score and a feature breakdown for `text`.

        The score is deliberately conservative: it rewards multiple independent
        injection families appearing together and strong structural signals,
        but rarely fires on a single ambiguous keyword.
        """
        if not text:
            return 0.0, {}

        normalized = text.lower()
        word_count = max(len(normalized.split()), 1)

        override_hits = sum(1 for token in self._OVERRIDE_TOKENS if token in normalized)
        role_hits = sum(1 for token in self._ROLE_TOKENS if token in normalized)
        extraction_hits = sum(1 for token in self._EXTRACTION_TOKENS if token in normalized)
        multiturn_hits = sum(1 for token in self._MULTITURN_TOKENS if token in normalized)
        format_hits = sum(1 for token in self._FORMAT_BREAKOUT if token in normalized)

        system_prefix = 1.0 if self._SYSTEM_PREFIX.search(text) else 0.0
        imperative_start = 1.0 if self._IMPERATIVE_START.search(text) else 0.0

        benign_marker_count = sum(1 for token in self._BENIGN_MARKERS if token in normalized)
        benign_override_context = 1.0 if self._BENIGN_OVERRIDE_CONTEXT.search(text) else 0.0
        has_benign_context = benign_marker_count > 0 or benign_override_context > 0

        # Density features: how many suspicious tokens per word.
        override_density = min(override_hits / max(word_count * 0.05, 1), 1.0)
        role_density = min(role_hits / max(word_count * 0.05, 1), 1.0)
        extraction_density = min(extraction_hits / max(word_count * 0.05, 1), 1.0)

        # Category diversity: reward multiple attack families appearing together.
        categories_present: set[str] = set(matched_categories or [])
        if override_hits:
            categories_present.add("instruction_override")
        if role_hits:
            categories_present.add("role_manipulation")
        if extraction_hits:
            categories_present.add("extraction_attempt")
        if multiturn_hits:
            categories_present.add("multi_turn_trap")
        if system_prefix:
            categories_present.add("system_prefix")
        if format_hits:
            categories_present.add("format_breakout")

        diversity = min(len(categories_present) / 3.0, 1.0)

        # Structural score: strong single signals.
        structural = max(
            system_prefix * 0.7,
            imperative_start * 0.6,
            min(format_hits / 2.0, 1.0) * 0.5,
        )

        # Family scores. A single isolated suspicious word is not enough; we
        # require either multiple tokens in one family, multiple families, or a
        # structural signal to reach block-level scores.
        override_score = min(override_density * 0.95 + (1.0 if override_hits >= 2 else 0.0) * 0.2, 1.0)
        role_score = min(role_density * 0.8 + (1.0 if role_hits >= 2 else 0.0) * 0.15, 1.0)
        extraction_score = min(extraction_density * 0.95, 1.0)
        multiturn_score = min(multiturn_hits / 2.0, 1.0) * 0.5

        family_max = max(override_score, role_score, extraction_score, multiturn_score)

        corroborated = (
            override_hits >= 2
            or role_hits >= 2
            or extraction_hits >= 2
            or multiturn_hits >= 2
            or len(categories_present) >= 2
            or structural > 0
        )
        if not corroborated and family_max > 0.45:
            family_max = 0.45

        # Combine: diversity amplifies the strongest family signal.
        combined = family_max * (0.4 + 0.8 * max(diversity, 0.5)) + structural * (0.5 + 0.5 * diversity)
        combined = min(combined, 1.0)

        # Suppress weak signals when benign context is present. A single
        # ambiguous override word next to "I made a typo" / "correction" should
        # not even warn. Stronger signals (multiple override tokens, system
        # prefix, format breakout, multiple families) are suppressed but can
        # still block if they are strong enough.
        if benign_override_context and override_hits <= 1 and structural < 0.5:
            score = 0.0
        elif has_benign_context and corroborated:
            signal_strength = family_max + structural + diversity
            if signal_strength < 1.9:
                suppression = 0.35
            elif signal_strength < 2.5:
                suppression = 0.6
            else:
                suppression = 0.85
            combined *= suppression
            score = round(min(max(combined, 0.0), 1.0), 6)
        elif has_benign_context:
            score = round(min(max(combined * 0.25, 0.0), 1.0), 6)
        else:
            score = round(min(max(combined, 0.0), 1.0), 6)

        features: dict[str, float] = {
            "override_density": round(override_density, 6),
            "role_density": round(role_density, 6),
            "extraction_density": round(extraction_density, 6),
            "multiturn_hits": float(multiturn_hits),
            "format_hits": float(format_hits),
            "system_prefix": system_prefix,
            "imperative_start": imperative_start,
            "benign_marker_count": float(benign_marker_count),
            "benign_override_context": benign_override_context,
            "diversity": round(diversity, 6),
            "family_max": round(family_max, 6),
            "structural": round(structural, 6),
            "corroborated": float(corroborated),
        }

        return score, features

    def blend(self, regex_score: float, classifier_score: float) -> float:
        """Return the blended final score.

        The classifier can only elevate, never lower, the regex score. This
        prevents regressions on existing detections while letting the classifier
        push borderline paraphrases above the warning/block thresholds.
        """
        blended = max(regex_score, classifier_score * self._blend_factor)
        return round(min(blended, 1.0), 6)
