"""Direct tests for the extracted static intelligence detection data."""

from __future__ import annotations


class TestIntelligenceData:
    def test_patterns_are_loaded(self):
        from picosentry.serve.services._intelligence_data import PATTERNS

        assert isinstance(PATTERNS, dict)
        assert len(PATTERNS) > 0

    def test_safe_domains_are_populated(self):
        from picosentry.serve.services._intelligence_data import SAFE_DOMAINS

        assert len(SAFE_DOMAINS) > 0

    def test_intelligence_engine_class_attributes_match_data_module(self):
        from picosentry.serve.services._intelligence_data import (
            BANNER_PATTERNS,
            FILENAME_EXTENSIONS,
            MODULE_FALSE_POSITIVES,
            PATTERNS,
            PRIVATE_IP_PREFIXES,
            SAFE_DOMAINS,
            SAFE_IPS,
            _SIMPLE_IPV4_RE,
        )
        from picosentry.serve.services.intelligence import IntelligenceEngine

        assert IntelligenceEngine.PATTERNS is PATTERNS
        assert IntelligenceEngine._SIMPLE_IPV4_RE is _SIMPLE_IPV4_RE
        assert IntelligenceEngine.SAFE_IPS is SAFE_IPS
        assert IntelligenceEngine.PRIVATE_IP_PREFIXES is PRIVATE_IP_PREFIXES
        assert IntelligenceEngine.BANNER_PATTERNS is BANNER_PATTERNS
        assert IntelligenceEngine.FILENAME_EXTENSIONS is FILENAME_EXTENSIONS
        assert IntelligenceEngine.SAFE_DOMAINS is SAFE_DOMAINS
        assert IntelligenceEngine.MODULE_FALSE_POSITIVES is MODULE_FALSE_POSITIVES
