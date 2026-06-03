"""Tests for API versioning."""

from picosentry.sandbox.api_versioning import (
    CURRENT_API_VERSION,
    APIVersion,
    APIVersionNegotiator,
    DeprecationNotice,
)


class TestAPIVersion:
    def test_parse_v1(self):
        v = APIVersion.parse("v1")
        assert v.major == 1
        assert v.path_prefix == "v1"

    def test_parse_v2(self):
        v = APIVersion.parse("v2")
        assert v.major == 2

    def test_str(self):
        assert str(APIVersion.parse("v1")) == "v1"


class TestDeprecationNotice:
    def test_to_header(self):
        notice = DeprecationNotice(version="v0", sunset_date="2026-06-01", replacement="v1")
        name, value = notice.to_header()
        assert name == "Deprecation"
        assert "v0" in value


class TestAPIVersionNegotiator:
    def test_path_extraction(self):
        neg = APIVersionNegotiator()
        version, deprecation = neg.negotiate(path="/api/v1/scan")
        assert version == "v1"
        assert deprecation is None

    def test_accept_header(self):
        neg = APIVersionNegotiator()
        version, _ = neg.negotiate(accept_header="application/vnd.picodome.v1+json")
        assert version == "v1"

    def test_custom_header(self):
        neg = APIVersionNegotiator()
        version, _ = neg.negotiate(version_header="v1")
        assert version == "v1"

    def test_default_version(self):
        neg = APIVersionNegotiator()
        version, _ = neg.negotiate()
        assert version == CURRENT_API_VERSION

    def test_unsupported_version_falls_back(self):
        neg = APIVersionNegotiator()
        version, _ = neg.negotiate(version_header="v99")
        assert version == CURRENT_API_VERSION

    def test_get_version_info(self):
        neg = APIVersionNegotiator()
        info = neg.get_version_info()
        assert info["current"] == "v1"
        assert "v1" in info["supported"]
