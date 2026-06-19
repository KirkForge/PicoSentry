"""Tests for picodome.license — license tier enforcement."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from picosentry.sandbox.license import (
    LicenseInfo,
    LicenseTier,
    _load_license_file,
    _reset_cache,
    _validate_key,
    check_license,
    get_license_info,
    require_commercial,
)


@pytest.fixture(autouse=True)
def reset_license():
    _reset_cache()
    yield
    _reset_cache()


class TestLicenseTier:
    def test_personal(self):
        assert LicenseTier.PERSONAL.value == "personal"

    def test_commercial(self):
        assert LicenseTier.COMMERCIAL.value == "commercial"

    def test_enterprise(self):
        assert LicenseTier.ENTERPRISE.value == "enterprise"


class TestLicenseInfo:
    def test_defaults(self):
        info = LicenseInfo()
        assert info.tier == LicenseTier.PERSONAL
        assert info.holder == ""
        assert info.is_personal is True
        assert info.is_commercial is False

    def test_commercial_tier(self):
        info = LicenseInfo(tier=LicenseTier.COMMERCIAL)
        assert info.is_commercial is True
        assert info.is_personal is False

    def test_enterprise_is_commercial(self):
        info = LicenseInfo(tier=LicenseTier.ENTERPRISE)
        assert info.is_commercial is True

    def test_to_dict(self):
        info = LicenseInfo(tier=LicenseTier.COMMERCIAL, holder="Test Org", organization="org1")
        d = info.to_dict()
        assert d["tier"] == "commercial"
        assert d["holder"] == "Test Org"

    def test_repr(self):
        info = LicenseInfo(tier=LicenseTier.PERSONAL, holder="user1")
        r = repr(info)
        assert "personal" in r
        assert "user1" in r


class TestValidateKey:
    def test_valid_commercial_key(self):
        info = _validate_key("picoshogun-commercial-testorg-abc123def4567890")
        assert info is not None
        assert info.tier == LicenseTier.COMMERCIAL
        assert info.organization == "testorg"

    def test_valid_enterprise_key(self):
        info = _validate_key("picoshogun-enterprise-bigcorp-xyz789abc123def4")
        assert info is not None
        assert info.tier == LicenseTier.ENTERPRISE

    def test_valid_personal_key(self):
        info = _validate_key("picoshogun-personal-user1-def456abc789xyz012")
        assert info is not None
        assert info.tier == LicenseTier.PERSONAL

    def test_invalid_prefix(self):
        info = _validate_key("invalid-commercial-testorg")
        assert info is None

    def test_invalid_tier(self):
        info = _validate_key("picoshogun-unknown-testorg")
        assert info is None

    def test_too_few_parts(self):
        info = _validate_key("picoshogun-personal")
        assert info is None

    def test_key_truncation(self):
        info = _validate_key("picoshogun-commercial-org-" + "x" * 50)
        assert info is not None
        assert "..." in info.key


class TestLoadLicenseFile:
    def test_valid_file(self, tmp_path):
        path = tmp_path / "license.json"
        path.write_text(
            json.dumps(
                {
                    "key": "picoshogun-commercial-testorg-abc123def4567890",
                    "holder": "Test User",
                    "organization": "TestOrg",
                }
            )
        )
        info = _load_license_file(str(path))
        assert info is not None
        assert info.tier == LicenseTier.COMMERCIAL
        assert info.holder == "Test User"

    def test_tier_only_file(self, tmp_path):
        path = tmp_path / "license.json"
        path.write_text(json.dumps({"tier": "enterprise", "holder": "User"}))
        info = _load_license_file(str(path))
        assert info is not None
        assert info.tier == LicenseTier.ENTERPRISE

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "license.json"
        path.write_text("not json")
        info = _load_license_file(str(path))
        assert info is None

    def test_invalid_tier(self, tmp_path):
        path = tmp_path / "license.json"
        path.write_text(json.dumps({"tier": "invalid_tier"}))
        info = _load_license_file(str(path))
        assert info is None

    def test_missing_file(self):
        info = _load_license_file("/nonexistent/path/license.json")
        assert info is None


class TestCheckLicense:
    def test_default_personal(self):
        with patch.dict(os.environ, {}, clear=True):
            _reset_cache()
            info = check_license()
            assert info.tier == LicenseTier.PERSONAL

    def test_env_key(self):
        with patch.dict(
            os.environ,
            {"PICODOME_LICENSE_KEY": "picoshogun-commercial-testorg-1234567890abcdef"},
            clear=False,
        ):
            _reset_cache()
            info = check_license()
            assert info.tier == LicenseTier.COMMERCIAL

    def test_local_license_file(self, tmp_path):
        license_path = tmp_path / ".picodome-license"
        license_path.write_text(
            json.dumps(
                {
                    "key": "picoshogun-enterprise-testorg-1234567890abcdef",
                    "holder": "Local User",
                }
            )
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("os.getcwd", return_value=str(tmp_path)),
            patch("os.path.isfile", side_effect=lambda p: p == str(license_path) or Path(p).is_file()),
        ):
            _reset_cache()
            info = check_license()
            assert info.tier == LicenseTier.ENTERPRISE

    def test_caches_result(self):
        with patch.dict(os.environ, {}, clear=True):
            _reset_cache()
            info1 = check_license()
            info2 = check_license()
            assert info1 is info2


class TestGetLicenseInfo:
    def test_returns_license(self):
        with patch.dict(os.environ, {}, clear=True):
            _reset_cache()
            info = get_license_info()
            assert isinstance(info, LicenseInfo)


class TestRequireCommercial:
    def test_personal_returns_false(self):
        with patch.dict(os.environ, {}, clear=True):
            _reset_cache()
            result = require_commercial("test-feature")
            assert result is False

    def test_commercial_returns_true(self):
        with patch.dict(
            os.environ,
            {"PICODOME_LICENSE_KEY": "picoshogun-commercial-testorg-1234567890abcdef"},
            clear=False,
        ):
            _reset_cache()
            result = require_commercial()
            assert result is True
