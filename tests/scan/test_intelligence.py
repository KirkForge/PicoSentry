from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from picosentry.scan.intelligence import IntelligenceMode, OSVClient

_OSV_VULN = {
    "id": "GHSA-1234-5678",
    "summary": "prototype pollution",
    "affected": [
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
            "versions": [],
        }
    ],
    "database_specific": {"severity": "HIGH"},
}


def _mock_osv_response(vulns):
    mock_resp = MagicMock()
    body = json.dumps({"vulns": vulns}).encode("utf-8")
    return mock_resp, body


class TestIntelligenceMode:
    def test_offline_value(self):
        assert IntelligenceMode.OFFLINE.value == "offline"

    def test_connected_value(self):
        assert IntelligenceMode.CONNECTED.value == "connected"

    def test_from_string(self):
        assert IntelligenceMode("offline") == IntelligenceMode.OFFLINE
        assert IntelligenceMode("connected") == IntelligenceMode.CONNECTED


class TestOSVClientInit:
    def test_default_cache_dir(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path / "intel")
        assert client._cache_dir == tmp_path / "intel"
        assert client._cache_ttl == 60 * 60
        assert client._timeout == 10

    def test_custom_ttl(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path, cache_ttl_hours=48, timeout=5)
        assert client._cache_ttl == 48 * 3600
        assert client._timeout == 5

    def test_env_cache_minutes(self, tmp_path):
        with patch.dict("os.environ", {"PICOSENTRY_OSV_CACHE_MINUTES": "5"}):
            client = OSVClient(cache_dir=tmp_path)
        assert client._cache_ttl == 5 * 60

    def test_explicit_ttl_overrides_env(self, tmp_path):
        with patch.dict("os.environ", {"PICOSENTRY_OSV_CACHE_MINUTES": "5"}):
            client = OSVClient(cache_dir=tmp_path, cache_ttl_hours=48)
        assert client._cache_ttl == 48 * 3600

    def test_env_override_cache_dir(self, tmp_path):
        custom = tmp_path / "custom_intel"
        with patch.dict("os.environ", {"PICOSENTRY_INTELLIGENCE_DIR": str(custom)}):
            client = OSVClient()
            assert client._cache_dir == custom

    def test_offline_env(self, tmp_path):
        with patch.dict("os.environ", {"PICOSENTRY_OFFLINE": "1"}):
            client = OSVClient(cache_dir=tmp_path)
            assert client._offline is True


class TestCacheKey:
    def test_deterministic(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        k1 = client._cache_key("npm", "lodash")
        k2 = client._cache_key("npm", "lodash")
        assert k1 == k2

    def test_different_packages(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        k1 = client._cache_key("npm", "lodash")
        k2 = client._cache_key("npm", "express")
        assert k1 != k2

    def test_different_ecosystems(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        k1 = client._cache_key("npm", "lodash")
        k2 = client._cache_key("PyPI", "lodash")
        assert k1 != k2


class TestCacheHitMiss:
    def test_cache_miss(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        assert client._read_cache(client._cache_key("npm", "nosuchpkg")) is None

    def test_cache_write_and_read(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        key = client._cache_key("npm", "lodash")
        advisories = [{"id": "GHSA-xxxx-xxxx", "package_name": "lodash", "summary": "test"}]
        client._write_cache(key, advisories)
        result = client._read_cache(key)
        assert result is not None
        assert len(result) == 1
        assert result[0]["id"] == "GHSA-xxxx-xxxx"

    def test_cache_expire(self, tmp_path, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr("picosentry.scan.intelligence.time.time", lambda: now[-1])

        client = OSVClient(cache_dir=tmp_path, cache_ttl_hours=0)
        key = client._cache_key("npm", "lodash")
        client._write_cache(key, [{"id": "test"}])
        now.append(1001.0)
        assert client._read_cache(key) is None

    def test_cache_corrupt_json(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        key = client._cache_key("npm", "lodash")
        client._cache_dir.mkdir(parents=True, exist_ok=True)
        path = client._cache_path(key)
        path.write_text("not json{{", encoding="utf-8")
        assert client._read_cache(key) is None


class TestOSVClientQuery:
    def test_query_returns_advisories(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        mock_resp = _mock_osv_response([_OSV_VULN])
        with patch("picosentry.scan.intelligence.safe_urlopen", return_value=mock_resp):
            results = client.query("npm", "lodash")
        assert len(results) >= 1
        assert any(a.id == "GHSA-1234-5678" for a in results)

    def test_query_uses_cache(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        key = client._cache_key("npm", "lodash")
        client._write_cache(key, [_OSV_VULN])

        with patch("picosentry.scan.intelligence.safe_urlopen") as mock_urlopen:
            results = client.query("npm", "lodash")
            mock_urlopen.assert_not_called()

        assert len(results) == 1
        assert results[0].id == "GHSA-1234-5678"

    def test_query_api_error_returns_empty(self, tmp_path):
        from urllib.error import URLError

        client = OSVClient(cache_dir=tmp_path)
        with patch("picosentry.scan.intelligence.safe_urlopen", side_effect=URLError("timeout")):
            results = client.query("npm", "lodash")
        assert results == []

    def test_query_offline_returns_empty(self, tmp_path):
        with patch.dict("os.environ", {"PICOSENTRY_OFFLINE": "1"}):
            client = OSVClient(cache_dir=tmp_path)
            with patch("picosentry.scan.intelligence.safe_urlopen") as mock_urlopen:
                results = client.query("npm", "lodash")
                mock_urlopen.assert_not_called()
            assert results == []

    def test_query_by_commit(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        mock_resp = _mock_osv_response([_OSV_VULN])
        with patch("picosentry.scan.intelligence.safe_urlopen", return_value=mock_resp):
            results = client.query_by_commit("abc123")
        assert len(results) == 1

    def test_bulk_query(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)
        key_lodash = client._cache_key("npm", "lodash")
        key_express = client._cache_key("npm", "express")
        client._write_cache(key_lodash, [_OSV_VULN])
        express_vuln = {
            "id": "GHSA-9999-0000",
            "summary": "test",
            "affected": [{"package": {"name": "express", "ecosystem": "npm"}, "ranges": [], "versions": []}],
        }
        client._write_cache(key_express, [express_vuln])

        with patch("picosentry.scan.intelligence.safe_urlopen"):
            results = client.bulk_query([("npm", "lodash"), ("npm", "express")])
        assert ("npm", "lodash") in results
        assert len(results[("npm", "lodash")]) == 1
        assert ("npm", "express") in results
        assert len(results[("npm", "express")]) == 1


class TestRefreshCache:
    def test_refresh_cache(self, tmp_path):
        client = OSVClient(cache_dir=tmp_path)

        with patch("picosentry.scan.intelligence.safe_urlopen", return_value=_mock_osv_response([_OSV_VULN])):
            count = client.refresh_cache("npm")
        assert count == 1


class TestAdvisoryCheckIntegration:
    def test_offline_mode_uses_local_data(self, tmp_path):
        from picosentry.scan.rules.advisory_check import (
            detect_all_advisory_vulnerabilities,
        )

        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "advisories").mkdir()
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\nname='test'\nversion='0.1.0'\ndependencies=[]\n",
            encoding="utf-8",
        )
        findings = detect_all_advisory_vulnerabilities(tmp_path, corpus_dir, intelligence_mode="offline")
        assert isinstance(findings, list)

    def test_connected_mode_no_local_db(self, tmp_path):
        from picosentry.scan.rules.advisory_check import (
            detect_all_advisory_vulnerabilities,
        )

        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "advisories").mkdir()
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\nname='test'\nversion='0.1.0'\ndependencies=[]\n",
            encoding="utf-8",
        )
        with patch(
            "picosentry.scan.intelligence.safe_urlopen",
            side_effect=Exception("no network"),
        ):
            findings = detect_all_advisory_vulnerabilities(tmp_path, corpus_dir, intelligence_mode="connected")
        assert isinstance(findings, list)
