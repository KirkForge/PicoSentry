"""Tests for the management module — org config, policy, advisories, auth, zip safety."""

import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from picosentry.scan._network import InsecureURLError, ResponseTooLargeError
from picosentry.scan.management import (
    ORG_ADVISORY_URL_ENV,
    ORG_POLICY_URL_ENV,
    PICOSENTRY_API_KEY_ENV,
    PICOSENTRY_AUTH_TOKEN_ENV,
    OrgConfig,
    _validate_zip_paths,
    fetch_advisories,
    fetch_policy,
    get_auth_token,
    make_authenticated_request,
    org_config_template,
    push_policy,
)

# ── Helpers ───────────────────────────────────────────────────────────────


def _make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    """Return bytes of a zip archive containing the given entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _make_policy_bundle(policy: dict | None = None) -> bytes:
    """Return bytes of a minimal valid policy bundle (with digest)."""
    import hashlib

    policy = policy or {"version": 1, "fail_on": {"severity": "high"}}
    policy_json = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    digest = f"sha256:{hashlib.sha256(policy_json.encode()).hexdigest()[:32]}"
    bundle = {"policy": policy, "digest": digest}
    return json.dumps(bundle).encode("utf-8")


# ── OrgConfig.discover ──────────────────────────────────────────────────


class TestOrgConfigDiscover(unittest.TestCase):
    """Tests for OrgConfig.discover() — env vars, file-based config, missing files."""

    def setUp(self):
        self._saved_policy = os.environ.pop(ORG_POLICY_URL_ENV, None)
        self._saved_advisory = os.environ.pop(ORG_ADVISORY_URL_ENV, None)

    def tearDown(self):
        if self._saved_policy is not None:
            os.environ[ORG_POLICY_URL_ENV] = self._saved_policy
        else:
            os.environ.pop(ORG_POLICY_URL_ENV, None)
        if self._saved_advisory is not None:
            os.environ[ORG_ADVISORY_URL_ENV] = self._saved_advisory
        else:
            os.environ.pop(ORG_ADVISORY_URL_ENV, None)

    def test_env_vars_only(self):
        """Environment variables populate config without any files."""
        os.environ[ORG_POLICY_URL_ENV] = "https://policy.example.com"
        os.environ[ORG_ADVISORY_URL_ENV] = "https://advisories.example.com"
        config = OrgConfig.discover()
        self.assertEqual(config.policy_url, "https://policy.example.com")
        self.assertEqual(config.advisory_url, "https://advisories.example.com")

    def test_env_vars_override_file(self):
        """Env vars take priority over file-based config values."""
        os.environ[ORG_POLICY_URL_ENV] = "https://env-policy.example.com"
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".picosentry-org.yml"
            cfg_path.write_text(
                "policy_url: https://file-policy.example.com\nadvisory_url: https://file-advisory.example.com\n"
            )
            config = OrgConfig.discover(root=Path(tmpdir))
            self.assertEqual(config.policy_url, "https://env-policy.example.com")
            self.assertEqual(config.advisory_url, "https://file-advisory.example.com")

    def test_yaml_file_config(self):
        """YAML config file is read when env vars are not set."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".picosentry-org.yml"
            cfg_path.write_text(
                "org_name: TestOrg\n"
                "policy_url: https://policy.test\n"
                "advisory_url: https://adv.test\n"
                "require_signed_policy: false\n"
            )
            config = OrgConfig.discover(root=Path(tmpdir))
            self.assertEqual(config.org_name, "TestOrg")
            self.assertEqual(config.policy_url, "https://policy.test")
            self.assertEqual(config.advisory_url, "https://adv.test")
            self.assertFalse(config.require_signed_policy)

    def test_yaml_file_second_path(self):
        """Discovery checks .picosentry-org.yaml as a fallback path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".picosentry-org.yaml"
            cfg_path.write_text("org_name: YamlOrg\npolicy_url: https://yaml.test\n")
            config = OrgConfig.discover(root=Path(tmpdir))
            self.assertEqual(config.org_name, "YamlOrg")
            self.assertEqual(config.policy_url, "https://yaml.test")

    def test_json_fallback_when_yaml_not_importable(self):
        """If yaml module is missing, falls back to JSON parsing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".picosentry-org.yml"
            cfg_path.write_text(
                json.dumps(
                    {
                        "org_name": "JsonOrg",
                        "policy_url": "https://json.test",
                    }
                )
            )
            with patch.dict("sys.modules", {"yaml": None}):
                config = OrgConfig.discover(root=Path(tmpdir))
                self.assertEqual(config.org_name, "JsonOrg")
                self.assertEqual(config.policy_url, "https://json.test")

    def test_missing_files_returns_defaults(self):
        """When no env vars and no config files, defaults are returned."""
        config = OrgConfig.discover(root=Path("/nonexistent/path"))
        self.assertEqual(config.policy_url, "")
        self.assertEqual(config.advisory_url, "")
        self.assertEqual(config.org_name, "")
        self.assertTrue(config.require_signed_policy)

    def test_root_none_skips_project_files(self):
        """Passing root=None skips project-level config files."""
        config = OrgConfig.discover(root=None)
        self.assertIsInstance(config, OrgConfig)

    def test_non_dict_file_ignored(self):
        """A config file with a non-dict YAML value is ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".picosentry-org.yml"
            cfg_path.write_text("- just\n- a\n- list\n")
            config = OrgConfig.discover(root=Path(tmpdir))
            self.assertEqual(config.org_name, "")

    def test_empty_env_vars_fall_through_to_file(self):
        """Empty string env vars don't block file config values."""
        os.environ[ORG_POLICY_URL_ENV] = ""
        os.environ[ORG_ADVISORY_URL_ENV] = ""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".picosentry-org.yml"
            cfg_path.write_text("policy_url: https://from-file.test\n")
            config = OrgConfig.discover(root=Path(tmpdir))
            self.assertEqual(config.policy_url, "https://from-file.test")

    def test_file_config_does_not_override_env(self):
        """File config does not overwrite already-set env var values."""
        os.environ[ORG_POLICY_URL_ENV] = "https://env.test"
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".picosentry-org.yml"
            cfg_path.write_text("policy_url: https://file.test\n")
            config = OrgConfig.discover(root=Path(tmpdir))
            self.assertEqual(config.policy_url, "https://env.test")


# ── fetch_policy ──────────────────────────────────────────────────────────


class TestFetchPolicy(unittest.TestCase):
    """Tests for fetch_policy() — success, verification, URL errors."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.output_path = Path(self.tmpdir) / "policy.json"

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("picosentry.scan.policy.import_policy_bundle")
    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_policy_success_with_verify(self, mock_urlopen, mock_import):
        """Successful policy fetch with verification enabled."""
        bundle_data = _make_policy_bundle()
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, bundle_data)

        result = fetch_policy("https://example.com/policy.json", self.output_path, verify=True)
        self.assertEqual(result, self.output_path)
        self.assertTrue(self.output_path.exists())
        self.assertEqual(self.output_path.read_bytes(), bundle_data)
        mock_import.assert_called_once_with(self.output_path, verify=True)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_policy_success_without_verify(self, mock_urlopen):
        """Policy fetch skips verification when verify=False."""
        bundle_data = _make_policy_bundle()
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, bundle_data)

        result = fetch_policy("https://example.com/policy.json", self.output_path, verify=False)
        self.assertEqual(result, self.output_path)
        self.assertTrue(self.output_path.exists())

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_policy_creates_parent_dirs(self, mock_urlopen):
        """fetch_policy creates missing parent directories."""
        deep_path = Path(self.tmpdir) / "a" / "b" / "c" / "policy.json"
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b'{"policy":{}}')

        fetch_policy("https://example.com/policy.json", deep_path, verify=False)
        self.assertTrue(deep_path.parent.is_dir())

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_policy_url_error(self, mock_urlopen):
        """fetch_policy re-raises URLError on network failure."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        with self.assertRaises(urllib.error.URLError):
            fetch_policy("https://bad.example.com/policy.json", self.output_path)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_policy_insecure_url_error(self, mock_urlopen):
        """fetch_policy re-raises InsecureURLError for non-HTTPS URLs."""
        mock_urlopen.side_effect = InsecureURLError("Not HTTPS")
        with self.assertRaises(InsecureURLError):
            fetch_policy("http://bad.example.com/policy.json", self.output_path)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_policy_response_too_large(self, mock_urlopen):
        """fetch_policy re-raises ResponseTooLargeError."""
        mock_urlopen.side_effect = ResponseTooLargeError("Too big")
        with self.assertRaises(ResponseTooLargeError):
            fetch_policy("https://example.com/policy.json", self.output_path)


# ── fetch_advisories ─────────────────────────────────────────────────────


class TestFetchAdvisories(unittest.TestCase):
    """Tests for fetch_advisories() — success, bad content type, zip extraction."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.output_dir = Path(self.tmpdir) / "advisories"

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_json_advisory(self, mock_urlopen):
        """Fetching a single JSON advisory saves it to disk."""
        json_data = json.dumps({"advisory": "CVE-2025-0001"}).encode()
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, json_data)

        count = fetch_advisories("https://example.com/adv.json", self.output_dir)
        self.assertEqual(count, 1)
        json_files = list(self.output_dir.glob("advisory-*.json"))
        self.assertEqual(len(json_files), 1)
        self.assertEqual(json_files[0].read_bytes(), json_data)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_zip_advisory(self, mock_urlopen):
        """Fetching a zip archive extracts all .json files."""
        zip_bytes = _make_zip_bytes(
            {
                "adv1.json": json.dumps({"id": "CVE-1"}).encode(),
                "sub/adv2.json": json.dumps({"id": "CVE-2"}).encode(),
            }
        )
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, zip_bytes)

        count = fetch_advisories("https://example.com/adv.zip", self.output_dir)
        self.assertEqual(count, 2)
        self.assertTrue((self.output_dir / "adv1.json").exists())
        self.assertTrue((self.output_dir / "sub" / "adv2.json").exists())

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_advisories_creates_output_dir(self, mock_urlopen):
        """fetch_advisories creates the output directory if missing."""
        json_data = b'{"ok":true}'
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, json_data)

        new_dir = Path(self.tmpdir) / "new" / "dir"
        count = fetch_advisories("https://example.com/adv.json", new_dir)
        self.assertEqual(count, 1)
        self.assertTrue(new_dir.is_dir())

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_advisories_url_error(self, mock_urlopen):
        """fetch_advisories re-raises URLError on network failure."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("timeout")

        with self.assertRaises(urllib.error.URLError):
            fetch_advisories("https://bad.example.com/adv.zip", self.output_dir)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_advisories_insecure_url(self, mock_urlopen):
        """fetch_advisories re-raises InsecureURLError."""
        mock_urlopen.side_effect = InsecureURLError("Not HTTPS")
        with self.assertRaises(InsecureURLError):
            fetch_advisories("http://bad.example.com/adv.zip", self.output_dir)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_advisories_zip_with_traversal_raises(self, mock_urlopen):
        """A zip with path traversal entries is rejected."""
        bad_zip = _make_zip_bytes({"../../etc/passwd": b"malicious"})
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, bad_zip)

        with self.assertRaises(ValueError):
            fetch_advisories("https://example.com/adv.zip", self.output_dir)

    @patch("picosentry.scan.management.safe_urlopen")
    @patch("picosentry.scan.management.verify_content")
    def test_fetch_advisories_crypto_verify_success(self, mock_verify, mock_urlopen):
        """Cryptographic verification is requested and succeeds."""
        json_data = b'{"advisory": "test"}'
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_sig_resp = MagicMock()
        mock_sig_resp.close = MagicMock()

        sig_bundle_dict = {
            "signer_identity": "test@example.com",
            "provider": "sigstore",
            "signature": "base64sig==",
            "certificate": "PEMCERT",
            "digest": "abc123",
            "signed_at": "2026-01-01T00:00:00Z",
        }

        mock_urlopen.side_effect = [
            (mock_resp, json_data),
            (mock_sig_resp, json.dumps(sig_bundle_dict).encode()),
        ]
        mock_verify.return_value = True

        count = fetch_advisories(
            "https://example.com/adv.json",
            self.output_dir,
            verify_crypto=True,
        )
        self.assertEqual(count, 1)

    @patch("picosentry.scan.management.safe_urlopen")
    @patch("picosentry.scan.management.verify_content")
    def test_fetch_advisories_crypto_verify_failure_raises(self, mock_verify, mock_urlopen):
        """Cryptographic verification failure raises ValueError."""
        json_data = b'{"advisory": "test"}'
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_sig_resp = MagicMock()
        mock_sig_resp.close = MagicMock()

        sig_bundle_dict = {
            "signer_identity": "test@example.com",
            "provider": "sigstore",
            "signature": "base64sig==",
            "certificate": "PEMCERT",
            "digest": "abc123",
            "signed_at": "2026-01-01T00:00:00Z",
        }

        mock_urlopen.side_effect = [
            (mock_resp, json_data),
            (mock_sig_resp, json.dumps(sig_bundle_dict).encode()),
        ]
        mock_verify.return_value = False

        with self.assertRaises(ValueError) as ctx:
            fetch_advisories(
                "https://example.com/adv.json",
                self.output_dir,
                verify_crypto=True,
            )
        self.assertIn("verification FAILED", str(ctx.exception))

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_advisories_crypto_sig_url_error_raises(self, mock_urlopen):
        """Missing .sig file when verify_crypto=True raises ValueError."""
        import urllib.error

        json_data = b'{"advisory": "test"}'
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()

        mock_urlopen.side_effect = [
            (mock_resp, json_data),
            urllib.error.URLError("not found"),
        ]

        with self.assertRaises(ValueError) as ctx:
            fetch_advisories(
                "https://example.com/adv.json",
                self.output_dir,
                verify_crypto=True,
            )
        self.assertIn("no signature found", str(ctx.exception))

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_advisories_zip_with_nested_dirs(self, mock_urlopen):
        """Zip with nested subdirectories extracts correctly."""
        zip_bytes = _make_zip_bytes(
            {
                "a/b/c/d/e/deep.json": json.dumps({"id": "deep"}).encode(),
                "root.json": json.dumps({"id": "root"}).encode(),
            }
        )
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, zip_bytes)

        count = fetch_advisories("https://example.com/adv.zip", self.output_dir)
        self.assertEqual(count, 2)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_fetch_advisories_json_array(self, mock_urlopen):
        """JSON array advisory is saved as a single file."""
        data = json.dumps([{"id": "CVE-1"}, {"id": "CVE-2"}]).encode()
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, data)

        count = fetch_advisories("https://example.com/adv.json", self.output_dir)
        self.assertEqual(count, 1)
        json_files = list(self.output_dir.glob("advisory-*.json"))
        self.assertEqual(len(json_files), 1)

    @patch("picosentry.scan.management.safe_urlopen")
    @patch("picosentry.scan.management.verify_content")
    def test_fetch_advisories_crypto_unsigned_raises(self, mock_verify, mock_urlopen):
        """A signature bundle with provider=none is rejected for verify_crypto."""
        json_data = b'{"advisory": "test"}'
        mock_resp = MagicMock()
        mock_resp.close = MagicMock()
        mock_sig_resp = MagicMock()
        mock_sig_resp.close = MagicMock()

        sig_bundle_dict = {
            "signer_identity": "",
            "provider": "none",
            "signature": "",
            "certificate": "",
            "digest": "abc",
            "signed_at": "",
        }

        mock_urlopen.side_effect = [
            (mock_resp, json_data),
            (mock_sig_resp, json.dumps(sig_bundle_dict).encode()),
        ]

        with self.assertRaises(ValueError) as ctx:
            fetch_advisories(
                "https://example.com/adv.json",
                self.output_dir,
                verify_crypto=True,
            )
        self.assertIn("not cryptographic", str(ctx.exception))


# ── push_policy ──────────────────────────────────────────────────────────


class TestPushPolicy(unittest.TestCase):
    """Tests for push_policy() — success, auth failure, HTTP errors."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.policy_path = Path(self.tmpdir) / "policy.json"
        self.policy_path.write_text('{"policy": {}}')

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_push_success(self, mock_urlopen):
        """Successful push returns True for 200 status."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b"ok")

        result = push_policy("https://example.com/upload", self.policy_path, api_key="key123")
        self.assertTrue(result)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_push_created_status(self, mock_urlopen):
        """HTTP 201 also counts as success."""
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b"created")

        result = push_policy("https://example.com/upload", self.policy_path, api_key="key123")
        self.assertTrue(result)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_push_non_2xx_returns_false(self, mock_urlopen):
        """Non-2xx status returns False."""
        mock_resp = MagicMock()
        mock_resp.status = 409
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b"conflict")

        result = push_policy("https://example.com/upload", self.policy_path)
        self.assertFalse(result)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_push_url_error_raises(self, mock_urlopen):
        """URLError is re-raised on network failure."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        with self.assertRaises(urllib.error.URLError):
            push_policy("https://bad.example.com/upload", self.policy_path)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_push_insecure_url_raises(self, mock_urlopen):
        """InsecureURLError is re-raised."""
        mock_urlopen.side_effect = InsecureURLError("Not HTTPS")
        with self.assertRaises(InsecureURLError):
            push_policy("http://bad.example.com/upload", self.policy_path)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_push_sets_bearer_auth(self, mock_urlopen):
        """Authorization header is set when api_key is provided."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b"ok")

        push_policy("https://example.com/upload", self.policy_path, api_key="secret")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertIn("Bearer secret", req.get_header("Authorization"))

    @patch("picosentry.scan.management.safe_urlopen")
    def test_push_no_auth_when_empty_api_key(self, mock_urlopen):
        """No meaningful Authorization header when api_key is empty."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b"ok")

        push_policy("https://example.com/upload", self.policy_path, api_key="")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        auth = req.get_header("Authorization")
        self.assertTrue(auth is None or auth == "")


# ── get_auth_token ──────────────────────────────────────────────────────


class TestGetAuthToken(unittest.TestCase):
    """Tests for get_auth_token() — explicit key, env vars, empty."""

    def setUp(self):
        self._saved_api = os.environ.pop(PICOSENTRY_API_KEY_ENV, None)
        self._saved_auth = os.environ.pop(PICOSENTRY_AUTH_TOKEN_ENV, None)

    def tearDown(self):
        if self._saved_api is not None:
            os.environ[PICOSENTRY_API_KEY_ENV] = self._saved_api
        else:
            os.environ.pop(PICOSENTRY_API_KEY_ENV, None)
        if self._saved_auth is not None:
            os.environ[PICOSENTRY_AUTH_TOKEN_ENV] = self._saved_auth
        else:
            os.environ.pop(PICOSENTRY_AUTH_TOKEN_ENV, None)

    def test_explicit_api_key_wins(self):
        """Explicit api_key argument takes priority over env vars."""
        os.environ[PICOSENTRY_API_KEY_ENV] = "from-env"
        self.assertEqual(get_auth_token("explicit-key"), "explicit-key")

    def test_api_key_env(self):
        """Falls back to PICOSENTRY_API_KEY env var."""
        os.environ[PICOSENTRY_API_KEY_ENV] = "env-key"
        self.assertEqual(get_auth_token(), "env-key")

    def test_auth_token_env_fallback(self):
        """Falls back to PICOSENTRY_AUTH_TOKEN when API_KEY is not set."""
        os.environ[PICOSENTRY_AUTH_TOKEN_ENV] = "auth-token"
        self.assertEqual(get_auth_token(), "auth-token")

    def test_api_key_priority_over_auth_token(self):
        """PICOSENTRY_API_KEY takes priority over PICOSENTRY_AUTH_TOKEN."""
        os.environ[PICOSENTRY_API_KEY_ENV] = "api-key"
        os.environ[PICOSENTRY_AUTH_TOKEN_ENV] = "auth-token"
        self.assertEqual(get_auth_token(), "api-key")

    def test_empty_string_returns_empty(self):
        """No keys set returns empty string."""
        self.assertEqual(get_auth_token(), "")

    def test_empty_api_key_env_falls_through(self):
        """Empty PICOSENTRY_API_KEY falls through to PICOSENTRY_AUTH_TOKEN."""
        os.environ[PICOSENTRY_API_KEY_ENV] = ""
        os.environ[PICOSENTRY_AUTH_TOKEN_ENV] = "from-auth"
        self.assertEqual(get_auth_token(), "from-auth")


# ── make_authenticated_request ───────────────────────────────────────────


class TestMakeAuthenticatedRequest(unittest.TestCase):
    """Tests for make_authenticated_request() — bearer vs API key, auth errors."""

    def setUp(self):
        self._saved_api = os.environ.pop(PICOSENTRY_API_KEY_ENV, None)
        self._saved_auth = os.environ.pop(PICOSENTRY_AUTH_TOKEN_ENV, None)

    def tearDown(self):
        if self._saved_api is not None:
            os.environ[PICOSENTRY_API_KEY_ENV] = self._saved_api
        else:
            os.environ.pop(PICOSENTRY_API_KEY_ENV, None)
        if self._saved_auth is not None:
            os.environ[PICOSENTRY_AUTH_TOKEN_ENV] = self._saved_auth
        else:
            os.environ.pop(PICOSENTRY_AUTH_TOKEN_ENV, None)

    @patch("picosentry.scan.management.safe_urlopen")
    def test_bearer_header_for_jwt_like_token(self, mock_urlopen):
        """Tokens starting with 'eyJ' (JWT) use Bearer auth."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b'{"ok":true}')

        result = make_authenticated_request("https://example.com/api", api_key="eyJhbGciOiJIUzI1NiJ9.payload.sig")
        self.assertEqual(result["status"], 200)
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertEqual(req.get_header("Authorization"), "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
        self.assertIsNone(req.get_header("X-api-key"))

    @patch("picosentry.scan.management.safe_urlopen")
    def test_api_key_header_for_short_token(self, mock_urlopen):
        """Short tokens use X-API-Key header."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b'{"ok":true}')

        make_authenticated_request("https://example.com/api", api_key="short-key-123")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        # urllib title-cases headers, so X-API-Key becomes X-Api-Key
        self.assertEqual(req.get_header("X-api-key"), "short-key-123")
        self.assertIsNone(req.get_header("Authorization"))

    @patch("picosentry.scan.management.safe_urlopen")
    def test_bearer_for_long_token(self, mock_urlopen):
        """Tokens longer than 40 chars use Bearer auth even without 'eyJ' prefix."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b"ok")

        long_token = "a" * 41
        make_authenticated_request("https://example.com/api", api_key=long_token)
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertEqual(req.get_header("Authorization"), f"Bearer {long_token}")

    @patch("picosentry.scan.management.safe_urlopen")
    def test_no_auth_when_no_token(self, mock_urlopen):
        """No auth headers when no token is available."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b"ok")

        make_authenticated_request("https://example.com/api")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertIsNone(req.get_header("Authorization"))

    @patch("picosentry.scan.management.safe_urlopen")
    def test_content_type_set_when_data_provided(self, mock_urlopen):
        """Content-Type header set when request body is provided."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b"ok")

        make_authenticated_request("https://example.com/api", data=b'{"test":1}', method="POST", api_key="key")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertEqual(req.get_header("Content-type"), "application/json")

    @patch("picosentry.scan.management.safe_urlopen")
    def test_401_raises_value_error(self, mock_urlopen):
        """HTTP 401 raises ValueError with auth failure message."""
        import urllib.error

        err = urllib.error.HTTPError("https://example.com", 401, "Unauthorized", {}, None)
        mock_urlopen.side_effect = err

        with self.assertRaises(ValueError) as ctx:
            make_authenticated_request("https://example.com/api")
        self.assertIn("Authentication failed", str(ctx.exception))

    @patch("picosentry.scan.management.safe_urlopen")
    def test_403_raises_value_error(self, mock_urlopen):
        """HTTP 403 raises ValueError with auth failure message."""
        import urllib.error

        err = urllib.error.HTTPError("https://example.com", 403, "Forbidden", {}, None)
        mock_urlopen.side_effect = err

        with self.assertRaises(ValueError) as ctx:
            make_authenticated_request("https://example.com/api")
        self.assertIn("Authentication failed", str(ctx.exception))

    @patch("picosentry.scan.management.safe_urlopen")
    def test_other_http_error_reraises(self, mock_urlopen):
        """Non-401/403 HTTP errors are re-raised as-is."""
        import urllib.error

        err = urllib.error.HTTPError("https://example.com", 500, "Server Error", {}, None)
        mock_urlopen.side_effect = err

        with self.assertRaises(urllib.error.HTTPError):
            make_authenticated_request("https://example.com/api")

    @patch("picosentry.scan.management.safe_urlopen")
    def test_insecure_url_error_reraises(self, mock_urlopen):
        """InsecureURLError is re-raised."""
        mock_urlopen.side_effect = InsecureURLError("Not HTTPS")
        with self.assertRaises(InsecureURLError):
            make_authenticated_request("http://example.com/api")

    @patch("picosentry.scan.management.safe_urlopen")
    def test_response_too_large_error_reraises(self, mock_urlopen):
        """ResponseTooLargeError is re-raised."""
        mock_urlopen.side_effect = ResponseTooLargeError("Too big")
        with self.assertRaises(ResponseTooLargeError):
            make_authenticated_request("https://example.com/api")

    @patch("picosentry.scan.management.safe_urlopen")
    def test_returns_dict_with_status_body_headers(self, mock_urlopen):
        """Successful request returns dict with status, body, headers."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.close = MagicMock()
        mock_urlopen.return_value = (mock_resp, b'{"result":"ok"}')

        result = make_authenticated_request("https://example.com/api", api_key="test")
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body"], b'{"result":"ok"}')
        self.assertIn("Content-Type", result["headers"])


# ── _validate_zip_paths ──────────────────────────────────────────────────


class TestValidateZipPaths(unittest.TestCase):
    """Tests for _validate_zip_paths() — path traversal, symlinks, safe paths."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.output_dir = Path(self.tmpdir) / "output"
        self.output_dir.mkdir()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _zip_from_entries(self, entries: dict[str, bytes]) -> zipfile.ZipFile:
        """Create a ZipFile in memory from entries dict."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, content in entries.items():
                zf.writestr(name, content)
        buf.seek(0)
        return zipfile.ZipFile(buf, "r")

    def test_safe_paths_pass(self):
        """Normal relative paths pass validation."""
        zf = self._zip_from_entries(
            {
                "safe/file.json": b'{"ok":true}',
                "top.json": b'{"ok":true}',
            }
        )
        try:
            _validate_zip_paths(zf, self.output_dir)
        finally:
            zf.close()

    def test_path_traversal_with_dotdot(self):
        """Paths containing '..' are rejected."""
        zf = self._zip_from_entries({"../etc/passwd": b"malicious"})
        try:
            with self.assertRaises(ValueError) as ctx:
                _validate_zip_paths(zf, self.output_dir)
            self.assertIn("traversal", str(ctx.exception))
        finally:
            zf.close()

    def test_absolute_path_rejected(self):
        """Absolute paths starting with '/' are rejected."""
        zf = self._zip_from_entries({"/etc/shadow": b"malicious"})
        try:
            with self.assertRaises(ValueError) as ctx:
                _validate_zip_paths(zf, self.output_dir)
            self.assertIn("absolute", str(ctx.exception))
        finally:
            zf.close()

    def test_dotdot_in_subdirectory_rejected(self):
        """Paths with '..' in the middle are rejected."""
        zf = self._zip_from_entries({"sub/../../etc/passwd": b"malicious"})
        try:
            with self.assertRaises(ValueError) as ctx:
                _validate_zip_paths(zf, self.output_dir)
            self.assertIn("traversal", str(ctx.exception))
        finally:
            zf.close()

    def test_empty_zip_passes(self):
        """Empty zip archive passes validation."""
        zf = self._zip_from_entries({})
        try:
            _validate_zip_paths(zf, self.output_dir)
        finally:
            zf.close()

    def test_deeply_nested_safe_path_passes(self):
        """Deeply nested but safe relative paths pass."""
        zf = self._zip_from_entries({"a/b/c/d/e/file.json": b"ok"})
        try:
            _validate_zip_paths(zf, self.output_dir)
        finally:
            zf.close()

    def test_mixed_safe_and_unsafe_rejects(self):
        """A zip with one unsafe entry rejects the entire archive."""
        zf = self._zip_from_entries(
            {
                "safe.json": b"ok",
                "../evil.json": b"malicious",
            }
        )
        try:
            with self.assertRaises(ValueError):
                _validate_zip_paths(zf, self.output_dir)
        finally:
            zf.close()


# ── org_config_template ─────────────────────────────────────────────────


class TestOrgConfigTemplate(unittest.TestCase):
    """Tests for org_config_template() — returns non-empty string."""

    def test_returns_non_empty_string(self):
        """Template is a non-empty string."""
        template = org_config_template()
        self.assertIsInstance(template, str)
        self.assertTrue(len(template) > 0)

    def test_contains_expected_keys(self):
        """Template contains expected YAML keys."""
        template = org_config_template()
        for key in ("org_name", "policy_url", "advisory_url", "require_signed_policy"):
            self.assertIn(key, template)

    def test_is_valid_yaml(self):
        """Template can be parsed as YAML."""
        import yaml

        template = org_config_template()
        lines = [line for line in template.splitlines() if not line.strip().startswith("#")]
        data = yaml.safe_load("\n".join(lines))
        self.assertIsInstance(data, dict)
        self.assertIn("org_name", data)
        self.assertIn("policy_url", data)


if __name__ == "__main__":
    unittest.main()
