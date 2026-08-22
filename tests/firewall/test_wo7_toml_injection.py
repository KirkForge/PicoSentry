"""WO7-008 — TOML injection via URL-path package name.

``classify_path`` percent-decodes ``%27``→``'`` and ``%0a``→``\\n``;
``scan_metadata`` interpolated the raw name into ``f\"name = '{name}'\"``.
A name with ``'`` closes the TOML string and a newline starts a new section
— attacker controls the synthetic pyproject.toml. The fix strips/escapes
those characters and rejects unsanitizable names.
"""

from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from picosentry.firewall.scanner import FirewallScanner, FirewallVerdict, _sanitize_pypi_name


class TestSanitizePypiName:
    def test_strips_single_quote(self):
        assert "'" not in _sanitize_pypi_name("evil'name")

    def test_strips_newline(self):
        assert "\n" not in _sanitize_pypi_name("evil\nname")

    def test_strips_carriage_return(self):
        assert "\r" not in _sanitize_pypi_name("evil\rname")

    def test_strips_close_bracket(self):
        assert "]" not in _sanitize_pypi_name("evil]name")

    def test_strips_hash(self):
        assert "#" not in _sanitize_pypi_name("evil#name")

    def test_rejects_empty_after_strip(self):
        assert _sanitize_pypi_name("'''") is None

    def test_rejects_empty(self):
        assert _sanitize_pypi_name("") is None

    def test_clean_name_passes(self):
        assert _sanitize_pypi_name("requests") == "requests"


class TestTomlInjectionBlocked:
    def test_injected_name_does_not_create_new_section(self, monkeypatch):
        scanner = FirewallScanner(cache_ttl_seconds=60)
        name = "evil'\n[tool.evil]\ncmd = 'rm -rf /'"
        info = {"name": "evil", "version": "1.0.0"}
        written_toml: list[str] = []

        original_write_text = __import__("pathlib").Path.write_text

        def capture_write_text(self_path, data, *args, **kwargs):
            if str(self_path).endswith("pyproject.toml"):
                written_toml.append(data)
            return original_write_text(self_path, data, *args, **kwargs)

        monkeypatch.setattr("pathlib.Path.write_text", capture_write_text)
        verdict, _ = scanner.scan_metadata("pypi", name, "1.0.0", {"info": info})
        assert verdict != FirewallVerdict.UNRESOLVED
        if written_toml:
            toml_text = written_toml[0]
            try:
                parsed = tomllib.loads(toml_text)
                assert "tool" not in parsed, "injected name created a [tool.evil] section"
                assert parsed.get("project", {}).get("name") != name
            except Exception as exc:
                raise AssertionError(f"sanitized TOML failed to parse: {exc}\n{toml_text}") from exc

    def test_quote_injection_blocked(self):
        scanner = FirewallScanner(cache_ttl_seconds=60)
        name = "x'; y = 'evil"
        verdict, _ = scanner.scan_metadata("pypi", name, "1.0.0", {"info": {"name": "x", "version": "1.0.0"}})
        assert verdict in (FirewallVerdict.BLOCK, FirewallVerdict.ALLOW, FirewallVerdict.QUARANTINE)
        cached = scanner.cache.get("pypi", name, "1.0.0")
        if cached is not None:
            assert cached[0] != FirewallVerdict.UNRESOLVED

    def test_newline_section_injection_blocked(self, monkeypatch):
        scanner = FirewallScanner(cache_ttl_seconds=60)
        name = "evil\n[tool.evil]\ncmd"
        written_toml: list[str] = []

        original_write_text = __import__("pathlib").Path.write_text

        def capture_write_text(self_path, data, *args, **kwargs):
            if str(self_path).endswith("pyproject.toml"):
                written_toml.append(data)
            return original_write_text(self_path, data, *args, **kwargs)

        monkeypatch.setattr("pathlib.Path.write_text", capture_write_text)
        _verdict, _ = scanner.scan_metadata("pypi", name, "1.0.0", {"info": {"name": "evil", "version": "1.0.0"}})
        if written_toml:
            parsed = tomllib.loads(written_toml[0])
            assert "tool" not in parsed
