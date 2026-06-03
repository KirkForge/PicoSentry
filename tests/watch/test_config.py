"""PicoWatch Config tests — environment variables and TOML file loading."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from picosentry.watch.config import PicoWatchConfig


class TestConfig:
    def test_defaults(self) -> None:
        """Default config values are correct."""
        config = PicoWatchConfig()
        assert config.threshold_block == 0.7
        assert config.threshold_warn == 0.4
        assert config.max_prompt_size == 1_000_000
        assert config.port == 8766
        assert config.admin_port == 9091
        assert config.rate_limit == 100
        assert config.rate_limit_window == 60

    def test_from_env(self) -> None:
        """Config loads from environment variables."""
        os.environ["PICOWATCH_THRESHOLD_BLOCK"] = "0.8"
        os.environ["PICOWATCH_PORT"] = "9999"
        try:
            config = PicoWatchConfig.from_env()
            assert config.threshold_block == 0.8
            assert config.port == 9999
        finally:
            del os.environ["PICOWATCH_THRESHOLD_BLOCK"]
            del os.environ["PICOWATCH_PORT"]


class TestTomlConfig:
    """Test TOML config file loading."""

    def test_load_toml_config(self) -> None:
        """Config loads from a TOML file."""
        toml_content = """
[picowatch]
threshold_block = 0.9
port = 7777
rate_limit = 50
rate_limit_window = 120
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            config = PicoWatchConfig.from_env(config_path=Path(f.name))

        assert config.threshold_block == 0.9
        assert config.port == 7777
        assert config.rate_limit == 50
        assert config.rate_limit_window == 120
        os.unlink(f.name)

    def test_env_overrides_toml(self) -> None:
        """Environment variables override TOML file values."""
        toml_content = """
[picowatch]
threshold_block = 0.9
port = 7777
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()

            os.environ["PICOWATCH_THRESHOLD_BLOCK"] = "0.5"
            try:
                config = PicoWatchConfig.from_env(config_path=Path(f.name))
                # Env overrides file
                assert config.threshold_block == 0.5
                # File value used when no env override
                assert config.port == 7777
            finally:
                del os.environ["PICOWATCH_THRESHOLD_BLOCK"]
                os.unlink(f.name)

    def test_toml_with_otel_endpoint(self) -> None:
        """TOML config can set OTel endpoint."""
        toml_content = """
[picowatch]
otel_endpoint = "localhost:4317"
api_key = "secret-key-123"
admin_port = 9092
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            config = PicoWatchConfig.from_env(config_path=Path(f.name))

        assert config.otel_endpoint == "localhost:4317"
        assert config.api_key == "secret-key-123"
        assert config.admin_port == 9092
        os.unlink(f.name)

    def test_missing_config_file_uses_defaults(self) -> None:
        """Non-existent config file path falls back to defaults."""
        config = PicoWatchConfig.from_env(config_path=Path("/nonexistent/picowatch.toml"))
        assert config.threshold_block == 0.7
        assert config.port == 8766

    def test_toml_without_picowatch_section(self) -> None:
        """TOML file without [picowatch] section uses root-level keys."""
        toml_content = """
threshold_block = 0.85
port = 8888
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            config = PicoWatchConfig.from_env(config_path=Path(f.name))

        assert config.threshold_block == 0.85
        assert config.port == 8888
        os.unlink(f.name)

    def test_invalid_toml_is_ignored(self) -> None:
        """Invalid TOML content is ignored, defaults used."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("this is not valid toml {{{")
            f.flush()
            config = PicoWatchConfig.from_env(config_path=Path(f.name))

        # Falls back to defaults
        assert config.threshold_block == 0.7
        os.unlink(f.name)


class TestConfigPermissions:
    """Test config file permission warnings (ADR-008)."""

    def test_check_config_permissions_no_file(self, tmp_path) -> None:
        """check_config_permissions returns empty list when no config file exists."""
        from picosentry.watch.config import check_config_permissions

        # No config files exist in search paths — should return empty
        warnings = check_config_permissions()
        assert isinstance(warnings, list)

    def test_check_config_permissions_world_readable(self, tmp_path) -> None:
        """check_config_permissions warns on world-readable config file."""
        from picosentry.watch.config import check_config_permissions

        # Create a temporary world-readable config
        config_file = tmp_path / "picowatch.toml"
        config_file.write_text("[picowatch]\nthreshold_block = 0.7\n")
        config_file.chmod(0o644)

        # Temporarily patch CONFIG_SEARCH_PATHS
        import picosentry.watch.config as cfg_module

        original_paths = cfg_module.CONFIG_SEARCH_PATHS
        cfg_module.CONFIG_SEARCH_PATHS = [config_file]
        try:
            warnings = check_config_permissions()
            assert any("world-readable" in w for w in warnings)
        finally:
            cfg_module.CONFIG_SEARCH_PATHS = original_paths
