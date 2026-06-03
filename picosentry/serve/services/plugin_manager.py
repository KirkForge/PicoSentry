"""Plugin system for extensible project integration.

Security note: Plugins are loaded from the local plugins/ directory only.
Each plugin must have a plugin.json manifest. The manifest is validated
before loading: entry_point must be a simple Python identifier (no dots,
no path separators), and hooks must be from the known whitelist. Arbitrary
code execution via path traversal or importlib abuse is prevented.

For production deployments, manifests can be Ed25519-signed to verify
plugin authenticity. Set PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1 to enforce
signature verification.
"""
import hashlib
import importlib
import inspect
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from typing import Any

# Ed25519 signature support — lazy-imported to avoid hard dependency
HAS_NACL = False
try:
    import nacl.exceptions  # noqa: F401
    import nacl.signing  # noqa: F401
    HAS_NACL = True
except ImportError:
    pass


logger = logging.getLogger("picoshogun.Plugins")

# Valid hook names — plugins can only register for these
VALID_HOOKS = {"project_start", "project_complete", "intelligence", "alert"}

# Manifest fields and their expected types
REQUIRED_MANIFEST_FIELDS = {"name": str, "entry_point": str}
OPTIONAL_MANIFEST_FIELDS = {
    "version": str, "author": str, "description": str,
    "hooks": list, "dependencies": list, "config": dict,
}

# Entry point must be a simple Python identifier — no dots, slashes, or path traversal
_ENTRY_POINT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


@dataclass
class PluginMetadata:
    name: str
    version: str
    author: str
    description: str
    entry_point: str
    hooks: list[str]
    dependencies: list[str]
    public_key: str | None = None
    signature: str | None = None
    signed: bool = False


class PluginInterface:
    """Base interface all plugins must implement."""

    def initialize(self, config: dict[str, Any]) -> bool:
        """Called once when plugin is loaded."""
        raise NotImplementedError

    def on_project_start(self, project_id: str, metadata: dict) -> None:
        """Hook: Before project execution."""
        pass

    def on_project_complete(self, project_id: str, result: dict) -> None:
        """Hook: After project execution."""
        pass

    def on_intelligence(self, intel: dict) -> dict | None:
        """Hook: Intelligence signal received."""
        return None

    def on_alert(self, alert: dict) -> dict | None:
        """Hook: Alert triggered."""
        return None

    def health_check(self) -> dict:
        """Return plugin health status."""
        return {"status": "healthy"}

    def shutdown(self) -> None:
        """Cleanup when plugin is unloaded."""
        pass


class PluginManager:
    """Dynamic plugin loader and lifecycle manager.

    Security measures:
    - Plugins are loaded only from the configured plugin_dir (local directory).
    - Manifest validation: entry_point must be a simple identifier, hooks must
      be from the known whitelist, required fields must be present.
    - sys.path manipulation is scoped: plugin path is added then removed in a
      try/finally block. Only the plugin directory itself is added, not arbitrary
      paths.
    - Module import is limited to the declared entry_point identifier.
    """

    def __init__(self, plugin_dir: str | None = None):
        if plugin_dir:
            self.plugin_dir = os.path.realpath(plugin_dir)
        else:
            # Resolve plugins directory: try installed package location first,
            # then fall back to relative path for development
            try:
                import plugins as _plugins_pkg
                self.plugin_dir = os.path.realpath(os.path.dirname(_plugins_pkg.__file__))
            except ImportError:
                self.plugin_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), "../plugins"))
        if not os.path.isdir(self.plugin_dir):
            logger.warning("Plugin directory not found: %s — no plugins loaded", self.plugin_dir)
        self.plugins: dict[str, PluginInterface] = {}
        self.metadata: dict[str, PluginMetadata] = {}
        self.hooks: dict[str, list[str]] = {
            "project_start": [],
            "project_complete": [],
            "intelligence": [],
            "alert": [],
        }
        self._load_plugins()

    @staticmethod
    def _validate_manifest(meta: dict, manifest_path: str) -> list[str]:
        """Validate plugin manifest. Returns list of issues (empty = valid)."""
        issues: list[str] = []

        # Required fields
        for field, expected_type in REQUIRED_MANIFEST_FIELDS.items():
            if field not in meta:
                issues.append(f"Missing required field: {field}")
            elif not isinstance(meta[field], expected_type):
                issues.append(f"Field '{field}' must be {expected_type.__name__}, got {type(meta[field]).__name__}")

        if issues:
            return issues  # Can't validate further without name/entry_point

        # Entry point must be a simple Python identifier — no path traversal
        entry_point = meta["entry_point"]
        if not _ENTRY_POINT_RE.match(entry_point):
            issues.append(
                f"entry_point '{entry_point}' is not a valid Python module identifier "
                f"(must match {_ENTRY_POINT_RE.pattern})"
            )

        # Hooks must be from the known whitelist
        hooks = meta.get("hooks", [])
        if not isinstance(hooks, list):
            issues.append("'hooks' must be a list")
        else:
            unknown = [h for h in hooks if h not in VALID_HOOKS]
            if unknown:
                issues.append(f"Unknown hooks: {unknown}. Valid hooks: {sorted(VALID_HOOKS)}")

        # Name must be a reasonable string
        name = meta.get("name", "")
        if not isinstance(name, str) or not name.strip():
            issues.append("Plugin name must be a non-empty string")

        return issues

    @staticmethod
    def _compute_manifest_signature_content(meta: dict, module_checksum: str) -> str:
        """Compute the canonical content to sign/verify for a plugin manifest.

        The signed content includes the manifest name, version, entry_point,
        hooks, and the SHA-256 checksum of the entry module. This ensures
        both the manifest and code are verified.
        """
        hooks = meta.get("hooks", [])
        return json.dumps({
            "name": meta.get("name", ""),
            "version": meta.get("version", ""),
            "entry_point": meta.get("entry_point", ""),
            "hooks": sorted(hooks) if isinstance(hooks, list) else [],
            "module_sha256": module_checksum,
        }, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def verify_manifest_signature(meta: dict, module_checksum: str,
                                  signature_hex: str, public_key_hex: str) -> bool:
        """Verify an Ed25519 signature on a plugin manifest.

        Args:
            meta: The parsed plugin.json manifest dict.
            module_checksum: SHA-256 hex digest of the entry module file.
            signature_hex: Hex-encoded Ed25519 signature.
            public_key_hex: Hex-encoded Ed25519 public key.

        Returns:
            True if signature is valid, False otherwise.
        """
        if not HAS_NACL:
            logger.warning("pynacl not installed — cannot verify Ed25519 signatures")
            return False

        try:
            from nacl.exceptions import BadSignatureError
            from nacl.signing import VerifyKey

            verify_key = VerifyKey(bytes.fromhex(public_key_hex))
            message = PluginManager._compute_manifest_signature_content(meta, module_checksum)
            verify_key.verify(message.encode(), bytes.fromhex(signature_hex))
            return True
        except BadSignatureError:
            logger.warning("Ed25519 signature verification failed: BadSignatureError")
            return False
        except Exception as e:
            logger.warning("Ed25519 signature verification failed: %s", e)
            return False

    def _load_plugins(self):
        """Discover and load all plugins from plugin directory."""
        if not os.path.exists(self.plugin_dir):
            logger.info("Plugin directory not found: %s", self.plugin_dir)
            return

        for entry in os.listdir(self.plugin_dir):
            plugin_path = os.path.join(self.plugin_dir, entry)
            manifest_path = os.path.join(plugin_path, "plugin.json")

            if not os.path.isdir(plugin_path) or not os.path.exists(manifest_path):
                continue

            # Verify plugin_path hasn't escaped the plugin directory via symlinks
            real_plugin_path = os.path.realpath(plugin_path)
            if not real_plugin_path.startswith(self.plugin_dir + os.sep) and real_plugin_path != self.plugin_dir:
                logger.error("Plugin path escapes plugin_dir: %s -> %s", plugin_path, real_plugin_path)
                continue

            try:
                with open(manifest_path) as f:
                    meta = json.load(f)

                # Validate manifest before loading
                issues = self._validate_manifest(meta, manifest_path)
                if issues:
                    logger.error("Plugin '%s' manifest validation failed: %s", entry, '; '.join(issues))
                    continue

                self._load_plugin(plugin_path, meta)
            except Exception as e:
                logger.error("Failed to load plugin %s: %s", entry, e)

    def _load_plugin(self, path: str, meta: dict):
        """Load a single plugin by its manifest."""
        name = meta["name"]
        entry = meta["entry_point"]

        # Compute full module checksum for signature verification
        module_file = os.path.join(path, f"{entry}.py")
        module_checksum = ""
        if os.path.exists(module_file):
            with open(module_file, "rb") as f:
                module_checksum = hashlib.sha256(f.read()).hexdigest()
            logger.info("Plugin '%s' entry module checksum: sha256:%s", name, module_checksum[:16])
        else:
            logger.warning("Plugin '%s' entry module not found at %s", name, module_file)

        # Ed25519 signature verification
        require_signed = os.environ.get("PICOSHOGUN_REQUIRE_SIGNED_PLUGINS", "").lower() in ("1", "true", "yes")
        sig_hex = meta.get("signature")
        pub_key_hex = meta.get("public_key")

        if require_signed:
            if not sig_hex or not pub_key_hex:
                logger.error("Plugin '%s': PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1 but no signature/public_key in manifest", name)
                return
            if not module_checksum:
                logger.error("Plugin '%s': cannot verify signature — entry module not found", name)
                return
            if not self.verify_manifest_signature(meta, module_checksum, sig_hex, pub_key_hex):
                logger.error("Plugin '%s': Ed25519 signature verification FAILED — refusing to load", name)
                return
            logger.info("Plugin '%s': Ed25519 signature verified", name)
        elif sig_hex and pub_key_hex and module_checksum and HAS_NACL:
            # Optional: verify if signature is present but not required
            if self.verify_manifest_signature(meta, module_checksum, sig_hex, pub_key_hex):
                logger.info("Plugin '%s': Ed25519 signature verified (optional)", name)
            else:
                logger.warning("Plugin '%s': Ed25519 signature present but INVALID — loading anyway (not required)", name)

        # Add plugin path to sys.path (scoped — removed in finally)
        sys.path.insert(0, path)
        try:
            module = importlib.import_module(entry)

            # Find plugin class
            plugin_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (inspect.isclass(attr) and
                    issubclass(attr, PluginInterface) and
                    attr != PluginInterface):
                    plugin_class = attr
                    break

            if plugin_class is None:
                logger.error("Plugin '%s': no class implementing PluginInterface found in module '%s'", name, entry)
                return

            instance = plugin_class()
            if instance.initialize(meta.get("config", {})):
                self.plugins[name] = instance
                self.metadata[name] = PluginMetadata(
                    name=name,
                    version=meta.get("version", "0.0.1"),
                    author=meta.get("author", "unknown"),
                    description=meta.get("description", ""),
                    entry_point=entry,
                    hooks=meta.get("hooks", []),
                    dependencies=meta.get("dependencies", []),
                    public_key=pub_key_hex if meta.get("public_key") else None,
                    signature=sig_hex if meta.get("signature") else None,
                    signed=require_signed or bool(sig_hex and pub_key_hex),
                )

                # Register hooks (only validated ones)
                for hook in meta.get("hooks", []):
                    if hook in self.hooks:
                        self.hooks[hook].append(name)

                logger.info("Plugin loaded: %s v%s", name, self.metadata[name].version)
            else:
                logger.warning("Plugin '%s' initialize() returned False — skipped", name)
        except Exception as e:
            logger.error("Failed to load plugin '%s': %s", name, e)
        finally:
            # Always remove the plugin path from sys.path to prevent leakage
            if path in sys.path:
                sys.path.remove(path)

    def dispatch(self, hook: str, **kwargs):
        """Dispatch event to all plugins registered for a hook."""
        if hook not in VALID_HOOKS:
            logger.warning("Dispatch called with unknown hook '%s' — ignoring", hook)
            return []

        results = []
        for plugin_name in self.hooks.get(hook, []):
            plugin = self.plugins.get(plugin_name)
            if not plugin:
                continue

            try:
                method = getattr(plugin, f"on_{hook}", None)
                if method:
                    result = method(**kwargs)
                    if result:
                        results.append({"plugin": plugin_name, "result": result})
            except Exception as e:
                logger.error("Plugin %s hook %s failed: %s", plugin_name, hook, e)

        return results

    def get_status(self) -> dict[str, Any]:
        """Get status of all loaded plugins."""
        status: dict[str, Any] = {}
        for name, plugin in self.plugins.items():
            try:
                health = plugin.health_check()
                status[name] = {
                    "metadata": {k: v for k, v in self.metadata[name].__dict__.items()},
                    "health": health,
                }
            except Exception as e:
                status[name] = {
                    "error": str(e),
                    "health": {"status": "unhealthy"},
                }
        return status

    def unload_all(self):
        """Gracefully shutdown all plugins."""
        for name, plugin in self.plugins.items():
            try:
                plugin.shutdown()
                logger.info("Plugin unloaded: %s", name)
            except Exception as e:
                logger.error("Plugin %s shutdown failed: %s", name, e)

        self.plugins.clear()
        self.metadata.clear()
        for hook_list in self.hooks.values():
            hook_list.clear()


# Global plugin manager instance
plugin_manager = PluginManager()
