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


HAS_NACL = False
try:
    import nacl.exceptions
    import nacl.signing  # noqa: F401
    HAS_NACL = True
except ImportError:
    pass


logger = logging.getLogger("picoshogun.Plugins")


VALID_HOOKS = {"project_start", "project_complete", "intelligence", "alert"}


REQUIRED_MANIFEST_FIELDS = {"name": str, "entry_point": str}
OPTIONAL_MANIFEST_FIELDS = {
    "version": str, "author": str, "description": str,
    "hooks": list, "dependencies": list, "config": dict,
}


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

    def initialize(self, config: dict[str, Any]) -> bool:
        raise NotImplementedError

    def on_project_start(self, project_id: str, metadata: dict) -> None:
        pass

    def on_project_complete(self, project_id: str, result: dict) -> None:
        pass

    def on_intelligence(self, intel: dict) -> dict | None:
        return None

    def on_alert(self, alert: dict) -> dict | None:
        return None

    def health_check(self) -> dict:
        return {"status": "healthy"}

    def shutdown(self) -> None:
        pass


DEFAULT_USER_PLUGIN_DIR = os.path.expanduser("~/.picosentry/plugins")


def _split_plugin_dir_env(raw: str) -> list[str]:
    """Split a comma-separated PICOSHOGUN_PLUGIN_DIR value into a clean list."""
    return [p.strip() for p in (raw or "").split(",") if p.strip()]


class PluginManager:

    def __init__(self, plugin_dir: str | None = None,
                 extra_plugin_dirs: list[str] | None = None):
        # The bundled plugin directory (shipped inside the wheel as
        # picosentry/serve/plugins/) is the lowest-priority source — it
        # must work in both the dev tree and a wheel install. A previous
        # version tried to `import plugins as _plugins_pkg` to find a
        # top-level `plugins` package; that import was dead code (the
        # actual package is `picosentry.serve.plugins`) and has been
        # removed. The relative `../plugins` fallback is the canonical
        # path in both layouts.
        self.bundled_plugin_dir: str = os.path.realpath(
            os.path.join(os.path.dirname(__file__), "../plugins")
        )

        if plugin_dir is not None:
            self._explicit_plugin_dir: str = os.path.realpath(plugin_dir)
        else:
            self._explicit_plugin_dir = ""

        # Extra dirs come from the CLI / Settings / env var, in
        # priority order. The env-var path is consulted at construction
        # time so the bundled plugins are discoverable without any
        # extra wiring; runtime reload (see `reload()`) is how the CLI
        # injects additional dirs after Settings have been parsed.
        env_dirs = _split_plugin_dir_env(os.environ.get("PICOSHOGUN_PLUGIN_DIR", ""))
        user_default = [DEFAULT_USER_PLUGIN_DIR] if os.path.isdir(DEFAULT_USER_PLUGIN_DIR) else []
        self.extra_plugin_dirs: list[str] = [
            os.path.realpath(p) for p in (list(extra_plugin_dirs or []) + env_dirs + user_default)
        ]

        self.plugins: dict[str, PluginInterface] = {}
        self.metadata: dict[str, PluginMetadata] = {}
        self.hooks: dict[str, list[str]] = {
            "project_start": [],
            "project_complete": [],
            "intelligence": [],
            "alert": [],
        }
        self._loaded_plugin_paths: set[str] = set()
        self._load_plugins()

    @property
    def plugin_dir(self) -> str:
        # Backwards-compat: existing callers that read `.plugin_dir`
        # get the bundled dir (the most useful single value).
        return self.bundled_plugin_dir

    def resolved_dirs(self) -> list[str]:
        """All plugin directories the manager will scan, in priority order.

        Order: explicit `plugin_dir` arg > extra dirs (CLI / env / user
        default) > bundled. Duplicates (by realpath) are collapsed so
        the same physical dir is never scanned twice.
        """
        seen: set[str] = set()
        ordered: list[str] = []
        for raw in [self._explicit_plugin_dir, *self.extra_plugin_dirs, self.bundled_plugin_dir]:
            if not raw:
                continue
            try:
                rp = os.path.realpath(raw)
            except OSError:
                continue
            if rp in seen:
                continue
            seen.add(rp)
            ordered.append(rp)
        return ordered

    def reload(self, extra_dirs: list[str] | None = None) -> None:
        """Re-scan the resolved directory list.

        Adds `extra_dirs` to the runtime extra_plugin_dirs list and
        re-runs the discovery loop. Already-loaded plugins (matched
        by manifest `name`) are not re-instantiated; new plugins are
        loaded. Used by `picosentry serve --plugin-dir <path>` after
        Settings have been parsed.
        """
        if extra_dirs:
            for p in extra_dirs:
                rp = os.path.realpath(p)
                if rp not in self.extra_plugin_dirs:
                    self.extra_plugin_dirs.append(rp)
        self._load_plugins()

    @staticmethod
    def _validate_manifest(meta: dict) -> list[str]:
        issues: list[str] = []


        for field, expected_type in REQUIRED_MANIFEST_FIELDS.items():
            if field not in meta:
                issues.append(f"Missing required field: {field}")
            elif not isinstance(meta[field], expected_type):
                issues.append(f"Field '{field}' must be {expected_type.__name__}, got {type(meta[field]).__name__}")

        if issues:
            return issues  # Can't validate further without name/entry_point


        entry_point = meta["entry_point"]
        if not _ENTRY_POINT_RE.match(entry_point):
            issues.append(
                f"entry_point '{entry_point}' is not a valid Python module identifier "
                f"(must match {_ENTRY_POINT_RE.pattern})"
            )


        hooks = meta.get("hooks", [])
        if not isinstance(hooks, list):
            issues.append("'hooks' must be a list")
        else:
            unknown = [h for h in hooks if h not in VALID_HOOKS]
            if unknown:
                issues.append(f"Unknown hooks: {unknown}. Valid hooks: {sorted(VALID_HOOKS)}")


        name = meta.get("name", "")
        if not isinstance(name, str) or not name.strip():
            issues.append("Plugin name must be a non-empty string")

        return issues

    @staticmethod
    def _compute_manifest_signature_content(meta: dict, module_checksum: str) -> str:
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
        dirs = self.resolved_dirs()
        loaded_count = 0
        for d in dirs:
            if not os.path.isdir(d):
                logger.info("Plugin directory not found: %s", d)
                continue
            for entry in os.listdir(d):
                plugin_path = os.path.join(d, entry)
                manifest_path = os.path.join(plugin_path, "plugin.json")

                if not os.path.isdir(plugin_path) or not os.path.exists(manifest_path):
                    continue

                real_plugin_path = os.path.realpath(plugin_path)

                # Containment check: a symlinked subdir must resolve
                # back into the directory we are scanning. This is the
                # symlink-escape guard from the original code, kept
                # verbatim per directory.
                if not real_plugin_path.startswith(d + os.sep) and real_plugin_path != d:
                    logger.error("Plugin path escapes plugin_dir: %s -> %s", plugin_path, real_plugin_path)
                    continue

                # Skip plugins we have already loaded (idempotent
                # re-scans, e.g. from `reload()`).
                if real_plugin_path in self._loaded_plugin_paths:
                    continue

                try:
                    with open(manifest_path) as f:
                        meta = json.load(f)

                    issues = self._validate_manifest(meta)
                    if issues:
                        logger.error("Plugin '%s' manifest validation failed: %s", entry, "; ".join(issues))
                        continue

                    if self._load_plugin(plugin_path, meta):
                        self._loaded_plugin_paths.add(real_plugin_path)
                        loaded_count += 1
                except Exception:
                    logger.exception("Failed to load plugin %s", entry)

        logger.info(
            "Resolved plugin dirs: %s; loaded %d plugin(s) from %d dir(s)",
            dirs, loaded_count, sum(1 for d in dirs if os.path.isdir(d)),
        )

    def _load_plugin(self, path: str, meta: dict) -> bool:
        """Load a single plugin. Returns True iff the plugin is
        registered in `self.plugins`. The caller is responsible for
        tracking the path so `reload()` is idempotent."""
        name = meta["name"]
        entry = meta["entry_point"]


        module_file = os.path.join(path, f"{entry}.py")
        module_checksum = ""
        if os.path.exists(module_file):
            with open(module_file, "rb") as f:
                module_checksum = hashlib.sha256(f.read()).hexdigest()
            logger.info("Plugin '%s' entry module checksum: sha256:%s", name, module_checksum[:16])
        else:
            logger.warning("Plugin '%s' entry module not found at %s", name, module_file)


        require_signed = os.environ.get("PICOSHOGUN_REQUIRE_SIGNED_PLUGINS", "").lower() in ("1", "true", "yes")
        sig_hex = meta.get("signature")
        pub_key_hex = meta.get("public_key")

        if require_signed:
            if not sig_hex or not pub_key_hex:
                logger.error(
                    "Plugin '%s': PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1 "
                    "but no signature/public_key in manifest",
                    name,
                )
                return False
            if not module_checksum:
                logger.error("Plugin '%s': cannot verify signature — entry module not found", name)
                return False
            if not self.verify_manifest_signature(meta, module_checksum, sig_hex, pub_key_hex):
                logger.error("Plugin '%s': Ed25519 signature verification FAILED — refusing to load", name)
                return False
            logger.info("Plugin '%s': Ed25519 signature verified", name)
        elif sig_hex and pub_key_hex and module_checksum and HAS_NACL:

            if self.verify_manifest_signature(meta, module_checksum, sig_hex, pub_key_hex):
                logger.info("Plugin '%s': Ed25519 signature verified (optional)", name)
            else:
                logger.warning(
                    "Plugin '%s': Ed25519 signature present but INVALID "
                    "— loading anyway (not required)",
                    name,
                )


        sys.path.insert(0, path)
        try:
            # Drop any cached module of the same name so the freshly
            # imported module's `PluginInterface` reference matches the
            # current class object. Without this, re-running discovery
            # in a fresh manager (or after the module is reloaded)
            # would find the cached module but `issubclass` against the
            # new `PluginInterface` would return False.
            sys.modules.pop(entry, None)
            module = importlib.import_module(entry)


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
                return False

            instance = plugin_class()
            if not instance.initialize(meta.get("config", {})):
                logger.warning("Plugin '%s' initialize() returned False — skipped", name)
                return False

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


            for hook in meta.get("hooks", []):
                if hook in self.hooks:
                    self.hooks[hook].append(name)

            logger.info("Plugin loaded: %s v%s", name, self.metadata[name].version)
            return True
        except Exception:
            logger.exception("Failed to load plugin '%s'", name)
            return False
        finally:
            # Also drop the imported module — the plugin owns the
            # lifecycle of its classes via `self.plugins[name]`, not
            # via `sys.modules`. Leaving the cached module around
            # causes stale references when the manager is recreated
            # (e.g. test fixtures, `--reload`).
            sys.modules.pop(entry, None)
            if path in sys.path:
                sys.path.remove(path)

    def dispatch(self, hook: str, **kwargs):
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
            except Exception:
                logger.exception("Plugin %s hook %s failed", plugin_name, hook)

        return results

    def get_status(self) -> dict[str, Any]:
        status: dict[str, Any] = {}
        for name, plugin in self.plugins.items():
            try:
                health = plugin.health_check()
                status[name] = {
                    "metadata": dict(self.metadata[name].__dict__.items()),
                    "health": health,
                }
            except Exception as e:
                status[name] = {
                    "error": str(e),
                    "health": {"status": "unhealthy"},
                }
        return status

    def unload_all(self):
        for name, plugin in self.plugins.items():
            try:
                plugin.shutdown()
                logger.info("Plugin unloaded: %s", name)
            except Exception:
                logger.exception("Plugin %s shutdown failed", name)

        self.plugins.clear()
        self.metadata.clear()
        for hook_list in self.hooks.values():
            hook_list.clear()


plugin_manager = PluginManager()
