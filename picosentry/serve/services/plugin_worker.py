"""Subprocess worker for sandboxed PicoShogun plugins.

The worker is spawned by `PluginHost` for each plugin. It imports the plugin
entry module, instantiates the plugin class, and then serves a JSON-RPC-like
loop over stdin/stdout. All communication is line-delimited JSON.

Capabilities are enforced by the parent process via the spawning environment
(e.g. stripped env vars, restricted cwd). The worker itself is unprivileged and
only needs to read its own plugin directory and respond to hook calls.
"""

from __future__ import annotations

import importlib
import inspect
import json
import logging
import os
import sys
import traceback
from typing import Any

logger = logging.getLogger("picoshogun.PluginWorker")

# The RPC channel. Bound to the real stdout in main() before plugin code can
# run; until then it falls back to sys.stdout so early errors still framed.
_rpc: Any = sys.stdout


def _send(obj: dict[str, Any]) -> None:
    _rpc.write(json.dumps(obj, separators=(",", ":")) + "\n")
    _rpc.flush()


def _isolate_stdout() -> None:
    # The plugin runs in this process, so any print()/stray stdout from plugin
    # code would land on the host<->worker JSON-RPC stream and be read as a
    # corrupt frame. Dup the real stdout fd for framed responses, then point
    # sys.stdout at stderr so plugin output can't poison the wire.
    global _rpc
    fd = os.dup(sys.stdout.fileno())
    _rpc = os.fdopen(fd, "w", buffering=1, encoding="utf-8")
    sys.stdout.flush()
    sys.stdout = sys.stderr


def _recv() -> dict[str, Any] | None:
    # Skip malformed request lines instead of letting a JSONDecodeError
    # propagate up and kill the worker. A partial write, stray log line, or
    # encoding glitch on the request channel should be reported and skipped,
    # not crash the plugin host. Returns None only on real EOF.
    while True:
        line = sys.stdin.readline()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning("plugin worker: malformed request JSON, skipping line: %s", exc)
            _send({"status": "error", "error": f"malformed request JSON: {exc}"})


def _find_plugin_class(module: Any) -> Any:
    from picosentry.serve.services.plugin_manager import PluginInterface

    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if inspect.isclass(attr) and issubclass(attr, PluginInterface) and attr is not PluginInterface:
            return attr
    return None


def main() -> int:
    if len(sys.argv) < 3:
        _send({"status": "error", "error": "usage: plugin_worker <plugin_path> <entry_point> [capabilities_json]"})
        return 2

    # Capture the RPC pipe and divert plugin stdout before importing the plugin
    # module — import-time print()/side effects would otherwise corrupt frames.
    _isolate_stdout()

    plugin_path = sys.argv[1]
    entry_point = sys.argv[2]
    capabilities = []
    if len(sys.argv) >= 4:
        try:
            capabilities = json.loads(sys.argv[3])
        except json.JSONDecodeError as exc:
            _send({"status": "error", "error": f"invalid capabilities JSON: {exc}"})
            return 2

    # Remove the worker script's directory from path so the plugin entry name
    # resolves from the plugin directory instead.
    sys.path.insert(0, plugin_path)
    sys.modules.pop(entry_point, None)

    try:
        module = importlib.import_module(entry_point)
    except Exception:
        # INTENTIONAL BROAD CATCH: plugin import failures are reported to the
        # host as a structured error; any import-time failure must not crash
        # the worker.
        _send({"status": "error", "error": f"failed to import plugin module: {traceback.format_exc()}"})
        return 1

    plugin_class = _find_plugin_class(module)
    if plugin_class is None:
        _send({"status": "error", "error": f"no PluginInterface implementation found in {entry_point}"})
        return 1

    try:
        instance = plugin_class()
    except Exception:
        # INTENTIONAL BROAD CATCH: plugin instantiation failures are reported
        # to the host as a structured error; any constructor failure must not
        # crash the worker.
        _send({"status": "error", "error": f"plugin instantiation failed: {traceback.format_exc()}"})
        return 1

    # Acknowledge ready with supported methods.
    _send(
        {
            "status": "ready",
            "capabilities": capabilities,
            "methods": [
                "initialize",
                "on_project_start",
                "on_project_complete",
                "on_intelligence",
                "on_alert",
                "health_check",
                "shutdown",
            ],
        }
    )

    while True:
        message = _recv()
        if message is None:
            break

        method_name = message.get("method")
        args = message.get("args", [])
        kwargs = message.get("kwargs", {})

        if not isinstance(method_name, str):
            _send({"status": "error", "error": f"invalid method name: {method_name!r}"})
            continue

        if method_name == "shutdown":
            try:
                if hasattr(instance, "shutdown"):
                    instance.shutdown()
            except Exception:
                # INTENTIONAL BROAD CATCH: plugin shutdown hook failures are
                # logged locally; the worker must still acknowledge shutdown.
                logger.exception("shutdown hook failed")
            _send({"status": "ok", "result": None})
            break

        method = getattr(instance, method_name, None)
        if method is None:
            _send({"status": "error", "error": f"unknown method: {method_name}"})
            continue

        try:
            result = method(*args, **kwargs)
            _send({"status": "ok", "result": result})
        except Exception:
            # INTENTIONAL BROAD CATCH: hook method failures are returned as
            # structured errors so the host can decide whether to continue.
            _send({"status": "error", "error": f"method {method_name} raised: {traceback.format_exc()}"})

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # INTENTIONAL BROAD CATCH: any uncaught worker crash is reported to the
        # host as a structured error before the worker exits.
        _send({"status": "error", "error": f"worker crashed: {traceback.format_exc()}"})
        raise SystemExit(1) from None
