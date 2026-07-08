"""Subprocess plugin host for PicoShogun.

Each plugin is loaded in a separate Python subprocess with a stripped
environment and a restricted working directory. The host communicates with
the worker over line-delimited JSON on stdin/stdout.

Capabilities are deny-by-default. The manifest declares which capabilities the
plugin needs; the host enforces the ones it can enforce directly and records
the rest for observability/audit.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import select
import subprocess
import sys
import weakref
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from picosentry.serve.services.plugin_manager import PluginMetadata

logger = logging.getLogger("picoshogun.PluginHost")

# Operational errors that can be raised by worker communication and should be
# treated as "plugin call failed, keep the host stable". Programmer errors such
# as NameError/AttributeError must not be swallowed so tests and monitoring can
# catch regressions.
_HOST_CALL_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
)


def _reap_orphan(proc: subprocess.Popen[str] | None) -> None:
    """Kill a worker subprocess whose host was dropped without shutdown().

    Registered via weakref.finalize so a caller that forgets to call
    shutdown() (e.g. a test that builds a PluginManager and lets it go out
    of scope) still gets its subprocess reaped instead of leaking it. Holds
    only the Popen, not the host, so it never blocks host GC.
    """
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=2.0)
    except (OSError, subprocess.TimeoutExpired):
        with contextlib.suppress(OSError):
            proc.kill()


class PluginHost:
    """Subprocess host for a single plugin.

    The host exposes the same lifecycle methods as a loaded
    `PluginInterface` instance, but each call is forwarded to the worker
    process. The worker is spawned with an environment scrubbed of host
    secrets unless the `environment` capability is granted.
    """

    # Env vars required for a Python subprocess to function in a minimal,
    # non-hostile environment. No secrets should be here.
    _MINIMAL_ENV_VARS: ClassVar[set[str]] = {
        "PATH",
        "PYTHONPATH",
        "PYTHONIOENCODING",
        "PYTHONUNBUFFERED",
        "TMPDIR",
        "TEMP",
        "TMP",
        "HOME",
        "USER",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    }

    # Plugin metadata used to construct env vars must be plain strings with
    # no whitespace or shell metacharacters that could leak into the child.
    _PLUGIN_NAME_RE: ClassVar[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_.-]+$")
    _CAPABILITY_RE: ClassVar[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_]+$")

    def __init__(
        self,
        plugin_path: str,
        metadata: PluginMetadata,
        module_checksum: str,
        timeout: float = 10.0,
    ):
        self.plugin_path = Path(plugin_path).resolve()
        self.metadata = metadata
        self.module_checksum = module_checksum
        self.timeout = timeout
        self._proc: subprocess.Popen[str] | None = None
        self._ready = False
        self._capabilities = set(metadata.capabilities)

        self._start_worker()
        # Safety net: if this host is GC'd without shutdown(), reap the worker.
        self._finalizer = weakref.finalize(self, _reap_orphan, self._proc)

    def _validate_env_values(self) -> None:
        """Ensure metadata values that become env vars are well-formed.

        This prevents a compromised manifest from injecting arbitrary env vars
        or shell control characters through the plugin name or capability list.
        """
        name = self.metadata.name
        if not self._PLUGIN_NAME_RE.match(name):
            raise ValueError(f"Invalid plugin name for env var: {name!r}")
        for capability in self._capabilities:
            if not self._CAPABILITY_RE.match(capability):
                raise ValueError(f"Invalid capability name for env var: {capability!r}")

    def _build_env(self) -> dict[str, str]:
        self._validate_env_values()

        if "environment" in self._capabilities:
            # Pass the host environment through, but mark the child as a
            # plugin worker so it can avoid re-spawning another host.
            env = dict(os.environ)
        else:
            # Deny-by-default: strip all host env vars except a minimal set
            # needed for Python to run. PYTHONPATH is preserved only if
            # already set (e.g. in test/dev trees) so the worker can import
            # picosentry; in production installs the package is on sys.path.
            env = {k: v for k, v in os.environ.items() if k in self._MINIMAL_ENV_VARS}
            # Always mark the worker.
            env["PICOSHOGUN_PLUGIN_WORKER"] = "1"
            env["PICOSHOGUN_PLUGIN_NAME"] = self.metadata.name

        # Encode capabilities so the worker can also reason about them.
        env["PICOSHOGUN_PLUGIN_CAPABILITIES"] = json.dumps(sorted(self._capabilities))
        return env

    def _python_executable(self) -> str:
        return sys.executable

    def _start_worker(self) -> None:
        if self._proc is not None:
            return

        env = self._build_env()
        capabilities_arg = json.dumps(sorted(self._capabilities))
        cmd = [
            self._python_executable(),
            "-m",
            "picosentry.serve.services.plugin_worker",
            str(self.plugin_path),
            self.metadata.entry_point,
            capabilities_arg,
        ]

        logger.info(
            "Starting plugin worker for '%s' with capabilities %s",
            self.metadata.name,
            sorted(self._capabilities),
        )

        # Restrict working directory to the plugin dir. Without the
        # `filesystem` capability the worker can still read its own code,
        # but it starts from its own directory rather than the server cwd.
        cwd = str(self.plugin_path)

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            cwd=cwd,
        )

        # Wait for the ready message.
        ready = self._read_message()
        if ready is None:
            self._terminate()
            raise RuntimeError(f"Plugin worker for '{self.metadata.name}' exited before ready")
        if ready.get("status") != "ready":
            self._terminate()
            raise RuntimeError(f"Plugin worker for '{self.metadata.name}' failed: {ready.get('error')}")
        self._ready = True

    def _send(self, method: str, *args: Any, **kwargs: Any) -> Any:
        if self._proc is None or self._proc.poll() is not None:
            raise RuntimeError(f"Plugin worker for '{self.metadata.name}' is not running")

        message: dict[str, Any] = {"method": method}
        if args:
            message["args"] = list(args)
        if kwargs:
            message["kwargs"] = dict(kwargs)

        if self._proc.stdin is None:
            raise RuntimeError(f"Plugin worker for '{self.metadata.name}' has no stdin channel")
        self._proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self._proc.stdin.flush()

        response = self._read_message()
        if response is None:
            raise RuntimeError(f"Plugin worker for '{self.metadata.name}' closed stdout unexpectedly")
        if response.get("status") == "error":
            raise RuntimeError(response.get("error", "unknown worker error"))
        return response.get("result")

    def _read_message(self) -> dict[str, Any] | None:
        if self._proc is None or self._proc.stdout is None:
            return None
        # Enforce a read timeout so a hung or infinite-looping plugin cannot
        # block the host thread forever. The protocol is strictly
        # request/response (one _send -> one _read_message), so the worker is
        # never more than one message ahead and select() on its stdout pipe is
        # an accurate readiness signal. On POSIX this works for pipes; if
        # select is unsupported for the fd we fall back to a blocking read.
        # ponytail: select+readline assumes no message pipelining (true here);
        # switch to a raw-fd framed reader if the protocol ever batches.
        try:
            ready, _, _ = select.select([self._proc.stdout], [], [], self.timeout)
            if not ready:
                logger.error(
                    "Plugin worker for '%s' did not respond within %.1fs; terminating",
                    self.metadata.name,
                    self.timeout,
                )
                self._terminate()
                return None
        except (OSError, ValueError):
            pass  # select unsupported for this fd — fall back to blocking read
        try:
            line = self._proc.stdout.readline()
            if not line:
                return None
            return json.loads(line)
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON from plugin worker: %s", exc)
            return None

    def _terminate(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
        except OSError as exc:
            logger.debug("closing plugin worker stdin failed: %s", exc)
        try:
            self._proc.terminate()
            self._proc.wait(timeout=2.0)
        except (OSError, subprocess.TimeoutExpired):
            try:
                self._proc.kill()
                self._proc.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                logger.warning("Failed to terminate plugin worker %s", self._proc.pid)
        self._proc = None
        self._ready = False
        fin = getattr(self, "_finalizer", None)
        if fin is not None:
            fin.detach()

    # PluginInterface-compatible API

    def initialize(self, config: dict[str, Any]) -> bool:
        return bool(self._send("initialize", config))

    def on_project_start(self, project_id: str, metadata: dict) -> None:
        self._send("on_project_start", project_id, metadata)

    def on_project_complete(self, project_id: str, result: dict) -> None:
        self._send("on_project_complete", project_id, result)

    def on_intelligence(self, intel: dict) -> dict | None:
        return self._send("on_intelligence", intel)

    def on_alert(self, alert: dict) -> dict | None:
        return self._send("on_alert", alert)

    def health_check(self) -> dict:
        try:
            return self._send("health_check") or {"status": "unhealthy"}
        except _HOST_CALL_ERRORS:
            logger.warning("Plugin health check failed", exc_info=True)
            return {"status": "unhealthy", "error": "health check failed"}

    def shutdown(self) -> None:
        try:
            self._send("shutdown")
        except _HOST_CALL_ERRORS:
            logger.debug("Shutdown request failed", exc_info=True)
        finally:
            self._terminate()

    @property
    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None and self._ready
