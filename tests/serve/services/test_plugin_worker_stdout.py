"""A1: plugin stdout must not poison the host<->worker RPC channel.

The plugin runs inside the worker process, so a stray print() (at import time
or in a hook) would otherwise land on the JSON-RPC stdout stream and be read by
the host as a corrupt frame. The worker diverts plugin stdout to stderr; every
line on the real RPC pipe must parse as JSON.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

NOISY_PLUGIN = """
print("noise at import time")  # would corrupt the RPC stream if not diverted

from picosentry.serve.services.plugin_manager import PluginInterface


class NoisyPlugin(PluginInterface):
    def initialize(self, config):
        print("noise from a hook")
        return True
"""


def test_plugin_prints_do_not_corrupt_rpc(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plug"
    plugin_dir.mkdir()
    (plugin_dir / "noisy.py").write_text(NOISY_PLUGIN)

    proc = subprocess.run(
        [sys.executable, "-m", "picosentry.serve.services.plugin_worker", str(plugin_dir), "noisy"],
        input='{"method":"initialize","args":[{}]}\n',
        capture_output=True,
        text=True,
        timeout=30,
    )

    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert lines, f"no RPC frames emitted; stderr={proc.stderr!r}"
    # Every line on the RPC channel must be a valid JSON frame — the plugin's
    # print() output must have been diverted to stderr, not the wire.
    for ln in lines:
        json.loads(ln)
    assert "noise at import time" in proc.stderr
    assert "noise from a hook" in proc.stderr
