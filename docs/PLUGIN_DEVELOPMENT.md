# PicoShogun Plugin Development Guide

PicoShogun is the plugin system used by `picosentry serve` to extend the server
with custom hooks (notifications, intelligence enrichment, alert filtering,
etc.) without running third-party code inside the main server process.

This guide explains how to write, package, sign, and deploy a plugin.

## What a plugin can do

A plugin implements one or more lifecycle hooks that the server calls over a
subprocess JSON-RPC channel:

| Hook | When called | Return value |
|------|-------------|--------------|
| `initialize(config)` | Once when the plugin worker starts | `bool` |
| `on_project_start(project_id, metadata)` | When a project run starts | `None` |
| `on_project_complete(project_id, result)` | When a project run finishes | `None` |
| `on_intelligence(intel)` | When new intelligence is ingested | enriched intel dict, or `None` |
| `on_alert(alert)` | When an alert is raised | alert dict, or `None` to suppress |
| `health_check()` | Periodic health probes | `{"status": "ok"\|"unhealthy", ...}` |
| `shutdown()` | When the server is stopping | `None` |

Plugins run in a **dedicated subprocess** spawned by `PluginHost`. The parent
process strips the environment, restricts the working directory to the plugin
directory, and enforces a deny-by-default **capability model**. Plugins cannot
read host secrets, access the network, or write files unless they declare the
corresponding capability and the operator has authorized it.

## Manifest (`plugin.json`)

Every plugin must contain a `plugin.json` manifest at the root of its directory:

```json
{
  "name": "my_notifier",
  "version": "1.0.0",
  "author": "you@example.com",
  "description": "Post alerts to an internal webhook",
  "entry_point": "handler",
  "hooks": ["alert"],
  "dependencies": [],
  "capabilities": ["network"],
  "public_key": "ffdbacc3ef1b141c1b75e4e7f0da291e17e64229fcfb9f959bdb6b694fa3ed02",
  "signature": "36943c9f..."
}
```

Field reference:

- `name` — unique identifier; must match `^[a-zA-Z0-9_.-]+$`.
- `entry_point` — Python module name (without `.py`) that contains a
  `PluginInterface` subclass. The module is imported from the plugin directory.
- `hooks` — subset of `project_start`, `project_complete`, `intelligence`,
  `alert`. The server only registers hooks declared here.
- `capabilities` — subset of:
  - `network` — worker receives host `HTTP_PROXY`/`HTTPS_PROXY` and can open
    outbound sockets.
  - `filesystem` — worker can read/write outside its own directory.
  - `subprocess` — worker can spawn child processes.
  - `environment` — worker receives the full host environment instead of a
    stripped minimal set.
  - `detection_write` — returned hook results may be used to modify server state.
    Without this capability the server treats returned data as read-only advice.
- `public_key` / `signature` — Ed25519 public key and detached minisign-style
  signature used to verify the manifest author. The key must be in the server's
  trusted-public-key allowlist (`BUNDLED_TRUSTED_PUBLIC_KEYS` or
  `PICOSHOGUN_TRUSTED_PUBLIC_KEYS`) or the plugin is rejected unless signing is
  optional in the current mode.

## Minimal handler (`handler.py`)

```python
from typing import Any
from picosentry.serve.services.plugin_manager import PluginInterface

class MyNotifier(PluginInterface):
    def initialize(self, config: dict[str, Any]) -> bool:
        self.webhook_url = config.get("webhook_url", "")
        return bool(self.webhook_url)

    def on_alert(self, alert: dict) -> dict | None:
        # Post to webhook if network capability is granted.
        return alert

    def health_check(self) -> dict:
        return {"status": "ok" if self.webhook_url else "unhealthy"}
```

Only one `PluginInterface` subclass per module is discovered. The class name is
irrelevant.

## Capabilities are deny-by-default

A plugin that does **not** declare a capability is denied that surface area:

- No `network` → the worker process has no route to outbound sockets unless the
  host firewall permits it; proxy env vars are removed.
- No `filesystem` → the worker `cwd` is locked to its own directory.
- No `environment` → the worker receives only a minimal set of env vars required
  for Python to boot (`PATH`, `PYTHONPATH`, `HOME`, `TMPDIR`, etc.). Host
  secrets such as `PICODOME_POLICY_KEY`, `DATABASE_URL`, or cloud credentials
  are stripped.
- No `subprocess` → spawning children is blocked by the seccomp-bpf / seatbelt
  policy applied to the worker.

If a plugin declares a capability it does not need, `PluginHost` still enforces
the declaration by passing it to the worker and logging it for audit, but the
actual host-level enforcement is what matters. Operators should review
`capabilities` before deploying a plugin.

## Signing a plugin

Plugins must be signed with a trusted Ed25519 key before production deployment.
The manifest signature covers a canonical JSON payload containing the plugin
name, version, entry point, sorted hooks, and the SHA-256 checksum of the
entry module file:

```python
import hashlib
import json
from pathlib import Path
from nacl.signing import SigningKey

plugin_dir = Path("/path/to/my_notifier")
entry_file = plugin_dir / "handler.py"
module_checksum = hashlib.sha256(entry_file.read_bytes()).hexdigest()

manifest = json.loads((plugin_dir / "plugin.json").read_text())
payload = json.dumps(
    {
        "name": manifest["name"],
        "version": manifest["version"],
        "entry_point": manifest["entry_point"],
        "hooks": sorted(manifest.get("hooks", [])),
        "module_sha256": module_checksum,
    },
    sort_keys=True,
    separators=(",", ":"),
)

signing_key = SigningKey(bytes.fromhex("your-private-key-hex"))
signature = signing_key.sign(payload.encode()).signature.hex()
manifest["public_key"] = signing_key.verify_key.encode().hex()
manifest["signature"] = signature
(plugin_dir / "plugin.json").write_text(json.dumps(manifest, indent=2) + "\n")
```

The server verifies the signature against the trusted-public-key allowlist
(`BUNDLED_TRUSTED_PUBLIC_KEYS` or `PICOSHOGUN_TRUSTED_PUBLIC_KEYS`) before
loading the plugin.

## Deployment

Plugins are loaded from directories listed in `PICOSHOGUN_PLUGIN_DIR`
(comma-separated). The bundled plugins live under
`picosentry/serve/plugins/`. To install a custom plugin:

1. Create a directory named after the plugin, e.g. `my_notifier/`.
2. Place `plugin.json`, the handler module, and any helper modules inside.
3. Sign `plugin.json`.
4. Add the plugin directory's parent to `PICOSHOGUN_PLUGIN_DIR`.
5. Restart `picosentry serve` or trigger a plugin reload via the API.

## Testing a plugin

Use the `PluginHost` directly in tests to exercise the subprocess boundary:

```python
from picosentry.serve.services.plugin_host import PluginHost
from picosentry.serve.services.plugin_manager import PluginMetadata

metadata = PluginMetadata(
    name="my_notifier",
    version="1.0.0",
    author="pytest",
    description="test",
    entry_point="handler",
    hooks=["alert"],
    dependencies=[],
    capabilities=[],
)

host = PluginHost(plugin_path="/path/to/my_notifier", metadata=metadata, module_checksum="abcd")
assert host.initialize({"webhook_url": "https://example.com/hook"})
host.on_alert({"message": "test"})
assert host.health_check()["status"] == "ok"
host.shutdown()
```

## Security checklist

Before deploying a plugin, verify:

- [ ] It declares only the capabilities it actually needs.
- [ ] It does not import or execute code from the network at runtime.
- [ ] It does not rely on host secrets being present in the environment.
- [ ] Its `on_intelligence` / `on_alert` return values are validated by the
      server if it does not hold `detection_write`.
- [ ] Its manifest is signed and the public key is in the server's trusted
      allowlist.
- [ ] It has a meaningful `health_check()` that fails closed when dependencies
      are unavailable.
- [ ] It expects the server to swallow hook/health-check/shutdown failures so a
      misbehaving plugin cannot crash the host; it should never rely on an
      unhandled exception crossing the subprocess boundary.
