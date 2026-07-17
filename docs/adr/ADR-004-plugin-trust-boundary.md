# ADR-004: Plugin trust boundary — signing is authenticity, sandboxing is safety

**Status:** Accepted
**Date:** 2026-07

## Context

PicoSentry plugins are user-supplied code that runs alongside the serve layer.
Two independent questions must be answered before a plugin does any work:

1. **Authenticity** — is this plugin the code its claimed author produced,
   unmodified? Answered by Ed25519 manifest signature verification against a
   trusted public-key set.
2. **Safety** — what may this plugin do once it runs? Answered by the
   `PluginHost` subprocess sandbox with deny-by-default capabilities.

A prior external review (Opus, 2026-06-24) flagged the conflation of these two:
"Ed25519 signing proves authenticity of the manifest author, not safety. Signed
malicious code is still malicious code." This ADR records the decision that
keeps them separate.

## Decision

**The sandbox is the safety boundary; signing is the admission boundary. No
plugin — signed or unsigned — is trusted with host privileges.**

- All plugin dispatch routes through `PluginHost`
  (`picosentry/serve/services/plugin_host.py`), a subprocess worker. The
  in-process `importlib` load path is reserved for the inert worker marker only
  (fork-bomb guard, `plugin_manager.py`).
- Capabilities are **deny-by-default** (`plugin_host.py:7`,
  `plugin_manager.py:37`). A plugin must declare each capability
  (`network`, `filesystem`, `subprocess`, `environment`, …) and the host
  enforces the declared set; undeclared access is refused.
- Manifest signature verification (`plugin_manager.py:290
  verify_manifest_signature`) checks the signer's public key against the
  trusted set (`BUNDLED_TRUSTED_PUBLIC_KEYS`, `plugin_manager.py:106`, plus
  `PICOSHOGUN_TRUSTED_PUBLIC_KEYS_FILE`). A signature over an untrusted key is
  rejected.
- **Signing does not expand capabilities.** A signed plugin and an unsigned
  plugin run under the same deny-by-default sandbox. Signing only decides
  *whether the plugin may load at all*.

## Production admission (fail-closed)

In `PICOSHOGUN_ENV=production`, `_SignedPluginsCheck`
(`picosentry/serve/config/settings.py:214`) raises an ERROR-level boot
violation unless `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1` is set. Because
`assert_secure()` exits with code 7 on any ERROR violation
(`picosentry/_core/config.py:124`), a production deploy that has not opted into
required signing **refuses to boot**. This is the fail-closed admission gate.

Out of production, unsigned plugins may load (the sandbox still applies), so
plugin development is not blocked by key management.

## Trust-boundary summary

| State | Loads? | Capabilities |
|-------|--------|--------------|
| Signed by trusted key | Yes (all envs) | deny-by-default sandbox |
| Signed by untrusted key | No | — |
| Unsigned, non-production | Yes | deny-by-default sandbox |
| Unsigned, production | No (boot refuses unless `REQUIRE_SIGNED_PLUGINS=1`) | — |

## Consequences

- A trusted author's signed-but-malicious plugin is still confined to its
  declared capabilities; signing is not a license to skip the sandbox.
- Operators who want defense-in-depth set both `REQUIRE_SIGNED_PLUGINS=1`
  (admission) and keep capabilities minimal (safety).
- Adding a new trusted author is a key-allowlist change, not a capability
  grant — the two concerns are reviewed independently.