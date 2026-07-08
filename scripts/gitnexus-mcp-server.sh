#!/usr/bin/env bash
# Stable entry point for the GitNexus MCP stdio server used by editors.
#
# This wrapper kills any orphaned GitNexus / LadybugDB locks before starting the
# real `gitnexus mcp` server, preventing the common "Resource temporarily
# unavailable" / "LadybugDB unavailable" error when Claude Code or OpenCode
# reconnect to the project-local `.gitnexus/lbug` database.
#
# If your editor allows configuring a custom MCP server command, point it at:
#   /home/kirk/Madlab/Github/KirkForge-PicoSeries-picosentry/scripts/gitnexus-mcp-server.sh
#
# For Claude Code and OpenCode the built-in GitNexus integration normally spawns
# `gitnexus mcp` itself; use this wrapper only when you need to guarantee a
# clean lock state on every connection.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Clean up stale locks/orphans before exec'ing the MCP server.
"${ROOT}/scripts/gitnexus-kill-orphans.sh" >&2

# Hand over to the real stdio MCP server.
exec gitnexus mcp
