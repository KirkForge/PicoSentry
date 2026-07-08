#!/usr/bin/env bash
# Kill orphaned GitNexus / LadybugDB processes that may hold locks on the
# project-local `.gitnexus/lbug` database.
#
# GitNexus uses System V semaphores and an embedded LadybugDB instance. When a
# client session (Claude Code, OpenCode, or a manual `gitnexus mcp` run) crashes
# or is killed, the child process can leave the semaphore and/or DB file locked.
# The next access then fails with:
#   "LadybugDB unavailable ... (Resource temporarily unavailable)"
# This script is safe to run repeatedly and is intentionally conservative: it
# only targets processes that are actually holding the local lbug file.
#
# Usage:
#   scripts/gitnexus-kill-orphans.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LBUG="${ROOT}/.gitnexus/lbug"

echo "[gitnexus-kill-orphans] repo: ${ROOT}"

# 1. Kill any process currently holding the lbug file open.
if [[ -f "${LBUG}" ]]; then
  PIDS="$(lsof -nP -t -- "${LBUG}" 2>/dev/null || true)"
  if [[ -n "${PIDS}" ]]; then
    echo "[gitnexus-kill-orphans] lbug held by pids: ${PIDS//
/ }"
    # Try graceful first, then forceful.
    kill -TERM ${PIDS} 2>/dev/null || true
    sleep 1
    kill -KILL ${PIDS} 2>/dev/null || true
  else
    echo "[gitnexus-kill-orphans] no process holding lbug"
  fi
fi

# 2. Kill standalone `gitnexus mcp` processes that may be parked on the repo.
#    We match the repo path to avoid interfering with other projects.
ORPHANS="$(pgrep -a -f "gitnexus mcp" 2>/dev/null || true)"
if [[ -n "${ORPHANS}" ]]; then
  echo "[gitnexus-kill-orphans] found gitnexus mcp processes:"
  echo "${ORPHANS}"
  pgrep -f "gitnexus mcp" | xargs -r kill -TERM 2>/dev/null || true
  sleep 1
  pgrep -f "gitnexus mcp" | xargs -r kill -KILL 2>/dev/null || true
fi

# 3. Remove stale LadybugDB backup files in /tmp that can prevent reopening.
if ls /tmp/lbug.bak* 1>/dev/null 2>&1; then
  echo "[gitnexus-kill-orphans] removing stale /tmp/lbug.bak* files"
  rm -f /tmp/lbug.bak*
else
  echo "[gitnexus-kill-orphans] no stale /tmp/lbug.bak* files"
fi

# 4. Remove stale hook lock slots. These only contain empty marker files and
#    are harmless, but a stale slot can occasionally confuse the freshness hook.
if [[ -d "${ROOT}/.gitnexus/.hook-locks" ]]; then
  find "${ROOT}/.gitnexus/.hook-locks" -type f -mmin +60 -delete 2>/dev/null || true
fi

echo "[gitnexus-kill-orphans] done"
