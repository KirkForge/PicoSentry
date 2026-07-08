#!/usr/bin/env bash
# Rebuild the GitNexus graph index for this repo in a controlled Docker container.
#
# Why Docker? The project uses a native LadybugDB binding (lbugjs.node) that is
# compiled against a specific Node ABI and OpenSSL version. The host may run a
# different Node/libssl combination, causing the host `gitnexus`/`npx gitnexus`
# analyze to fail with cryptic SQLite/LadybugDB errors such as
# "Resource temporarily unavailable" or "manual WAL checkpoint failed".
# Running the build inside the pinned `node:22.12.0` + libssl3 image is the
# reliable, reproducible path.
#
# Usage:
#   scripts/gitnexus-analyze.sh
#
# After the script completes, restart (or reconnect) your editor's GitNexus MCP
# client so it opens the freshly built lbug database without a stale lock.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_NAME="$(basename "${ROOT}")"

DOCKER_IMAGE="node:22.12.0"

echo "[gitnexus-analyze] repo: ${ROOT}"
echo "[gitnexus-analyze] Docker image: ${DOCKER_IMAGE}"

# 1. Clean up any leftover locks/orphans from previous sessions.
"${ROOT}/scripts/gitnexus-kill-orphans.sh"

# 2. Ensure the local .gitnexus directory is writable by the current user after
#    Docker writes to it as root.
mkdir -p "${ROOT}/.gitnexus"

HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

# 3. Run the analyzer inside Docker. The container installs gitnexus globally
#    and executes the project-local run.cjs wrapper when present, falling back
#    to npx. Output is streamed live.
echo "[gitnexus-analyze] starting Docker build (this takes ~2-3 minutes)..."
docker run --rm \
  -v "${ROOT}:/workspace" \
  -w /workspace \
  "${DOCKER_IMAGE}" \
  bash -c "
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq libssl3 >/dev/null
    npm i -g gitnexus --silent
    if [[ -f .gitnexus/run.cjs ]]; then
      node .gitnexus/run.cjs analyze
    else
      npx gitnexus analyze
    fi
    # Fix ownership from inside the container so the host user owns the index.
    chown -R ${HOST_UID}:${HOST_GID} /workspace/.gitnexus
  "

# 5. Docker sometimes leaves JSON metadata files owned by root even after the
#    in-container chown (async writes, overlay quirks, or UID mapping issues).
#    Fix ownership from the host side as a safety net so editors can read the
#    lbug database and the metadata files.
if [[ -n "$(command -v sudo)" ]]; then
  echo "[gitnexus-analyze] fixing ownership of .gitnexus/ (host side)"
  sudo chown -R "$(id -u):$(id -g)" "${ROOT}/.gitnexus"
fi

# 6. Final sanity check on the host.
echo "[gitnexus-analyze] verifying host CLI can read the index..."
cd "${ROOT}"
gitnexus status

echo ""
echo "[gitnexus-analyze] SUCCESS. Index rebuilt at ${ROOT}/.gitnexus/"
echo "[gitnexus-analyze] IMPORTANT: Restart or reconnect your editor's GitNexus"
echo "                  MCP client (Claude Code / OpenCode) so it opens the fresh"
echo "                  lbug database without a stale file handle."
