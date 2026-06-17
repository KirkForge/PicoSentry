#!/usr/bin/env bash
# =============================================================================
# PicoSentry — Multi-arch Docker build helper
# =============================================================================
# Builds linux/amd64 + linux/arm64 images using docker buildx bake.
#
# Usage:
#   ./scripts/build_docker_multiarch.sh              # build only
#   ./scripts/build_docker_multiarch.sh --push       # build and push
#   ./scripts/build_docker_multiarch.sh --ci         # build CI tag only
#
# Requires:
#   - Docker with buildx enabled
#   - binfmt / qemu-user-static for arm64 emulation on amd64 hosts
#   - For --push: logged in to the registry
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

PUSH_FLAG=""
CI_FLAG=""

for arg in "$@"; do
    case "$arg" in
        --push) PUSH_FLAG="--push" ;;
        --ci)   CI_FLAG="--set=*.target=picosentry-ci" ;;
        *)      echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

if ! docker buildx version >/dev/null 2>&1; then
    echo "ERROR: docker buildx is not available." >&2
    exit 1
fi

if ! docker buildx inspect --bootstrap | grep -q "linux/arm64"; then
    echo "WARNING: linux/arm64 builder not detected. Registering QEMU binfmt..."
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes || true
fi

TAG=$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
export TAG

if [[ -n "$PUSH_FLAG" ]]; then
    echo "Building and pushing multi-arch PicoSentry image (tag: ${TAG})..."
    docker buildx bake $CI_FLAG --push
else
    echo "Building multi-arch PicoSentry image (tag: ${TAG})..."
    docker buildx bake $CI_FLAG --set '*.output=type=docker'
fi

echo "Done."
