#!/usr/bin/env bash
# =============================================================================
# PicoSentry — Multi-arch Docker build helper
# =============================================================================
# Builds linux/amd64 + linux/arm64 images using docker buildx bake.
#
# Usage:
#   ./scripts/build_docker_multiarch.sh              # build to OCI tarball
#   ./scripts/build_docker_multiarch.sh --push       # build and push
#   ./scripts/build_docker_multiarch.sh --ci         # build CI tag only
#   ./scripts/build_docker_multiarch.sh --load       # build + load current platform
#
# Requires:
#   - Docker with buildx enabled
#   - A docker-container buildx builder (created automatically if missing)
#   - binfmt / qemu-user-static for arm64 emulation on amd64 hosts. If arm64 is
#     not available, the script prints the registration command and exits.
#   - For --push: logged in to the registry
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

PUSH_FLAG=""
CI_FLAG=""
LOAD_FLAG=""

for arg in "$@"; do
    case "$arg" in
        --push) PUSH_FLAG="--push" ;;
        --ci)   CI_FLAG="--set=*.target=picosentry-ci" ;;
        --load) LOAD_FLAG="1" ;;
        *)      echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

if [[ -n "$PUSH_FLAG" && -n "$LOAD_FLAG" ]]; then
    echo "ERROR: --push and --load are mutually exclusive." >&2
    exit 1
fi

if ! docker buildx version >/dev/null 2>&1; then
    echo "ERROR: docker buildx is not available." >&2
    exit 1
fi

BUILDER_NAME="picosentry-multiarch"

# Ensure a docker-container builder exists. The default docker driver cannot
# export multi-platform images locally.
if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    echo "Creating docker-container builder '${BUILDER_NAME}'..."
    docker buildx create --name "${BUILDER_NAME}" --driver docker-container --bootstrap --use
fi

# Use the dedicated builder for the rest of the script.
if ! docker buildx use "${BUILDER_NAME}" >/dev/null 2>&1; then
    echo "ERROR: failed to activate builder '${BUILDER_NAME}'." >&2
    exit 1
fi

# Newer buildx bake enables filesystem entitlements by default; local OCI output
# writes to /tmp, which requires an explicit allow. Disable the check for this
# helper script since both output paths are transient build artifacts.
export BUILDX_BAKE_ENTITLEMENTS_FS=0

SUPPORTED_PLATFORMS=$(docker buildx inspect "${BUILDER_NAME}" --bootstrap 2>/dev/null | awk '/Platforms:/{sub(/.*Platforms:[[:space:]]*/, ""); print}')

if [[ "$SUPPORTED_PLATFORMS" != *"linux/arm64"* ]]; then
    echo "ERROR: this builder does not support linux/arm64." >&2
    echo "Register QEMU binfmt with one of the following, then re-run:" >&2
    echo "  docker run --rm --privileged multiarch/qemu-user-static --reset -p yes" >&2
    echo "  # or, on Debian/Ubuntu:" >&2
    echo "  sudo apt-get install qemu-user-static && sudo update-binfmts --enable" >&2
    exit 1
fi

TAG=$(python3 -c "import pathlib, tomllib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])")
export TAG

if [[ -n "$PUSH_FLAG" ]]; then
    echo "Building and pushing multi-arch PicoSentry image (tag: ${TAG})..."
    docker buildx bake --builder "${BUILDER_NAME}" $CI_FLAG --push
elif [[ -n "$LOAD_FLAG" ]]; then
    echo "Building and loading single-platform PicoSentry image (tag: ${TAG})..."
    docker buildx bake --builder "${BUILDER_NAME}" $CI_FLAG --set '*.output=type=docker'
else
    DEST="/tmp/picosentry-multiarch-${TAG}.oci.tar"
    echo "Building multi-arch PicoSentry image (tag: ${TAG}) to ${DEST}..."
    docker buildx bake --builder "${BUILDER_NAME}" $CI_FLAG \
        --set '*.output=type=oci,dest='"${DEST}"''
    echo "Multi-arch OCI archive written to: ${DEST}"
    if command -v skopeo >/dev/null 2>&1; then
        echo "Manifest contents:"
        skopeo inspect --raw "oci-archive:${DEST}" | grep -E '"architecture"|"os"' || true
    fi
fi

echo "Done."
