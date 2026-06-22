// =============================================================================
// PicoSentry — Docker Buildx bake definition for multi-arch images
// =============================================================================
// Produces linux/amd64 and linux/arm64 images for kirkforge/picosentry.
//
// Build and push:
//   docker buildx bake --push
//
// Build locally (load only works for single-platform; use registry output for
// multi-platform):
//   docker buildx bake --set '*.output=type=docker'
//
// Override tags:
//   docker buildx bake --set '*.tags=kirkforge/picosentry:local'
// =============================================================================

variable "TAG" {
    default = "v2.0.14"
}

variable "REGISTRY" {
    default = "docker.io/kirkforge"
}

variable "IMAGE_NAME" {
    default = "picosentry"
}

group "default" {
    targets = ["picosentry"]
}

target "picosentry" {
    dockerfile = "Dockerfile"
    tags = [
        "${REGISTRY}/${IMAGE_NAME}:${TAG}",
        "${REGISTRY}/${IMAGE_NAME}:latest",
    ]
    platforms = [
        "linux/amd64",
        "linux/arm64",
    ]
    args = {
        // No architecture-specific build args required. The wheel is
        // pure-Python (py3-none-any) and the apt packages are available on
        // both amd64 and arm64 Debian Slim bases.
        BUILDKIT_INLINE_CACHE = "1"
    }
    cache-from = [
        "type=gha",
    ]
    cache-to = [
        "type=gha,mode=max",
    ]
}

// Variant used by CI to push a single test tag without clobbering :latest.
target "picosentry-ci" {
    inherits = ["picosentry"]
    tags = [
        "${REGISTRY}/${IMAGE_NAME}:${TAG}-ci",
    ]
}
