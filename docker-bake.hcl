variable "TAG" {
    # Callers inject the real tag: release.yml passes the git tag, scripts/
    # build_docker_multiarch.sh derives it from pyproject. A hardcoded version
    # here went stale every release (WO4.0.0-009 evidence #6) — "dev" is the
    # local-build default and is never a published version.
    default = "dev"
}

variable "REGISTRY" {
    default = "docker.io/kirkforge"
}

variable "IMAGE_NAME" {
    default = "picodome"
}

group "default" {
    targets = ["picosentry"]
}

target "picosentry" {
    dockerfile = "Dockerfile"
    target    = "all"
    tags = [
        "${REGISTRY}/${IMAGE_NAME}:${TAG}",
        "${REGISTRY}/${IMAGE_NAME}:latest",
    ]
    platforms = [
        "linux/amd64",
        "linux/arm64",
    ]
    args = {
        BUILDKIT_INLINE_CACHE = "1"
    }
    cache-from = [
        "type=gha",
    ]
    cache-to = [
        "type=gha,mode=max",
    ]
}