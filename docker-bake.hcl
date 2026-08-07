variable "TAG" {
    default = "v2.0.18"
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

target "picosentry-ci" {
    inherits = ["picosentry"]
    tags = [
        "${REGISTRY}/${IMAGE_NAME}:${TAG}-ci",
    ]
}

target "picosentry-scanner" {
    dockerfile = "Dockerfile"
    target    = "scanner"
    tags = [
        "${REGISTRY}/${IMAGE_NAME}:${TAG}-scanner",
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

target "picosentry-sandbox" {
    dockerfile = "Dockerfile"
    target    = "sandbox"
    tags = [
        "${REGISTRY}/${IMAGE_NAME}:${TAG}-sandbox",
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

target "picosentry-server" {
    dockerfile = "Dockerfile"
    target    = "server"
    tags = [
        "${REGISTRY}/${IMAGE_NAME}:${TAG}-server",
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