# PicoSentry Docker builds

The official image supports `linux/amd64` and `linux/arm64`.

## Quick local build

```bash
docker build -t picosentry:latest .
```

## Multi-arch build and push

Requirements:

- Docker with `buildx` enabled
- `binfmt` / QEMU user-static for arm64 emulation on amd64 hosts
- Logged in to the registry if pushing

### Using `docker buildx bake`

```bash
# Build only
docker buildx bake

# Build and push
docker buildx bake --push

# CI tag without clobbering :latest
./scripts/build_docker_multiarch.sh --ci --push
```

### Using the helper script

```bash
./scripts/build_docker_multiarch.sh        # build only
./scripts/build_docker_multiarch.sh --push # build and push
```

The script auto-registers QEMU binfmt if the local builder does not list
`linux/arm64`, reads the current version from `pyproject.toml`, and builds
both architectures.

## Helm chart

`deploy/helm/picodome/values.yaml` uses `kirkforge/picodome` by default. The
chart does not require any architecture-specific settings; Kubernetes pulls the
matching manifest from the multi-arch image.

## Runtime smoke test

```bash
docker run --rm kirkforge/picosentry:latest --version
docker run --rm kirkforge/picosentry:latest sandbox echo "hello"
```
