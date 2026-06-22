# =============================================================================
# PicoSentry — Unified Multi-stage Dockerfile
# =============================================================================
# Single image for all 4 Pico Security Series components:
#   scan      Supply-chain scanner    →  picosentry scan /path
#   sandbox   Runtime sandbox         →  picosentry sandbox <command>
#   watch     LLM defender            →  picosentry watch scan-prompt --text "..."
#   serve     API server              →  picosentry serve --host 0.0.0.0 --port 8765
#
# The image installs the [all] extra so every component's optional deps
# (requests for online corpus mgmt, fastapi+uvicorn for the watch daemon,
# opentelemetry, sigstore) are present. If you want a smaller image that
# only ships the API server, build with a different target or override the
# pip install line in a derived Dockerfile.
#
# Build:
#   docker build -t picosentry:latest .
#
# Multi-arch build (requires buildx + binfmt for arm64 emulation on amd64):
#   docker buildx bake --push
#   ./scripts/build_docker_multiarch.sh --push
#
# Run:
#   docker run --rm -v $(pwd):/scan picosentry scan /scan
#   docker run --rm picosentry sandbox echo "hello"
#   docker run --rm -p 8765:8765 picosentry serve
# =============================================================================

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM python:3.12-slim AS builder

ARG BUILDPLATFORM
ARG TARGETPLATFORM

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc libffi-dev libssl-dev libseccomp-dev && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip build

WORKDIR /build

COPY pyproject.toml README.md LICENSE COMMERCIAL-LICENSE.md ./
COPY picosentry/ ./picosentry/

# Build wheel with all extras
RUN python -m build --wheel

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ARG TARGETPLATFORM

LABEL org.opencontainers.image.title="PicoSentry"
LABEL org.opencontainers.image.description="Local supply-chain scanner with kernel-sandbox enforcement (beta). See experimental.py for component maturity."
LABEL org.opencontainers.image.url="https://github.com/KirkForge/PicoSentry"
LABEL org.opencontainers.image.source="https://github.com/KirkForge/PicoSentry"
LABEL org.opencontainers.image.vendor="KirkForge"
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.authors="kirk@kirkforge.dev"
LABEL org.opencontainers.image.documentation="https://github.com/KirkForge/PicoSentry#readme"

# Install runtime deps (seccomp for sandbox, tini for signal handling)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libseccomp2 tini && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r picosentry && \
    useradd -r -g picosentry -d /home/picosentry -s /sbin/nologin picosentry && \
    mkdir -p /home/picosentry/.local/share/picosentry && \
    chown -R picosentry:picosentry /home/picosentry

WORKDIR /home/picosentry

# Copy and install wheel from builder. We install the [all] extra so every
# component's optional dependencies (scan → requests, watch-server → fastapi/
# uvicorn, serve → FastAPI+auth+croniter, otel, sigstore) are present in the
# runtime image — matching the "all 4 components" claim in the header.
# The wheel filename is version-agnostic: this image builds against whatever
# `python -m build` produced from pyproject.toml. To pin to a specific version,
# override this line in a derived Dockerfile.
COPY --from=builder /build/dist/*.whl /tmp/
# [all,grpc] — `all` covers the four subcommands (scan/watch/serve + otel/sigstore),
# `grpc` is opt-in in pyproject but is needed here so the gRPC transport
# (`picosentry sandbox daemon --transport=grpc --grpc-port=50051`) actually
# starts in the official image.  See deploy/helm/picodome/values.yaml
# `grpc.enabled` for the deployment-side switch.
RUN WHEEL=$(ls /tmp/picosentry-*-py3-none-any.whl | head -n1) && \
    pip install --no-cache-dir "${WHEEL}[all,grpc]" && \
    rm -f /tmp/picosentry-*-py3-none-any.whl

# Verify installation
RUN picosentry --version && picosentry health

# Ports:
#   8765 — serve (API server / dashboard)
#   8766 — watch HTTP daemon
#   8443 — sandbox daemon (HTTP transport; default)
#   50051 — sandbox daemon (gRPC transport; opt-in via deploy/helm/picodome `grpc.enabled=true`)
EXPOSE 8765 8766 8443 50051

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD picosentry health || exit 1

# Security: non-root user
USER picosentry

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Use tini for proper signal forwarding
ENTRYPOINT ["tini", "--", "picosentry"]
CMD ["--help"]