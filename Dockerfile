# =============================================================================
# PicoSentry — Unified Multi-stage Dockerfile
# =============================================================================
# Single image for all 4 Pico Security Series components:
#   scan      Supply-chain scanner    →  picosentry scan /path
#   sandbox   Runtime sandbox         →  picosentry sandbox <command>
#   watch     LLM defender            →  picosentry watch scan-prompt --text "..."
#   serve     API server              →  picosentry serve --host 0.0.0.0 --port 8765
#
# Build:
#   docker build -t picosentry:latest .
#
# Run:
#   docker run --rm -v $(pwd):/scan picosentry scan /scan
#   docker run --rm picosentry sandbox echo "hello"
#   docker run --rm -p 8765:8765 picosentry serve
# =============================================================================

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

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

LABEL org.opencontainers.image.title="PicoSentry"
LABEL org.opencontainers.image.description="Unified Pico Security Series — scanner, sandbox, LLM defense, orchestration"
LABEL org.opencontainers.image.version="2.0.0"
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

# Copy and install wheel from builder (with serve extras for full functionality)
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir "/tmp/picosentry-2.0.0-py3-none-any.whl[serve]" && \
    rm -f /tmp/picosentry-2.0.0-py3-none-any.whl

# Verify installation
RUN picosentry --version && picosentry health

# Ports:
#   8765 — serve (API server / dashboard)
#   8766 — watch HTTP daemon
#   8443 — sandbox daemon
EXPOSE 8765 8766 8443

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