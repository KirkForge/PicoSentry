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

# Pin the build timestamp so the wheel is byte-identical across builds
# (reproducible builds / SLSA L3). Passed as a build arg so the image build
# is reproducible for a given source tree.
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN python -m build --wheel

FROM python:3.12-slim AS base

ARG TARGETPLATFORM

LABEL org.opencontainers.image.title="PicoSentry"
LABEL org.opencontainers.image.description="Local supply-chain scanner with kernel-sandbox enforcement (beta). See experimental.py for component maturity."
LABEL org.opencontainers.image.url="https://github.com/KirkForge/PicoSentry"
LABEL org.opencontainers.image.source="https://github.com/KirkForge/PicoSentry"
LABEL org.opencontainers.image.vendor="KirkForge"
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.authors="kirk@kirkforge.dev"
LABEL org.opencontainers.image.documentation="https://github.com/KirkForge/PicoSentry#readme"

RUN apt-get update && \
    apt-get install -y --no-install-recommends libseccomp2 tini && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r picosentry && \
    useradd -r -g picosentry -d /home/picosentry -s /sbin/nologin picosentry && \
    mkdir -p /home/picosentry/.local/share/picosentry && \
    chown -R picosentry:picosentry /home/picosentry

WORKDIR /home/picosentry

COPY --from=builder /build/dist/*.whl /tmp/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD picosentry health || exit 1

ENTRYPOINT ["tini", "--", "picosentry"]
CMD ["--help"]

FROM base AS scanner

ARG PICOSENTRY_EXTRAS=scan

# ceiling: the runtime `pip install "${WHEEL}[...]"` resolves the wheel's
# dependencies from PyPI without hash pins, so the image's dependency layer
# is not hash-pinned (the wheel itself is reproducible via SOURCE_DATE_EPOCH).
# upgrade path: install from a `uv export --frozen` requirements file (which
# carries the uv.lock hashes) instead of the bare wheel extra.
RUN WHEEL=$(ls /tmp/picosentry-*-py3-none-any.whl | head -n1) && \
    pip install --no-cache-dir "${WHEEL}[${PICOSENTRY_EXTRAS}]" && \
    rm -f /tmp/picosentry-*-py3-none-any.whl && \
    picosentry --version && picosentry health

USER picosentry

LABEL org.opencontainers.image.title="PicoSentry Scanner"

FROM base AS sandbox

ARG PICOSENTRY_EXTRAS=grpc

RUN WHEEL=$(ls /tmp/picosentry-*-py3-none-any.whl | head -n1) && \
    pip install --no-cache-dir "${WHEEL}[${PICOSENTRY_EXTRAS}]" && \
    rm -f /tmp/picosentry-*-py3-none-any.whl && \
    picosentry --version && picosentry health

USER picosentry

LABEL org.opencontainers.image.title="PicoSentry Sandbox"

EXPOSE 8443 50051

FROM base AS server

ARG PICOSENTRY_EXTRAS=serve,grpc

RUN WHEEL=$(ls /tmp/picosentry-*-py3-none-any.whl | head -n1) && \
    pip install --no-cache-dir "${WHEEL}[${PICOSENTRY_EXTRAS}]" && \
    rm -f /tmp/picosentry-*-py3-none-any.whl && \
    picosentry --version && picosentry health

USER picosentry

LABEL org.opencontainers.image.title="PicoSentry Server"

EXPOSE 8765 50051

FROM base AS all

ARG PICOSENTRY_EXTRAS=all,grpc

RUN WHEEL=$(ls /tmp/picosentry-*-py3-none-any.whl | head -n1) && \
    pip install --no-cache-dir "${WHEEL}[${PICOSENTRY_EXTRAS}]" && \
    rm -f /tmp/picosentry-*-py3-none-any.whl && \
    picosentry --version && picosentry health

USER picosentry

LABEL org.opencontainers.image.title="PicoSentry (All Components)"

EXPOSE 8765 8766 8443 50051