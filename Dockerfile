# syntax=docker/dockerfile:1
#
# Multi-stage, hash-verified build. Runtime image: production dependencies + the Insight wheel only; no build
# tools, no source tree, runs as an unprivileged user and works with a read-only root filesystem.
#
# SUPPLY CHAIN: pin both FROM lines by digest before a release, e.g.
#   FROM python:3.15-slim@sha256:<digest> AS build
# `python scripts/check_pins.py --strict` (release gate) fails until this is done; Dependabot keeps the
# digests current afterwards. See docs/CI_CD.md.

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
# The build backend is hash-pinned too, and used without build isolation so pip cannot fetch anything else.
COPY requirements-build.lock ./
RUN pip install --require-hashes -r requirements-build.lock
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip wheel --no-deps --no-build-isolation --wheel-dir /dist .

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Insight" \
      org.opencontainers.image.description="Evidence-first, local threat intelligence workbench" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    INSIGHT_DATA_DIR=/data \
    NICEGUI_STORAGE_PATH=/data/.nicegui
WORKDIR /app
# Debian security fixes published after the pinned base image (Trivy scans the result in CI).
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.lock ./
RUN pip install --require-hashes -r requirements.lock
COPY --from=build /dist/ /tmp/dist/
# pip is a build tool: remove it (and the libraries it vendors) once Insight is installed.
RUN pip install --no-deps --no-index /tmp/dist/*.whl \
    && pip uninstall -y pip \
    && rm -rf /tmp/dist \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir /data \
    && chown appuser:appuser /data
# /app stays root-owned and read-only; the only writable paths are the /data volume and the /tmp tmpfs.
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"]
CMD ["insight", "serve", "--host", "0.0.0.0", "--port", "8080"]
