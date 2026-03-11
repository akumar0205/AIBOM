# syntax=docker/dockerfile:1.7

# Pinned base image digest for reproducible production builds.
FROM python:3.12.8-alpine3.20@sha256:1776c88b5143eb2fb3b38f2d6f152fda9c24f00b1af31f5a22ddf3e6a86b8f24 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/home/app/.local/bin:${PATH}"

WORKDIR /app

# Install only runtime dependencies first (layer cache friendly).
COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip==24.3.1 && \
    python -m pip install --no-cache-dir --user -r requirements.txt

# Install the AIBOM package and CLI entrypoint.
COPY aibom ./aibom
COPY aibom_generator.py pyproject.toml README.md LICENSE ./
RUN python -m pip install --no-cache-dir --user .

# Create an unprivileged runtime user and writable working dirs.
RUN addgroup -g 10001 -S app && \
    adduser -S -D -H -u 10001 -s /sbin/nologin -G app app && \
    mkdir -p /workspace /out && \
    chown -R app:app /workspace /out /app /home/app

USER 10001:10001
WORKDIR /workspace

ENTRYPOINT ["aibom"]
CMD ["generate", ".", "--output", "/out/aibom.json", "--audit-mode", "--include-runtime-manifests"]
