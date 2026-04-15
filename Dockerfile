# syntax=docker/dockerfile:1.6
FROM python:3.11-slim AS base

# Non-root user for safety
RUN useradd -r -u 1000 -m -d /app validator && \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps as root (cached layer), then drop to non-root
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/ /app/src/

# Persistent state directory (bind to a Docker volume in production)
RUN mkdir -p /data && chown -R validator:validator /data /app
USER validator

# Healthcheck server runs on 8080 inside the container
EXPOSE 8080

# Container HEALTHCHECK — calls the internal /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl --fail --silent --max-time 5 http://localhost:8080/health || exit 1

ENTRYPOINT ["python", "-m", "src.validator_node"]
