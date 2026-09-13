# syntax=docker/dockerfile:1.6
FROM python:3.11-slim AS base

# Non-root user for safety
RUN useradd -r -u 1000 -m -d /app validator && \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gosu && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps as root (cached layer), then drop to non-root
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/ /app/src/

# Persistent state directory (bind to a Docker volume in production).
# NOTE: this chown covers the IMAGE's /data only. A mounted volume shadows it and
# arrives root-owned, so docker-entrypoint.sh repeats the chown at runtime and then
# drops to `validator`. Both are needed: this one for the no-volume case, that one for
# every real deployment.
RUN mkdir -p /data && chown -R validator:validator /data /app

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Deliberately NOT `USER validator`. The entrypoint needs root for one chown and then
# execs the node as `validator`, so the node still runs unprivileged — see the comment
# in docker-entrypoint.sh.

# Healthcheck server runs on 8080 inside the container
EXPOSE 8080

# Container HEALTHCHECK — calls the internal /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl --fail --silent --max-time 5 http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["python", "-m", "src.validator_node"]
