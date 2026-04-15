"""Internal HTTP server exposing /health and /metrics."""
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

logger = logging.getLogger("validator.health")

# ─── Prometheus metrics ──────────────────────────────────────────────────────
HEARTBEATS_OK    = Counter("validator_heartbeats_ok_total",   "Successful heartbeats sent")
HEARTBEATS_FAIL  = Counter("validator_heartbeats_fail_total", "Failed heartbeats")
BLOCKS_SIGNED    = Counter("validator_blocks_signed_total",   "Blocks successfully signed")
SIGN_FAIL        = Counter("validator_sign_fail_total",       "Failed sign-block attempts")
LAST_HEARTBEAT   = Gauge(  "validator_last_heartbeat_unix",   "Unix ts of last successful heartbeat")
UPTIME_SECONDS   = Gauge(  "validator_uptime_seconds",        "Seconds since process start")

_START_TS = time.time()
_LAST_OK_HEARTBEAT = 0.0


def record_heartbeat_ok():
    global _LAST_OK_HEARTBEAT
    HEARTBEATS_OK.inc()
    _LAST_OK_HEARTBEAT = time.time()
    LAST_HEARTBEAT.set(_LAST_OK_HEARTBEAT)


def record_heartbeat_fail():
    HEARTBEATS_FAIL.inc()


def record_block_signed():
    BLOCKS_SIGNED.inc()


def record_sign_fail():
    SIGN_FAIL.inc()


def _is_healthy() -> bool:
    """Healthy if last successful heartbeat was within 90s (3 missed cycles)."""
    if _LAST_OK_HEARTBEAT == 0:
        # Allow 60s grace at startup
        return (time.time() - _START_TS) < 60
    return (time.time() - _LAST_OK_HEARTBEAT) < 90


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence default access log

    def do_GET(self):
        if self.path == "/health":
            UPTIME_SECONDS.set(time.time() - _START_TS)
            healthy = _is_healthy()
            body = json.dumps({
                "status": "ok" if healthy else "degraded",
                "uptime_seconds": int(time.time() - _START_TS),
                "last_heartbeat_unix": _LAST_OK_HEARTBEAT,
                "last_heartbeat_age_seconds": int(time.time() - _LAST_OK_HEARTBEAT) if _LAST_OK_HEARTBEAT else None,
            }).encode("utf-8")
            self.send_response(200 if healthy else 503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/metrics":
            UPTIME_SECONDS.set(time.time() - _START_TS)
            data = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_response(404)
        self.end_headers()


def start_health_server(port: int):
    """Spawn the health/metrics server on a background daemon thread."""
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True, name="health-server")
    t.start()
    logger.info(f"Health server listening on 0.0.0.0:{port} (paths: /health, /metrics)")
    return server
