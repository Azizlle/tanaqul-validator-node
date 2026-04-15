"""Tanaqul Validator Node — env var configuration."""
import os
import sys


def _required(key: str) -> str:
    val = os.environ.get(key, "").strip()
    if not val:
        print(f"FATAL: required env var {key} is not set", file=sys.stderr)
        sys.exit(2)
    return val


def _int(key: str, default: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"WARN: env var {key}={raw!r} is not an int, using default {default}", file=sys.stderr)
        return default


# Required
TANAQUL_VALIDATOR_ID  = _required("TANAQUL_VALIDATOR_ID")
TANAQUL_API_KEY       = _required("TANAQUL_API_KEY")
TANAQUL_BACKEND_URL   = _required("TANAQUL_BACKEND_URL").rstrip("/")

# Optional with sane defaults
HEARTBEAT_INTERVAL = _int("TANAQUL_HEARTBEAT_INTERVAL", 30)   # seconds
POLL_INTERVAL      = _int("TANAQUL_POLL_INTERVAL", 15)        # seconds
HEALTH_PORT        = _int("TANAQUL_HEALTH_PORT", 8080)
LOG_LEVEL          = os.environ.get("TANAQUL_LOG_LEVEL", "INFO").upper()
REGION             = os.environ.get("TANAQUL_REGION", "Riyadh")
DATA_DIR           = os.environ.get("TANAQUL_DATA_DIR", "/data")
NODE_VERSION       = "1.0.0"
USER_AGENT         = f"tanaqul-validator-node/{NODE_VERSION}"

# Derived
API_BASE = f"{TANAQUL_BACKEND_URL}/api/v1"
KEY_PATH = os.path.join(DATA_DIR, "validator_key.pem")
