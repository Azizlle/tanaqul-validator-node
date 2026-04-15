"""HTTP client for the Tanaqul backend API."""
import logging
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src import config

logger = logging.getLogger("validator.client")


def _session() -> requests.Session:
    """Build a session with retry on connection errors (NOT on 4xx/5xx)."""
    s = requests.Session()
    retry = Retry(
        total=3,
        connect=3,
        read=2,
        backoff_factor=1.0,
        status_forcelist=[],  # do NOT retry HTTP errors — only connection errors
        allowed_methods=frozenset(["GET", "POST"]),
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": config.USER_AGENT, "Accept": "application/json"})
    return s


_S = _session()


class BackendError(Exception):
    pass


def heartbeat(block_height: int, peer_count: int, uptime_seconds: int) -> dict:
    """POST /api/v1/validators/heartbeat — proves liveness."""
    body = {
        "validator_id": config.TANAQUL_VALIDATOR_ID,
        "api_key": config.TANAQUL_API_KEY,
        "node_version": config.NODE_VERSION,
        "block_height": int(block_height),
        "peer_count": int(peer_count),
        "uptime_seconds": int(uptime_seconds),
        "region": config.REGION,
    }
    r = _S.post(f"{config.API_BASE}/validators/heartbeat", json=body, timeout=10)
    if r.status_code == 401:
        raise BackendError("auth_failed: API key rejected")
    if r.status_code >= 400:
        raise BackendError(f"heartbeat HTTP {r.status_code}: {r.text[:200]}")
    return r.json()


def get_pending_blocks() -> list:
    """GET /api/v1/validators/pending-blocks — returns blocks awaiting signatures."""
    # NOTE: B08 §5.4 adds auth headers to this endpoint. Send api_key as a header
    # so the change is backward-compatible with the current unauthenticated route.
    headers = {
        "X-Validator-Id": config.TANAQUL_VALIDATOR_ID,
        "X-Validator-Api-Key": config.TANAQUL_API_KEY,
    }
    r = _S.get(f"{config.API_BASE}/validators/pending-blocks", headers=headers, timeout=10)
    if r.status_code == 401:
        raise BackendError("auth_failed: API key rejected")
    if r.status_code >= 400:
        raise BackendError(f"pending-blocks HTTP {r.status_code}: {r.text[:200]}")
    data = r.json() or {}
    return data.get("pending_blocks", [])


def sign_block(block_number: int, signature_hex: str, approved: bool = True) -> dict:
    """POST /api/v1/validators/sign-block — submits signature."""
    body = {
        "validator_id": config.TANAQUL_VALIDATOR_ID,
        "api_key": config.TANAQUL_API_KEY,
        "block_number": int(block_number),
        "signature": signature_hex,
        "approved": bool(approved),
    }
    r = _S.post(f"{config.API_BASE}/validators/sign-block", json=body, timeout=10)
    if r.status_code == 401:
        raise BackendError("auth_failed: API key rejected")
    if r.status_code == 400 and "Already signed" in (r.text or ""):
        # Idempotent — backend already has our sig
        return {"already_signed": True, "block_number": block_number}
    if r.status_code >= 400:
        raise BackendError(f"sign-block HTTP {r.status_code}: {r.text[:200]}")
    return r.json()
