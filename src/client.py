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
        #: ⛔ READS ONLY. A timeout on a WRITE is INDETERMINATE, not a failure — the
        #: submission may already have been applied — and replaying it here repeats it
        #: BELOW the application, where no caller can see it and no idempotency reasoning
        #: applies. Retrying a GET is free; retrying a write is a decision that belongs to
        #: whoever knows what the write meant.
        allowed_methods=frozenset(["GET"]),
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": config.USER_AGENT, "Accept": "application/json"})
    return s


_S = _session()


class BackendError(Exception):
    pass


def _request(verb: str, url: str, **kw):
    """Every HTTP call goes through here, so a network failure is a `BackendError`.

    ⛔ THE NODE USED TO DIE ON A NETWORK BLIP. `requests` raises `Timeout` /
    `ConnectionError`, which is not a `BackendError`, and the poll loop catches only
    `BackendError` — so a read timeout on any call escaped to `main()`, which has no
    handler, and the process exited. Every failure counter stayed at zero for the
    commonest real failure there is, and every caller's careful reasoning about fetch
    failures rested on an exception type that never arrived.
    """
    try:
        return getattr(_S, verb)(url, **kw)
    except requests.exceptions.RequestException as e:
        raise BackendError(f"{verb.upper()} {url.rsplit('/', 1)[-1]}: "
                           f"{type(e).__name__}: {e}") from e


def heartbeat(block_height: int, peer_count: int, uptime_seconds: int,
              public_key_hex: str = None) -> dict:
    """POST /api/v1/validators/heartbeat — proves liveness.

    P2-003 2026-05-29: if public_key_hex is supplied, the backend persists
    it on the validators row and uses it to verify ECDSA signatures on
    /sign-block. Sent on every heartbeat (cheap, idempotent on the backend
    — only writes when value changes).
    """
    body = {
        "validator_id": config.TANAQUL_VALIDATOR_ID,
        "api_key": config.TANAQUL_API_KEY,
        "node_version": config.NODE_VERSION,
        "block_height": int(block_height),
        "peer_count": int(peer_count),
        "uptime_seconds": int(uptime_seconds),
        "region": config.REGION,
    }
    if public_key_hex:
        body["public_key_hex"] = public_key_hex
    r = _request("post", f"{config.API_BASE}/validators/heartbeat", json=body, timeout=10)
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
    r = _request("get", f"{config.API_BASE}/validators/pending-blocks", headers=headers, timeout=10)
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
    r = _request("post", f"{config.API_BASE}/validators/sign-block", json=body, timeout=10)
    if r.status_code == 401:
        raise BackendError("auth_failed: API key rejected")
    if r.status_code == 400 and "Already signed" in (r.text or ""):
        # Idempotent — backend already has our sig
        return {"already_signed": True, "block_number": block_number}
    if r.status_code >= 400:
        raise BackendError(f"sign-block HTTP {r.status_code}: {r.text[:200]}")
    return r.json()


def get_block_contents(block_number: int) -> dict:
    """GET /api/v1/validators/blocks/{n}/contents — the leaf INPUTS of a sealed block.

    ⛔ THIS DELIBERATELY DOES NOT RETURN `event_root` OR `tx_root`, and that omission is
    the mechanism rather than an oversight. `/pending-blocks` hands this node a
    `block_hash` and a `merkle_root`, which is why a v1 node could sign without checking
    anything. The other two roots are served by nothing, so the only way to hold them is
    to build the leaves and merkle them — and a `tv2` signature therefore could not have
    been produced by a node that did not do that work.
    """
    headers = {
        "X-Validator-Id": config.TANAQUL_VALIDATOR_ID,
        "X-Validator-Api-Key": config.TANAQUL_API_KEY,
    }
    r = _request("get", f"{config.API_BASE}/validators/blocks/{int(block_number)}/contents",
               headers=headers, timeout=10)
    if r.status_code == 401:
        raise BackendError("auth_failed: API key rejected")
    if r.status_code >= 400:
        raise BackendError(f"contents HTTP {r.status_code}: {r.text[:200]}")
    return r.json() or {}


def report_refusal(*, block_number: int, verdict: str, signature_hex: str,
                   reported_at: str, observed_block_hash: str = "",
                   expected_block_hash: str = "", observed_prev_hash: str = "",
                   expected_prev_hash: str = "", match_root: str = "",
                   event_root: str = "", tx_root: str = "", match_count: int = 0,
                   event_count: int = 0, tx_count: int = 0, hash_timestamp: str = "",
                   creator_id: str = "") -> dict:
    """POST /api/v1/validators/report-refusal — state, under our own key, what we will not
    attest and why.

    ⛔ WHY THIS IS NOT JUST `sign_block(approved=False)`. `/sign-block` verifies a signature
    against the roots the PLATFORM recomputed, so a node that disagrees about a root cannot
    produce a signature that verifies there: it gets one uninformative 401 and its
    objection is stored nowhere. **The disagreements most worth recording are exactly the
    ones that channel cannot carry.**

    ⛔ AND THE VERDICT IS INSIDE THE SIGNED BYTES (`tr2|`), so this is evidence rather than
    a flag written by the party being objected to.

    ⚠️ Every field here is committed by the pre-image the node signed. The endpoint rebuilds
    that string FROM THIS BODY and verifies it, so a field sent differently from how it was
    signed does not produce a wrong record — it produces no record at all.
    """
    body = {
        "validator_id": config.TANAQUL_VALIDATOR_ID,
        "api_key": config.TANAQUL_API_KEY,
        "block_number": int(block_number),
        "verdict": verdict,
        "observed_block_hash": observed_block_hash,
        "expected_block_hash": expected_block_hash,
        "observed_prev_hash": observed_prev_hash,
        "expected_prev_hash": expected_prev_hash,
        "match_root": match_root,
        "event_root": event_root,
        "tx_root": tx_root,
        "match_count": int(match_count),
        "event_count": int(event_count),
        "tx_count": int(tx_count),
        "hash_timestamp": hash_timestamp,
        "creator_id": creator_id,
        "reported_at": reported_at,
        "signature": signature_hex,
    }
    r = _request("post", f"{config.API_BASE}/validators/report-refusal", json=body, timeout=10)
    if r.status_code == 401:
        raise BackendError("auth_failed: API key rejected")
    if r.status_code >= 400:
        raise BackendError(f"report-refusal HTTP {r.status_code}: {r.text[:200]}")
    return r.json() or {}
