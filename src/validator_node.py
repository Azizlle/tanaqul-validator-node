"""Tanaqul Validator Node — main loop.

Reads config from env vars, persists ECDSA key in /data, sends heartbeats,
polls for pending blocks, and signs them.
"""
import json
import logging
import signal
import sys
import time

from src import config, client, crypto, healthcheck

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("validator.main")

_SHUTDOWN = False


def _handle_signal(signum, _frame):
    global _SHUTDOWN
    logger.info(f"Signal {signum} received — shutting down cleanly")
    _SHUTDOWN = True


def _do_heartbeat(start_ts: float, signed_height: int):
    try:
        client.heartbeat(
            block_height=signed_height,
            peer_count=0,  # peer-to-peer is not a thing in this permissioned model
            uptime_seconds=int(time.time() - start_ts),
        )
        healthcheck.record_heartbeat_ok()
    except client.BackendError as e:
        healthcheck.record_heartbeat_fail()
        logger.error(f"heartbeat failed: {e}")


def _do_polling(sk, signed_block_numbers: set) -> int:
    """Poll for pending blocks, sign each one we haven't signed yet.

    Returns the highest block number signed (for heartbeat reporting).
    """
    try:
        blocks = client.get_pending_blocks()
    except client.BackendError as e:
        logger.error(f"pending-blocks fetch failed: {e}")
        return max(signed_block_numbers) if signed_block_numbers else 0

    highest = max(signed_block_numbers) if signed_block_numbers else 0
    for b in blocks:
        n = int(b.get("block_number", 0))
        h = b.get("block_hash") or ""
        if not n or not h:
            continue
        if n in signed_block_numbers:
            continue
        try:
            sig_hex = crypto.sign_block_hash(sk, h)
            res = client.sign_block(n, sig_hex, approved=True)
            signed_block_numbers.add(n)
            healthcheck.record_block_signed()
            quorum = " (QUORUM MET)" if res.get("quorum_met") else ""
            logger.info(f"signed block #{n}{quorum}")
            highest = max(highest, n)
        except client.BackendError as e:
            healthcheck.record_sign_fail()
            logger.error(f"sign block #{n} failed: {e}")
    return highest


def main():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    logger.info("=" * 60)
    logger.info(f"Tanaqul Validator Node v{config.NODE_VERSION}")
    logger.info(f"Validator ID: {config.TANAQUL_VALIDATOR_ID}")
    logger.info(f"Backend:      {config.API_BASE}")
    logger.info(f"Region:       {config.REGION}")
    logger.info(f"Heartbeat:    every {config.HEARTBEAT_INTERVAL}s")
    logger.info(f"Poll:         every {config.POLL_INTERVAL}s")
    logger.info("=" * 60)

    # Load or create signing key
    sk = crypto.load_or_create_key(config.KEY_PATH)
    logger.info(f"Public key: 0x{crypto.public_key_hex(sk)[:16]}...")

    # Start health/metrics server
    healthcheck.start_health_server(config.HEALTH_PORT)

    start_ts = time.time()
    last_heartbeat = 0.0
    last_poll = 0.0
    signed_blocks: set = set()
    signed_height = 0

    # Initial heartbeat ASAP so /health flips green
    _do_heartbeat(start_ts, signed_height)
    last_heartbeat = time.time()

    while not _SHUTDOWN:
        now = time.time()
        if now - last_heartbeat >= config.HEARTBEAT_INTERVAL:
            _do_heartbeat(start_ts, signed_height)
            last_heartbeat = now
        if now - last_poll >= config.POLL_INTERVAL:
            signed_height = max(signed_height, _do_polling(sk, signed_blocks))
            last_poll = now
        # Sleep in 1s ticks so SIGTERM is responsive
        time.sleep(1)

    logger.info("Validator node stopped cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
