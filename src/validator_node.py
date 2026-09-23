"""Tanaqul Validator Node — main loop.

Reads config from env vars, persists ECDSA key in /data, sends heartbeats,
polls for pending blocks, and signs them.
"""
import json
import logging
import signal
import sys
import time

import uuid
from datetime import datetime, timezone

from src import config, client, crypto, healthcheck, verify

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


def _do_heartbeat(start_ts: float, signed_height: int, public_key_hex: str = None):
    try:
        client.heartbeat(
            block_height=signed_height,
            peer_count=0,  # peer-to-peer is not a thing in this permissioned model
            uptime_seconds=int(time.time() - start_ts),
            public_key_hex=public_key_hex,
        )
        healthcheck.record_heartbeat_ok()
    except client.BackendError as e:
        healthcheck.record_heartbeat_fail()
        logger.error(f"heartbeat failed: {e}")


def _signing_identity() -> str:
    """The validator id in the EXACT form the platform will rebuild it in.

    ⛔ 100% OF REFUSALS LOST, SILENTLY, ON A COSMETIC ENV VALUE. The node signed
    `TANAQUL_VALIDATOR_ID` verbatim into the `tr2` pre-image; the endpoint rebuilds that
    string from a `uuid.UUID` body field, which canonicalises to lowercase-hyphenated.
    Pydantic accepts uppercase and hyphen-free ids, so a perfectly valid-looking env value
    produced `401 Invalid refusal signature` on every objection — while the heartbeat,
    `/pending-blocks`, `/contents` and `/sign-block` all kept working, because `tv2` does
    not contain the id. A green node, a green `/health`, and every disagreement deleted.

    ⚠️ AN UNPARSEABLE ID IS PASSED THROUGH, NOT GUESSED. Test and staging deployments use
    non-UUID ids; canonicalising must not invent one. The platform decides.
    """
    raw = (config.TANAQUL_VALIDATOR_ID or "").strip()
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return raw


class PollState:
    """What this node has concluded, carried between polls.

    ⚠️ IN MEMORY ONLY, AND THAT IS A DECLARED LIMIT rather than an oversight. A restart
    clears `verified`, so the first block seen afterwards has no verified predecessor and
    is admitted without a chain check — see `_do_polling`. Persisting it would let a node
    refuse the whole chain forever on one bad row it can no longer re-examine, which is the
    worse failure; a node that re-acquires its chain opinion from blocks it re-verifies is
    the honest shape. What this does NOT cover: a fork that begins and ends entirely within
    a restart window.
    """

    def __init__(self):
        #: blocks whose signature the platform ACCEPTED — never "blocks we tried"
        self.signed: set = set()
        #: block number -> the hash THIS NODE computed and agreed with. Only ever written
        #: for a block that passed v2 verification.
        self.verified: dict = {}
        #: ⛔ KEYED ON THE EVIDENCE, NOT JUST THE VERDICT. Suppressing on (block, verdict)
        #: alone dropped a SECOND, materially different tampering of the same block: the
        #: record exists to state WHICH hashes disagreed, and the stored evidence would
        #: have been the first observation only, with no second page. The rate bound is the
        #: point; the uniqueness key has to be the disagreement itself.
        self.refused: dict = {}


def _evidence_key(v) -> tuple:
    """What makes two refusals the SAME disagreement rather than merely the same verdict."""
    return (verify.WIRE_VERDICTS[v.verdict], v.served_block_hash, v.computed_block_hash,
            v.served_prev_hash, v.expected_prev_hash, v.match_root, v.event_root, v.tx_root)


def _refuse(sk, state: "PollState", v, block_number: int) -> None:
    """File a signed objection — and mark it filed only once the platform accepted it.

    ⛔ THE ORDER HERE IS THE GUARD. Recording the refusal before the POST would mean one
    transient 503 permanently silences this node's objection to a tampered block: the
    suppression that stops a flood of duplicate objections would itself become what hides
    the page that matters.
    """
    wire = verify.WIRE_VERDICTS[v.verdict]
    reported_at = datetime.now(timezone.utc).isoformat()
    validator_id = _signing_identity()

    #: ⛔ ONE SET OF VALUES, TWO CONSUMERS — and it is built once so they cannot disagree.
    #: The platform rebuilds the `tr2` string FROM THE POSTED BODY and verifies it against
    #: the signature, so a single field signed differently from how it is sent does not
    #: produce a wrong record: it produces NO record, rejected at the door, on the one
    #: channel that exists because a refusal had nowhere to go. Built at two call sites
    #: this was a live divergence waiting on any future edit — a mutation to the signed
    #: half alone left the whole suite green.
    facts = dict(
        observed_block_hash=v.served_block_hash,
        expected_block_hash=v.computed_block_hash,
        observed_prev_hash=v.served_prev_hash,
        expected_prev_hash=v.expected_prev_hash,
        match_root=v.match_root, event_root=v.event_root, tx_root=v.tx_root,
        match_count=v.match_count, event_count=v.event_count, tx_count=v.tx_count,
        hash_timestamp=v.hash_timestamp, creator_id=v.creator_id,
    )

    message = verify.refusal_payload(
        number=block_number, validator_id=validator_id, verdict=wire,
        reported_at=reported_at, **facts)
    client.report_refusal(
        block_number=block_number, verdict=wire,
        signature_hex=crypto.sign_message(sk, message),
        reported_at=reported_at, **facts)
    state.refused[block_number] = _evidence_key(v)   #: only now
    healthcheck.record_block_refused()
    logger.critical(f"REFUSED block #{block_number}: {wire} — {v.detail}")


def _do_polling(sk, state: "PollState") -> int:
    """Fetch each pending block's contents, verify it, then sign or refuse.

    ⛔ WHAT THIS REPLACED, IN FULL:

        h = b.get("block_hash") or ""
        sig_hex = crypto.sign_block_hash(sk, h)

    The node took the platform's claim about a block out of the platform's own reply and
    signed it. The quorum was real and the cryptography was real; the thing attested was
    that a node had received a string.

    Returns the highest block number signed, for heartbeat reporting.
    """
    try:
        blocks = client.get_pending_blocks()
    except client.BackendError as e:
        logger.error(f"pending-blocks fetch failed: {e}")
        return max(state.signed) if state.signed else 0

    highest = max(state.signed) if state.signed else 0
    #: ascending, so a block's predecessor is verified before it is judged
    for b in sorted(blocks, key=lambda x: int(x.get("block_number", 0))):
        n = int(b.get("block_number", 0))
        served_hash = b.get("block_hash") or ""
        if not n or not served_hash or n in state.signed:
            continue

        #: ⛔ A FETCH FAILURE IS NOT A DISAGREEMENT, AND IT IS NOT A REASON TO SIGN. Both
        #: wrong answers are available here: filing a refusal puts a signed accusation on a
        #: objection channel because a load balancer hiccuped, and falling back to signing
        #: the served hash restores the exact behaviour this replaced, on the one path
        #: nobody would think to look at.
        try:
            contents = client.get_block_contents(n)
        except client.BackendError as e:
            healthcheck.record_contents_fail()
            logger.error(f"block #{n} contents fetch failed, verifying nothing: {e}")
            continue

        #: ⛔ THE PREDECESSOR IS THE ONE THIS NODE VERIFIED, never the one the platform
        #: names. `state.verified` holds only blocks that passed v2 verification, so an
        #: attested legacy block cannot seed a chain check — that would be the platform's
        #: claim laundered through one step into something that looks verified.
        #: ⛔ `merkle_root` IS SERVED HERE AND NOWHERE ELSE, and the genesis marker is
        #: derived from it. Dropping it would reinstate the false accusation with the
        #: checker still perfectly correct — the defect would live in the call, not the
        #: code it calls.
        v = verify.check_block(contents, served_hash=served_hash,
                               last_seen_hash=state.verified.get(n - 1),
                               served_merkle_root=b.get("merkle_root") or "")

        if v.ok:
            message = verify.validation_payload(
                number=n, block_hash=served_hash, prev_hash=v.served_prev_hash,
                match_root=v.match_root, event_root=v.event_root, tx_root=v.tx_root,
                match_count=v.match_count, event_count=v.event_count,
                tx_count=v.tx_count, hash_timestamp=v.hash_timestamp,
                creator_id=v.creator_id)
            try:
                res = client.sign_block(n, crypto.sign_message(sk, message), approved=True)
            except client.BackendError as e:
                healthcheck.record_sign_fail()
                logger.error(f"sign block #{n} failed: {e}")
                continue
            state.signed.add(n)
            state.verified[n] = v.computed_block_hash
            state.refused.pop(n, None)
            healthcheck.record_block_validated()
            quorum = " (QUORUM MET)" if res.get("quorum_met") else ""
            logger.info(f"VALIDATED block #{n}{quorum}")
            highest = max(highest, n)

        elif verify.should_attest_v1(v):
            #: ⚠️ Signed, because /pending-blocks keeps offering legacy blocks so they stay
            #: rescuable — but over the v1 pre-image and counted separately. The platform
            #: decides the scheme by trying v2 FIRST and falling back, so this can never
            #: inflate a validated quorum. `state.verified` is deliberately NOT written.
            try:
                client.sign_block(n, crypto.sign_block_hash(sk, served_hash), approved=True)
            except client.BackendError as e:
                healthcheck.record_sign_fail()
                logger.error(f"attest block #{n} failed: {e}")
                continue
            state.signed.add(n)
            healthcheck.record_block_attested_v1()
            logger.warning(f"ATTESTED block #{n} (legacy format, NOT validated): {v.detail}")
            highest = max(highest, n)

        elif verify.should_refuse(v):
            #: ⚠️ RE-VERIFIED EVERY POLL, REPORTED ONLY WHEN THE VERDICT CHANGES. A repaired
            #: block must become signable without restarting the fleet, so the check
            #: repeats; a standing disagreement must not be re-filed once every POLL_INTERVAL, so
            #: the report does not. The cost is one GET per poll per block in
            #: disagreement — bounded by blocks the platform is serving wrongly, not by
            #: chain size.
            if state.refused.get(n) == _evidence_key(v):
                continue
            try:
                _refuse(sk, state, v, n)
            except client.BackendError as e:
                healthcheck.record_refusal_fail()
                logger.error(f"REFUSAL for block #{n} could not be filed — a "
                             f"disagreement nobody heard: {e}")

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
    pk_hex = crypto.public_key_hex(sk)
    logger.info(f"Public key: 0x{pk_hex[:16]}...")

    # Start health/metrics server
    healthcheck.start_health_server(config.HEALTH_PORT)

    start_ts = time.time()
    last_heartbeat = 0.0
    last_poll = 0.0
    state = PollState()
    signed_height = 0

    # Initial heartbeat ASAP so /health flips green. P2-003: also publishes
    # our public key so the backend can verify subsequent ECDSA signatures.
    _do_heartbeat(start_ts, signed_height, public_key_hex=pk_hex)
    last_heartbeat = time.time()

    while not _SHUTDOWN:
        now = time.time()
        if now - last_heartbeat >= config.HEARTBEAT_INTERVAL:
            _do_heartbeat(start_ts, signed_height, public_key_hex=pk_hex)
            last_heartbeat = now
        if now - last_poll >= config.POLL_INTERVAL:
            signed_height = max(signed_height, _do_polling(sk, state))
            last_poll = now
        # Sleep in 1s ticks so SIGTERM is responsive
        time.sleep(1)

    logger.info("Validator node stopped cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
