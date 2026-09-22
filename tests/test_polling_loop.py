"""The poll loop: verify, then sign or refuse.

⛔ WHAT THIS REPLACES, IN FULL:

    h = b.get("block_hash") or ""
    sig_hex = crypto.sign_block_hash(sk, h)

Eight lines that took the platform's claim about a block out of the platform's own reply
and signed it. Every test here exists to keep some part of that from coming back — because
the failure mode of this loop is not a crash, it is a node that reports itself healthy
while attesting to nothing it checked.
"""
import os

import pytest

os.environ.setdefault("TANAQUL_VALIDATOR_ID", "ci")
os.environ.setdefault("TANAQUL_API_KEY", "ci")
os.environ.setdefault("TANAQUL_BACKEND_URL", "https://example.test")

from src import validator_node, verify  # noqa: E402


class FakeBackend:
    """A platform that serves consistent blocks — and can be told to lie."""

    def __init__(self):
        self.blocks = {}
        self.signed = []
        self.refusals = []
        self.contents_calls = []
        self.contents_error = None

    def add(self, n, *, prev_hash, events=1, validatable=True, format_version=2,
            is_genesis=False, tamper=None, serve_hash=None):
        c = {
            "block_number": n, "format_version": format_version,
            "validatable": validatable, "prev_hash": prev_hash,
            "hash_timestamp": f"2026-09-23T00:00:{n:02d}+00:00",
            "creator_id": "sys", "is_genesis": is_genesis,
            "counts": {"match_count": 0, "event_count": events, "tx_count": 0},
            "match_leaves": [],
            "event_leaves": [
                {"id": f"E{n}-{i}", "event_hash": f"0xeh{n}{i}", "grams": "1.0",
                 "event_type": "MINT_NEW", "metal": "Gold", "vault_key": "VK"}
                for i in range(events)
            ],
            "tx_leaves": [],
        }
        honest = _hash_of(c)
        if tamper:
            tamper(c)
        self.blocks[n] = (c, serve_hash or honest)
        return honest

    # ── the client surface the loop uses ──
    def get_pending_blocks(self):
        return [{"block_number": n, "block_hash": h}
                for n, (_c, h) in sorted(self.blocks.items())]

    def get_block_contents(self, n):
        self.contents_calls.append(n)
        if self.contents_error:
            raise validator_node.client.BackendError(self.contents_error)
        return self.blocks[n][0]

    def sign_block(self, n, sig, approved=True):
        self.signed.append({"n": n, "sig": sig, "approved": approved})
        return {"quorum_met": False}

    def report_refusal(self, **kw):
        self.refusals.append(kw)
        return {"recorded": True}


def _hash_of(c):
    return verify.hash_block_v2(
        number=c["block_number"], prev_hash=c["prev_hash"],
        match_root=verify.merkle_root([verify.sha256(verify.match_leaf(x))
                                       for x in c["match_leaves"]]),
        event_root=verify.merkle_root([verify.sha256(verify.event_leaf(x))
                                       for x in c["event_leaves"]]),
        tx_root=verify.merkle_root([verify.sha256(verify.tx_leaf(x))
                                    for x in c["tx_leaves"]]),
        match_count=c["counts"]["match_count"], event_count=c["counts"]["event_count"],
        tx_count=c["counts"]["tx_count"], hash_timestamp=c["hash_timestamp"],
        creator_id=c["creator_id"])


@pytest.fixture
def be(monkeypatch):
    b = FakeBackend()
    for name in ("get_pending_blocks", "get_block_contents", "sign_block", "report_refusal"):
        monkeypatch.setattr(validator_node.client, name, getattr(b, name))
    return b


class FakeKey:
    """Records the bytes it was ACTUALLY asked to sign.

    ⛔ THIS IS THE SUBJECT, AND NOTHING ELSE IS. These tests first asserted on a
    `last_signed_message` field the loop set beside the sign call — so replacing the whole
    signature with `crypto.sign_block_hash(sk, served_hash)`, the exact rubber stamp this
    work removes, left the suite GREEN. The field recorded the loop's intention; the key
    records its effect. Only one of those can be tampered with by the code under test.
    """

    def __init__(self):
        self.signed_payloads = []

    def sign(self, data, hashfunc=None):
        self.signed_payloads.append(data.decode("utf-8"))
        return b"\x01" * 8

    @property
    def last(self):
        return self.signed_payloads[-1] if self.signed_payloads else None


@pytest.fixture
def sk():
    return FakeKey()


GENESIS = "0x" + "11" * 32


# ── the happy path, and what makes it a validation rather than a stamp ──────

def test_a_GOOD_block_is_signed_over_the_tv2_pre_image_it_COMPUTED(be, sk):
    """⛔ THE SIGNED BYTES MUST CONTAIN THE ROOTS THE NODE COMPUTED. `event_root` and
    `tx_root` are served by no endpoint, so a signature over a string containing them is
    the proof of work — it could not have been produced by a node that did not build the
    leaves. Signing the block hash instead proves only that a string was received."""
    honest = be.add(1, prev_hash=GENESIS)
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)

    assert [s["n"] for s in be.signed] == [1]
    assert be.refusals == []

    c = be.blocks[1][0]
    expected_msg = verify.validation_payload(
        number=1, block_hash=honest, prev_hash=GENESIS,
        match_root=verify.merkle_root([]),
        event_root=verify.merkle_root([verify.sha256(verify.event_leaf(c["event_leaves"][0]))]),
        tx_root=verify.merkle_root([]),
        match_count=0, event_count=1, tx_count=0,
        hash_timestamp=c["hash_timestamp"], creator_id="sys")
    assert sk.last == expected_msg
    assert expected_msg.startswith("tv2|")
    #: the block hash is NOT what was signed — that is the whole change
    assert sk.last != honest


def test_a_block_is_only_marked_SIGNED_when_the_platform_ACCEPTED_it(be, sk):
    """⚠️ A submit that failed must be retried, or one transient 500 silently drops this
    node out of the quorum for that block permanently."""
    be.add(1, prev_hash=GENESIS)

    def _boom(n, sig, approved=True):
        raise validator_node.client.BackendError("HTTP 503")

    validator_node.client.sign_block = _boom
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    assert 1 not in state.signed

    validator_node.client.sign_block = be.sign_block
    validator_node._do_polling(sk, state)
    assert 1 in state.signed and [s["n"] for s in be.signed] == [1]


# ── the attack the loop exists to catch ────────────────────────────────────

def test_a_TAMPERED_LEAF_is_REFUSED_and_REPORTED_not_signed(be, sk):
    """⛔ THE ATTACK. The platform serves a block whose stored hash is the honest one but
    whose leaves say something else. The old loop signed the served hash and could not have
    noticed. Now the recomputation disagrees, nothing is signed, and the objection is filed
    under this node's own key."""
    honest = be.add(1, prev_hash=GENESIS, events=2,
                    tamper=lambda c: c["event_leaves"][0].__setitem__("grams", "999.0"))
    be.blocks[1] = (be.blocks[1][0], honest)   # serve the honest hash with tampered leaves
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)

    assert be.signed == [], "a block that failed verification must not be signed"
    assert len(be.refusals) == 1
    r = be.refusals[0]
    assert r["verdict"] == "HASH_MISMATCH"
    assert r["observed_block_hash"] == honest          # what we were served
    assert r["expected_block_hash"] != honest          # what we computed
    assert r["event_root"] and r["event_count"] == 2
    assert sk.last.startswith("tr2|")
    assert verify.PLATFORM_REFUSAL_VERDICTS and r["verdict"] in verify.PLATFORM_REFUSAL_VERDICTS


def test_a_REFUSAL_is_filed_ONCE_not_once_per_poll(be, sk):
    """⛔ A REFUSAL WITH AN INFINITE RETRY IS A LOAD AMPLIFIER ON THE
    OBJECTION CHANNEL. At POLL_INTERVAL=15 a permanently-bad block would file a signed
    objection every fifteen seconds, per node — burying the one that matters under
    thousands of copies of itself.

    ⚠️ But it is RE-VERIFIED every poll, because a repaired block must be signable without
    restarting the fleet. Only the REPORT is suppressed, and only while the verdict is
    unchanged."""
    honest = be.add(1, prev_hash=GENESIS,
                    tamper=lambda c: c["event_leaves"][0].__setitem__("grams", "999.0"))
    be.blocks[1] = (be.blocks[1][0], honest)
    state = validator_node.PollState()
    for _ in range(5):
        validator_node._do_polling(sk, state)

    assert len(be.refusals) == 1, "one disagreement, one report"
    assert be.contents_calls == [1, 1, 1, 1, 1], "but re-checked every poll"
    assert be.signed == []


def test_a_REPAIRED_block_is_signed_on_the_next_poll_without_a_restart(be, sk):
    """⛔ A REFUSAL WITH NO PATH BACK IS A DELETION. If the platform fixes the block, this
    node must sign it — otherwise a single transient corruption strands the block forever
    and the operator's only remedy is restarting every node in the fleet."""
    honest = be.add(1, prev_hash=GENESIS,
                    tamper=lambda c: c["event_leaves"][0].__setitem__("grams", "999.0"))
    be.blocks[1] = (be.blocks[1][0], honest)
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    assert len(be.refusals) == 1 and be.signed == []

    be.blocks[1][0]["event_leaves"][0]["grams"] = "1.0"    # repaired
    validator_node._do_polling(sk, state)
    assert [s["n"] for s in be.signed] == [1]
    assert len(be.refusals) == 1


# ── the chain ───────────────────────────────────────────────────────────────

def test_a_BROKEN_CHAIN_is_refused_against_the_block_this_node_VERIFIED(be, sk):
    """⛔ THE PREDECESSOR IS THE ONE THIS NODE CHECKED, never the one the platform names.
    Chaining against a served `prev_hash` would be comparing the platform's claim to
    itself."""
    h1 = be.add(1, prev_hash=GENESIS)
    be.add(2, prev_hash="0x" + "99" * 32)         # does not follow #1
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)

    assert [s["n"] for s in be.signed] == [1]
    assert [r["verdict"] for r in be.refusals] == ["PREV_HASH_MISMATCH"]
    r = be.refusals[0]
    assert r["observed_prev_hash"] == "0x" + "99" * 32
    assert r["expected_prev_hash"] == h1


def test_a_block_whose_PREDECESSOR_was_never_verified_is_not_chain_checked(be, sk):
    """⚠️ THE NODE HAS AN OPINION ONLY WHERE IT HAS ONE. A node that starts mid-chain, or
    is offered #7 without #6, has nothing to compare against — refusing on that basis
    would accuse the platform of a fork every time a node restarts."""
    be.add(7, prev_hash="0x" + "abc" * 21 + "a")
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    assert [s["n"] for s in be.signed] == [7]
    assert be.refusals == []


def test_an_ATTESTED_legacy_block_does_NOT_become_a_verified_predecessor(be, sk):
    """⛔ THE SUBTLE ONE. A legacy block is signed as receipt, not verified — so it must
    NOT seed the chain check for its successor. If it did, this node would be checking
    block #2 against a hash it never recomputed, which is the platform's claim laundered
    through one extra step into something that looks verified."""
    be.add(1, prev_hash=GENESIS, format_version=1, validatable=False, serve_hash="0xlegacy")
    be.add(2, prev_hash="0xsomething-else")
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)

    assert [s["n"] for s in be.signed] == [1, 2]
    assert be.refusals == [], "block #2 had no VERIFIED predecessor, so no chain opinion"
    assert 1 not in state.verified and 2 in state.verified


# ── legacy and failure ──────────────────────────────────────────────────────

def test_a_LEGACY_block_is_attested_over_the_BARE_HASH_and_counted_separately(be, sk):
    """⚠️ Signed, because `/pending-blocks` keeps offering legacy blocks so they stay
    rescuable — but over the v1 pre-image, and counted as an attestation. The platform
    decides which scheme a signature is by trying v2 FIRST and falling back, so this can
    never inflate a validated quorum."""
    be.add(1, prev_hash=GENESIS, format_version=1, validatable=False, serve_hash="0xdeadbeef")
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)

    assert [s["n"] for s in be.signed] == [1]
    assert be.refusals == [], "a format this node cannot read is not an accusation"
    assert sk.last == "deadbeef", "the v1 pre-image is the bare hash"


def test_a_CONTENTS_FETCH_FAILURE_signs_nothing_and_accuses_nobody(be, sk):
    """⛔ THE TWO WRONG ANSWERS ARE SIGNING ANYWAY AND REPORTING A REFUSAL. A 503 is not a
    disagreement — filing one would put a signed accusation on the objection channel because
    a load balancer hiccuped. And falling back to signing the served hash would restore the
    exact behaviour this replaces, on the one path where nobody would look for it."""
    be.add(1, prev_hash=GENESIS)
    be.contents_error = "contents HTTP 503"
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)

    assert be.signed == [] and be.refusals == []
    assert 1 not in state.signed

    be.contents_error = None
    validator_node._do_polling(sk, state)
    assert [s["n"] for s in be.signed] == [1], "and it is retried once the fetch works"


def test_a_FAILED_REFUSAL_is_retried_rather_than_recorded_as_filed(be, sk):
    """⛔ THE SUPPRESSION ABOVE MUST KEY ON A REPORT THAT LANDED. Marking a refusal filed
    before the platform accepted it means one 503 permanently silences this node's
    objection to a tampered block — the failure the whole channel exists to prevent,
    reintroduced by the fix for the load amplifier."""
    honest = be.add(1, prev_hash=GENESIS,
                    tamper=lambda c: c["event_leaves"][0].__setitem__("grams", "999.0"))
    be.blocks[1] = (be.blocks[1][0], honest)

    def _boom(**kw):
        raise validator_node.client.BackendError("HTTP 503")

    validator_node.client.report_refusal = _boom
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    assert 1 not in state.refused

    validator_node.client.report_refusal = be.report_refusal
    validator_node._do_polling(sk, state)
    assert len(be.refusals) == 1 and state.refused[1] == "HASH_MISMATCH"


def test_a_block_already_signed_is_not_re_fetched(be, sk):
    be.add(1, prev_hash=GENESIS)
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    validator_node._do_polling(sk, state)
    assert be.contents_calls == [1] and len(be.signed) == 1


def test_the_REPORTED_BODY_rebuilds_the_SIGNED_BYTES_exactly(be, sk):
    """⛔ THE PLATFORM VERIFIES THE SIGNATURE AGAINST A STRING IT REBUILDS FROM THIS BODY.
    So a single field signed differently from how it is sent does not produce a wrong
    record — it produces NO record, rejected at the door, on the channel that exists
    because a refusal had nowhere to go. The failure is silent and lands in production.

    ⚠️ This is the platform's check, performed here. The two are built from one dict so
    divergence is inexpressible; this proves that is actually so rather than intended."""
    honest = be.add(1, prev_hash=GENESIS, events=3,
                    tamper=lambda c: c["event_leaves"][1].__setitem__("metal", "Silver"))
    be.blocks[1] = (be.blocks[1][0], honest)
    validator_node._do_polling(sk, validator_node.PollState())

    assert len(be.refusals) == 1
    r = dict(be.refusals[0])
    r.pop("signature_hex")
    rebuilt = verify.refusal_payload(
        number=r.pop("block_number"), validator_id="ci", **r)
    assert rebuilt == sk.last, "the platform would reject this refusal and store nothing"


def test_a_CONTENTS_FETCH_FAILURE_leaves_NO_TRACE_in_the_node_s_state(be, sk):
    """⚠️ Not signed, not verified — and not recorded as refused either. Writing a fetch
    failure into the refusal map would make the node believe it had filed an objection it
    never filed, which is the suppression guard turned into a silencer."""
    be.add(1, prev_hash=GENESIS)
    be.contents_error = "contents HTTP 503"
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    assert state.signed == set() and state.verified == {} and state.refused == {}
