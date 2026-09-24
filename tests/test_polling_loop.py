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
            is_genesis=False, tamper=None, serve_hash=None, creator="sys",
            merkle_root=None):
        c = {
            "block_number": n, "format_version": format_version,
            "validatable": validatable, "prev_hash": prev_hash,
            "hash_timestamp": f"2026-09-23T00:00:{n:02d}+00:00",
            "creator_id": creator, "is_genesis": is_genesis,
            "counts": {"match_count": 0, "event_count": events, "tx_count": 0},
            "match_leaves": [],
            "event_leaves": [
                {"id": f"E{n}-{i}", "event_hash": f"0xeh{n}{i}", "grams": "1.0",
                 "event_type": "MINT_NEW", "metal": "Gold", "vault_key": "VK"}
                for i in range(events)
            ],
            "tx_leaves": [],
        }
        mr = merkle_root if merkle_root is not None else verify.merkle_root(
            [verify.sha256(verify.match_leaf(x)) for x in c["match_leaves"]])
        honest = _hash_of(c, match_root=mr)
        if tamper:
            tamper(c)
        self.blocks[n] = (c, serve_hash or honest, mr)
        return honest

    # ── the client surface the loop uses ──
    def get_pending_blocks(self):
        return [{"block_number": n, "block_hash": h, "merkle_root": mr}
                for n, (_c, h, mr) in sorted(self.blocks.items())]

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


def _hash_of(c, match_root=None):
    return verify.hash_block_v2(
        number=c["block_number"], prev_hash=c["prev_hash"],
        match_root=(match_root if match_root is not None else verify.merkle_root(
            [verify.sha256(verify.match_leaf(x)) for x in c["match_leaves"]])),
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
    be.blocks[1] = (be.blocks[1][0], honest, be.blocks[1][2])   # serve the honest hash with tampered leaves
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
    be.blocks[1] = (be.blocks[1][0], honest, be.blocks[1][2])
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
    be.blocks[1] = (be.blocks[1][0], honest, be.blocks[1][2])
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
    be.blocks[1] = (be.blocks[1][0], honest, be.blocks[1][2])

    def _boom(**kw):
        raise validator_node.client.BackendError("HTTP 503")

    validator_node.client.report_refusal = _boom
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    assert 1 not in state.refused

    validator_node.client.report_refusal = be.report_refusal
    validator_node._do_polling(sk, state)
    assert len(be.refusals) == 1
    assert state.refused[1][0] == "HASH_MISMATCH", state.refused[1]


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
    be.blocks[1] = (be.blocks[1][0], honest, be.blocks[1][2])
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


# ── the loop passes the artifact the genesis check is derived from ─────────

def test_the_loop_passes_the_SERVED_merkle_root_through_to_the_check(be, sk, monkeypatch):
    """⛔ `/pending-blocks` ALREADY SERVES `merkle_root`, and it is `match_root` under its
    older name. The genesis marker is derived from it, so a loop that dropped it would
    reinstate the false accusation with the checker still correct."""
    be.add(1, prev_hash=GENESIS)
    seen = {}
    real = validator_node.verify.check_block

    def spy(contents, served_hash, last_seen_hash, served_merkle_root):
        seen["mr"] = served_merkle_root
        return real(contents, served_hash, last_seen_hash, served_merkle_root)

    monkeypatch.setattr(validator_node.verify, "check_block", spy)
    validator_node._do_polling(sk, validator_node.PollState())
    assert seen["mr"] == be.blocks[1][2], "the served merkle_root never reached the checker"


def test_a_GENESIS_block_is_ATTESTED_not_refused(be, sk):
    """⛔ THE FALSE ACCUSATION, END TO END. Before this, the node refused the live genesis
    block and POSTed a tr2-signed HASH_MISMATCH — every node, every poll, forever."""
    be.add(1, prev_hash="0x" + "00" * 64, events=0, creator="genesis",
           merkle_root=verify.sha256("genesis"))
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)

    assert be.refusals == [], f"the node accused the platform over genesis: {be.refusals}"
    assert [s["n"] for s in be.signed] == [1], "genesis was not signed at all"
    assert 1 not in state.verified, "a contentless block must not seed the chain"


# ── identity ───────────────────────────────────────────────────────────────

def test_the_VALIDATOR_ID_is_CANONICALISED_before_it_is_signed(be, sk, monkeypatch):
    """⛔ 100% OF REFUSALS LOST, SILENTLY, ON A COSMETIC ENV VALUE. The node signed the id
    verbatim; the endpoint rebuilds the `tr2` string with `str(body.validator_id)` through
    a `uuid.UUID` field, which canonicalises. An uppercase or hyphen-free id — both of
    which Pydantic accepts — produced 401 on every refusal while heartbeat,
    /pending-blocks, /contents and /sign-block all kept working, because `tv2` does not
    contain the id. Green node, green health, every objection deleted."""
    canonical = "f11089a3-ddb0-4a1a-9f6e-1b2c3d4e5f60"
    for raw in (canonical, canonical.upper(), canonical.replace("-", "")):
        monkeypatch.setattr(validator_node.config, "TANAQUL_VALIDATOR_ID", raw)
        assert validator_node._signing_identity() == canonical, raw


def test_a_NON_UUID_validator_id_is_passed_through_rather_than_guessed(monkeypatch):
    """⚠️ Test and staging deployments use non-UUID ids. Canonicalising must not invent one
    — an unparseable id is sent as-is, and the platform is the one that decides."""
    monkeypatch.setattr(validator_node.config, "TANAQUL_VALIDATOR_ID", "ci")
    assert validator_node._signing_identity() == "ci"


# ── the refusal record keys on the evidence, not just the verdict ──────────

def test_a_MATERIALLY_DIFFERENT_refusal_on_the_same_block_is_still_FILED(be, sk):
    """⛔ THE RECORD EXISTS TO STATE *WHICH* HASHES DISAGREED. Keying suppression on
    (block, verdict) alone meant a second, different tampering of the same block was
    dropped silently: the stored evidence is the first observation only, and no second page
    fires. The rate bound is right; the uniqueness key was wrong for evidence."""
    honest = be.add(1, prev_hash=GENESIS, events=2,
                    tamper=lambda c: c["event_leaves"][0].__setitem__("grams", "999.0"))
    be.blocks[1] = (be.blocks[1][0], honest, be.blocks[1][2])
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    assert len(be.refusals) == 1

    #: same verdict, a DIFFERENT observation
    be.blocks[1][0]["event_leaves"][1]["metal"] = "Silver"
    validator_node._do_polling(sk, state)
    assert len(be.refusals) == 2, "a different disagreement on the same block was swallowed"
    assert be.refusals[0]["expected_block_hash"] != be.refusals[1]["expected_block_hash"]

    #: and the UNCHANGED one still files once
    validator_node._do_polling(sk, state)
    assert len(be.refusals) == 2, "a standing disagreement re-filed"


# ── the guards the chain check DEPENDS on, and the counters that report it ──

def _counter(name):
    from prometheus_client import REGISTRY
    v = REGISTRY.get_sample_value(name)
    return 0.0 if v is None else v


def test_blocks_are_judged_in_ASCENDING_ORDER(be, sk):
    """⛔ THE GUARD THE CHAIN CHECK RESTS ON, AND NOTHING NOTICED ITS REMOVAL. `verified[n-1]`
    is only populated if n-1 was judged first, so served order silently turns every
    continuity check into "no verified predecessor, admit" — the check stays present, reads
    correct, and stops being able to fail. Three seats independently deleted `sorted()` with
    the suite green."""
    h1 = be.add(1, prev_hash=GENESIS)
    be.add(2, prev_hash=h1)
    be.add(3, prev_hash="0x" + "99" * 32)          # does NOT follow #2

    #: the platform serves them newest-first — the node must not take that order
    order = []
    real = be.get_pending_blocks
    validator_node.client.get_pending_blocks = lambda: list(reversed(real()))
    real_check = validator_node.verify.check_block

    def spy(contents, served_hash, last_seen_hash, served_merkle_root):
        order.append(int(contents["block_number"]))
        return real_check(contents, served_hash, last_seen_hash, served_merkle_root)

    validator_node.verify.check_block = spy
    try:
        validator_node._do_polling(sk, validator_node.PollState())
    finally:
        validator_node.verify.check_block = real_check

    assert order == [1, 2, 3], f"blocks were judged out of order: {order}"
    assert [r["verdict"] for r in be.refusals] == ["PREV_HASH_MISMATCH"], (
        "the broken chain at #3 was not detected, because its predecessor was unverified")


def test_a_REPAIRED_block_CLEARS_its_refusal_record(be, sk):
    """⛔ WITHOUT THE RESET, A BLOCK THAT IS FIXED AND THEN BREAKS AGAIN IS NEVER RE-FILED —
    the suppression that stops a flood becomes the thing that hides the second incident."""
    honest = be.add(1, prev_hash=GENESIS,
                    tamper=lambda c: c["event_leaves"][0].__setitem__("grams", "999.0"))
    be.blocks[1] = (be.blocks[1][0], honest, be.blocks[1][2])
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    assert 1 in state.refused and len(be.refusals) == 1

    be.blocks[1][0]["event_leaves"][0]["grams"] = "1.0"      # repaired
    validator_node._do_polling(sk, state)
    assert 1 not in state.refused, "a signed block kept its refusal record"
    assert [s["n"] for s in be.signed] == [1]


def test_each_OUTCOME_increments_ITS_OWN_counter(be, sk):
    """⛔ THE COUNTERS EXIST SO AN OPERATOR DOES NOT READ ATTESTATION AS VALIDATION — and
    every one of them could be deleted, or wired to the wrong metric, with the suite green.
    Six mutations, six survivors. This is the instrument the cutover decision is made on."""
    before = {n: _counter(n) for n in (
        "validator_blocks_validated_total", "validator_blocks_attested_v1_total",
        "validator_blocks_refused_total", "validator_contents_fail_total",
        "validator_blocks_signed_total")}

    h1 = be.add(1, prev_hash=GENESIS)                                   # validated
    be.add(2, prev_hash=h1, format_version=1, validatable=False, serve_hash="0xold")  # attested
    honest3 = be.add(3, prev_hash=h1, events=2,
                     tamper=lambda c: c["event_leaves"][0].__setitem__("grams", "9.0"))
    be.blocks[3] = (be.blocks[3][0], honest3, be.blocks[3][2])          # refused
    validator_node._do_polling(sk, validator_node.PollState())

    d = {n: _counter(n) - before[n] for n in before}
    assert d["validator_blocks_validated_total"] == 1, d
    assert d["validator_blocks_attested_v1_total"] == 1, d
    assert d["validator_blocks_refused_total"] == 1, d
    assert d["validator_blocks_signed_total"] == 2, (
        "blocks_signed must count BOTH signing paths and only those", d)
    assert d["validator_contents_fail_total"] == 0, d


def test_a_CONTENTS_FAILURE_increments_its_own_counter_and_signs_nothing(be, sk):
    before = _counter("validator_contents_fail_total")
    be.add(1, prev_hash=GENESIS)
    be.contents_error = "contents HTTP 503"
    validator_node._do_polling(sk, validator_node.PollState())
    assert _counter("validator_contents_fail_total") - before == 1
    assert be.signed == [] and be.refusals == []


# ── round two: the node must not believe it filed what the platform discarded ──

def test_a_DISCARDED_refusal_is_stated_ONCE_and_not_retried_for_ever(be, sk):
    """⛔ THE PLATFORM KEEPS THE FIRST PAGE, BY RULING. Its unique index is
    `(block_number, validator_id, verdict)` with `ON CONFLICT DO NOTHING`, so a second,
    materially different observation of the same block comes back `recorded: False` with
    HTTP 200 and is stored nowhere. That bound is deliberate — a validator filing two
    different accusations against one block is broken or attacking, and unbounded rows on
    a money-path table is the worse failure.

    ⚠️ SO THE NODE'S JOB IS TO SAY SO ONCE, NOT TO ARGUE. Recording it as filed would be
    *intent reported as act*; re-sending it every poll would be a load amplifier against a
    filing that cannot ever be stored — 5,760 doomed POSTs a day per block per node. It
    logs CRITICAL, counts it, and suppresses that observation.

    ⚠️ AND THE BOUND IS PER OBSERVATION, not per block: a genuinely new third observation
    is attempted once more, and says so once more."""
    honest = be.add(1, prev_hash=GENESIS, events=3,
                    tamper=lambda c: c["event_leaves"][0].__setitem__("grams", "999.0"))
    be.blocks[1] = (be.blocks[1][0], honest, be.blocks[1][2])

    seen = {"n": 0}

    def discarding(**kw):
        seen["n"] += 1
        be.refusals.append(kw)
        return {"recorded": seen["n"] == 1, "duplicate": seen["n"] > 1}

    validator_node.client.report_refusal = discarding
    state = validator_node.PollState()
    validator_node._do_polling(sk, state)
    assert seen["n"] == 1, "the first observation was not filed"

    #: a DIFFERENT observation, same verdict -> attempted once, discarded, stated once
    be.blocks[1][0]["event_leaves"][1]["metal"] = "METAL_B"
    before = _counter("validator_refusal_fail_total")
    validator_node._do_polling(sk, state)
    assert seen["n"] == 2
    assert _counter("validator_refusal_fail_total") - before == 1, (
        "a discarded filing was not counted, so it is visible nowhere")

    #: ⛔ and NOT again, for ever
    for _ in range(5):
        validator_node._do_polling(sk, state)
    assert seen["n"] == 2, (
        f"the node re-sent a filing the platform can never store ({seen['n']} attempts); "
        f"at POLL_INTERVAL=15 that is thousands of doomed POSTs a day per block")

    #: a THIRD, genuinely different observation is still attempted once
    be.blocks[1][0]["event_leaves"][2]["metal"] = "METAL_C"
    validator_node._do_polling(sk, state)
    assert seen["n"] == 3, "a new observation was swallowed by the suppression"


def test_a_refusal_the_platform_ACCEPTS_is_recorded_and_suppressed(be, sk):
    """⭐ THE CONTROL. Without it the assertion above is satisfied by a node that never
    records anything, which would re-file every poll forever."""
    honest = be.add(1, prev_hash=GENESIS,
                    tamper=lambda c: c["event_leaves"][0].__setitem__("grams", "999.0"))
    be.blocks[1] = (be.blocks[1][0], honest, be.blocks[1][2])
    state = validator_node.PollState()
    for _ in range(4):
        validator_node._do_polling(sk, state)
    assert len(be.refusals) == 1 and 1 in state.refused
