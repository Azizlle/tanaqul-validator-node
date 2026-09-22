"""Tests for src/verify.py — the node recomputes the block hash and checks the chain.

⛔ WHAT THIS EXISTS TO CHANGE. Until now the node took `block_hash` out of the payload the
platform sent and signed it:

    h = b.get("block_hash") or ""
    sig_hex = crypto.sign_block_hash(sk, h)

No recomputation, no chain check. So a validator signature attested to exactly one thing —
that a node received a string and signed it. The quorum was real, the cryptography was
real, and the thing being attested was the platform's own claim.

⚠️ THE NODE MUST HAVE ITS OWN IMPLEMENTATION, and that is the one case where a second
implementation is correct rather than a defect. Importing the platform's hashing would
verify the platform's arithmetic with the platform's code — a bug there would verify
itself. Independent verification requires an independent implementation.

⚠️ BUT INDEPENDENT IS NOT UNPINNED. These vectors are written from the SPEC — the
documented pre-image and merkle rules — not copied from either side, so they fail if either
implementation drifts.

    sha256(s)        = "0x" + sha256(utf8(s))
    merkle_root([])  = sha256("empty")          # NOT the empty string
    merkle_root(hs)  = strip "0x"; while >1: duplicate last if odd, concat HEX STRINGS
                       pairwise, sha256 each; "0x" + final
    hash_block_v2    = sha256("v2|{n}|{prev}|{match}|{event}|{tx}"
                              "|{mc}|{ec}|{txc}|{hash_timestamp}|{creator}")

⚠️ `hash_timestamp` IS THE EXACT STORED STRING, never re-serialised. The v1 defect was
hashing a transient `now.isoformat()` while the row's `created_at` took a different instant.
"""
import hashlib
import os

import pytest

os.environ.setdefault("TANAQUL_VALIDATOR_ID", "ci")
os.environ.setdefault("TANAQUL_API_KEY", "ci")
os.environ.setdefault("TANAQUL_BACKEND_URL", "https://example.test")

from src import verify  # noqa: E402


# ── the primitives, against vectors derived from the spec ────────────────────

def test_sha256_is_0x_prefixed_utf8():
    assert verify.sha256("abc") == "0x" + hashlib.sha256(b"abc").hexdigest()


def test_the_EMPTY_root_is_the_hash_of_the_word_empty():
    """⛔ NOT the hash of an empty string, and not an empty string. A block with no events
    has `event_root = sha256("empty")`; getting this wrong makes every eventless block
    mismatch and the node refuse the whole chain."""
    assert verify.merkle_root([]) == verify.sha256("empty")


def test_a_single_leaf_root_is_that_leaf():
    h = verify.sha256("leaf")
    assert verify.merkle_root([h]) == h


def test_an_ODD_level_duplicates_its_last_node():
    a, b, c = (verify.sha256(x) for x in ("a", "b", "c"))
    ab = "0x" + hashlib.sha256((a[2:] + b[2:]).encode()).hexdigest()
    cc = "0x" + hashlib.sha256((c[2:] + c[2:]).encode()).hexdigest()
    expect = "0x" + hashlib.sha256((ab[2:] + cc[2:]).encode()).hexdigest()
    assert verify.merkle_root([a, b, c]) == expect


def test_pairs_are_concatenated_as_HEX_STRINGS_not_bytes():
    """⛔ THE TRAP. `bytes.fromhex(a) + bytes.fromhex(b)` is the conventional merkle
    construction and is NOT what this chain does. Concatenating the hex TEXT gives a
    different root, and a node built the conventional way would refuse every block."""
    a, b = verify.sha256("a"), verify.sha256("b")
    text_concat = "0x" + hashlib.sha256((a[2:] + b[2:]).encode()).hexdigest()
    byte_concat = "0x" + hashlib.sha256(bytes.fromhex(a[2:]) + bytes.fromhex(b[2:])).hexdigest()
    assert verify.merkle_root([a, b]) == text_concat
    assert verify.merkle_root([a, b]) != byte_concat


def test_the_v2_preimage_is_positional_and_pipe_delimited():
    got = verify.hash_block_v2(
        number=7, prev_hash="0xprev", match_root="0xm", event_root="0xe", tx_root="0xt",
        match_count=1, event_count=2, tx_count=3,
        hash_timestamp="2026-09-23T00:00:00+00:00", creator_id="sys")
    assert got == verify.sha256(
        "v2|7|0xprev|0xm|0xe|0xt|1|2|3|2026-09-23T00:00:00+00:00|sys")


def test_the_hash_timestamp_is_used_VERBATIM():
    """⛔ THE v1 DEFECT, PINNED. Two strings that denote the same instant must produce
    different hashes — the node may not normalise, reformat or re-serialise what it was
    served, or it will disagree with a correctly sealed block."""
    common = dict(number=1, prev_hash="0x0", match_root="0xm", event_root="0xe",
                  tx_root="0xt", match_count=0, event_count=0, tx_count=0, creator_id="c")
    a = verify.hash_block_v2(hash_timestamp="2026-09-23T00:00:00+00:00", **common)
    b = verify.hash_block_v2(hash_timestamp="2026-09-23T00:00:00Z", **common)
    assert a != b


# ── leaf payloads: the node builds them, so it checks the FORMAT too ─────────

GOOD_MATCH = {"id": "M1", "buy_order_id": "B", "sell_order_id": "S", "metal": "Gold",
              "quantity_grams": "2.0", "price_per_gram": "10.00", "matched_at": "T"}
GOOD_EVENT = {"id": "E1", "event_hash": "0xeh", "grams": "1.0", "event_type": "MINT_NEW",
              "metal": "Gold", "vault_key": "VK"}
GOOD_TX = {"id": "T1", "tx_hash": "0xth", "grams": "1.0", "tx_type": "XFER",
           "metal": "Gold", "total_grams": "9.0", "from_vault_key": "A",
           "to_vault_key": "B"}

LEAVES = [("match", verify.match_leaf, GOOD_MATCH), ("event", verify.event_leaf, GOOD_EVENT),
          ("tx", verify.tx_leaf, GOOD_TX)]


def test_the_three_leaf_payloads_are_built_from_fields_not_taken_whole():
    """⛔ `/contents` SERVES FIELD DICTS, NOT BUILT STRINGS, AND THAT IS THE DESIGN. If it
    served the pre-image text, the node would be hashing the platform's rendering of the
    leaf and could not detect a leaf whose fields say something other than its string. The
    node assembles each payload itself, so a disagreement about FORMAT surfaces as a hash
    mismatch rather than passing silently.

    ⚠️ These three dicts are pinned to their exact output here, so a builder that gains or
    reorders a field fails on this line — which is what lets the test below enumerate
    `.keys()` and call it the complete field set rather than a remembered one."""
    assert verify.match_leaf(GOOD_MATCH) == "MATCH|M1|B|S|Gold|2.0|10.00|T"
    assert verify.event_leaf(GOOD_EVENT) == "E|E1|0xeh|MINT_NEW|Gold|1.0|VK"
    assert verify.tx_leaf(GOOD_TX) == "T|T1|0xth|XFER|Gold|1.0|9.0|A|B"


@pytest.mark.parametrize(
    "kind,build,good,dropped",
    [(k, b, g, f) for k, b, g in LEAVES for f in g],
)
def test_a_MISSING_leaf_field_is_refused_not_defaulted(kind, build, good, dropped):
    """⛔ A LEAF WITH A FIELD MISSING IS NOT A LEAF WITH AN EMPTY FIELD. The server already
    normalises NULLs to "" and 0 before serving, so an absent key means the payload is not
    the payload this protocol describes. Defaulting it would let the node hash something
    the seal never hashed and still call it a match.

    ⚠️ EVERY FIELD, not one. This test first dropped a single field and passed with
    `f['buy_order_id']` mutated to `.get(...)` — a later field still raised, so it proved
    only that SOME field was indexed. The field set is `good.keys()`, and the pinning
    assertion above is what keeps that set honest."""
    payload = {k: v for k, v in good.items() if k != dropped}
    with pytest.raises(KeyError):
        build(payload)


# ── the decision: verify, then sign or refuse ───────────────────────────────

def _contents(**over):
    """A block whose served hash is the one its own leaves produce."""
    d = {
        "block_number": 42, "format_version": 2, "validatable": True,
        "prev_hash": "0x" + "11" * 32, "hash_timestamp": "2026-09-23T00:00:00+00:00",
        "creator_id": "sys", "is_genesis": False,
        "counts": {"match_count": 0, "event_count": 1, "tx_count": 0},
        "match_leaves": [],
        "event_leaves": [{"id": "E1", "event_hash": "0xeh", "grams": "1.0",
                          "event_type": "MINT_NEW", "metal": "Gold", "vault_key": "VK"}],
        "tx_leaves": [],
    }
    d.update(over)
    return d


def _expected_hash(c):
    return verify.hash_block_v2(
        number=c["block_number"], prev_hash=c["prev_hash"],
        match_root=verify.merkle_root([verify.sha256(verify.match_leaf(x))
                                       for x in c["match_leaves"]]),
        event_root=verify.merkle_root([verify.sha256(verify.event_leaf(x))
                                       for x in c["event_leaves"]]),
        tx_root=verify.merkle_root([verify.sha256(verify.tx_leaf(x))
                                    for x in c["tx_leaves"]]),
        match_count=c["counts"]["match_count"], event_count=c["counts"]["event_count"],
        tx_count=c["counts"]["tx_count"],
        hash_timestamp=c["hash_timestamp"], creator_id=c["creator_id"])


def test_a_block_that_recomputes_is_APPROVED():
    c = _contents()
    v = verify.check_block(c, served_hash=_expected_hash(c), last_seen_hash=c["prev_hash"])
    assert v.ok is True and v.verdict == "OK", v


def test_a_TAMPERED_LEAF_is_caught_even_though_the_hash_is_self_consistent():
    """⛔ THE ATTACK THIS WHOLE MODULE EXISTS FOR. The platform serves a block whose hash
    matches its own served roots — but a leaf's CONTENT differs from what was sealed. The
    old node signed the served hash and could not have noticed. Recomputing from leaves
    means the node's root disagrees with the served hash."""
    c = _contents()
    honest = _expected_hash(c)
    tampered = _contents(event_leaves=[dict(c["event_leaves"][0], grams="999.0")])
    v = verify.check_block(tampered, served_hash=honest, last_seen_hash=c["prev_hash"])
    assert v.ok is False and v.verdict == "HASH_MISMATCH", v
    assert v.served_block_hash == honest
    assert v.computed_block_hash != honest


def test_a_BROKEN_CHAIN_is_refused_even_when_the_hash_recomputes():
    """⛔ TWO INDEPENDENT PROPERTIES. A block can be internally perfect and still not follow
    the block this node last saw — which is what a fork or a replayed history looks like."""
    c = _contents()
    v = verify.check_block(c, served_hash=_expected_hash(c),
                           last_seen_hash="0x" + "99" * 32)
    assert v.ok is False and v.verdict == "PREV_HASH_MISMATCH", v


def test_the_FIRST_block_a_node_sees_has_nothing_to_chain_to():
    """⛔ THE ADMIT CASE. A node with no history must not refuse everything — that is a
    refusal with no retry, which is a deletion."""
    c = _contents()
    v = verify.check_block(c, served_hash=_expected_hash(c), last_seen_hash=None)
    assert v.ok is True, v


def test_a_LEGACY_block_is_not_validatable_and_is_not_refused_either():
    """⛔ PRE-v2 BLOCKS CANNOT BE RECOMPUTED — no event_root or tx_root exists for
    them. Refusing them would strand the chain; signing them as if verified would be the
    rubber stamp this replaces. They are reported as UNVALIDATABLE so the caller decides."""
    c = _contents(format_version=1, validatable=False)
    v = verify.check_block(c, served_hash="0xwhatever", last_seen_hash=c["prev_hash"])
    assert v.ok is False and v.verdict == "UNVALIDATABLE", v


def test_COUNTS_disagreeing_with_the_LEAVES_is_its_own_verdict():
    """⛔ THE COUNTS ARE HASHED SEPARATELY FROM THE ROOTS, so a payload whose declared
    counts differ from the leaf lists it served is incoherent before any hashing. It
    would fail as a hash mismatch anyway — naming it distinctly is what makes the
    refusal report actionable instead of just negative."""
    c = _contents()
    c["counts"]["event_count"] = 7          # one leaf served, seven declared
    v = verify.check_block(c, served_hash="0xanything", last_seen_hash=c["prev_hash"])
    assert v.verdict == "COUNT_MISMATCH", v
    assert "seven" not in v.detail and "(1, 7, 0)" not in v.detail
    assert "(0, 7, 0)" in v.detail and "(0, 1, 0)" in v.detail, v.detail


def test_GENESIS_is_not_held_to_a_predecessor_it_cannot_have():
    """⛔ A refusal with no path to retry is a deletion. Genesis follows nothing, so
    chaining it against whatever this node last saw would refuse the one block that is
    correct by definition."""
    c = _contents(is_genesis=True)
    v = verify.check_block(c, served_hash=_expected_hash(c),
                           last_seen_hash="0x" + "99" * 32)
    assert v.ok is True, v


def test_UNVALIDATABLE_does_NOT_earn_a_signed_REFUSAL():
    """⛔ THE THIRD STATE, AND THE ONE THAT GETS COLLAPSED BY ACCIDENT. `ok is False`
    reads as "refuse" to any caller that checks one boolean — and refusing a legacy
    block accuses the platform of tampering on the strength of a format the node cannot
    read. Every legacy block on the chain would be reported as an attack."""
    c = _contents(format_version=1, validatable=False)
    v = verify.check_block(c, served_hash="0xwhatever", last_seen_hash=c["prev_hash"])
    assert v.ok is False
    assert verify.should_refuse(v) is False, "a block the node could not check is not a refusal"

    for bad in ("HASH_MISMATCH", "PREV_HASH_MISMATCH", "COUNT_MISMATCH"):
        assert verify.should_refuse(
            verify.Verdict(ok=False, verdict=bad, block_number=1)) is True, bad
    assert verify.should_refuse(
        verify.Verdict(ok=True, verdict="OK", block_number=1)) is False


# ── the signed pre-images ───────────────────────────────────────────────────

def test_the_VALIDATION_pre_image_strips_0x_from_the_BLOCK_HASH_and_nothing_else():
    """⛔ THE ASYMMETRY THAT WOULD BREAK EVERY SIGNATURE SILENTLY. The platform builds the
    `tv2` message with `block.hash[2:]` — the block hash WITHOUT its `0x` — while
    `prev_hash` and all three roots go in exactly as stored, `0x` intact. A node that
    treats all five the same way produces a signature over different bytes, gets one
    deliberately uninformative 401, and reports itself healthy while signing nothing.

    There is no way to discover this from the shape of the data: all five are 0x-prefixed
    hex and only one is stripped."""
    msg = verify.validation_payload(
        number=42, block_hash="0xaa", prev_hash="0xbb", match_root="0xcc",
        event_root="0xdd", tx_root="0xee", match_count=1, event_count=2, tx_count=3,
        hash_timestamp="TS", creator_id="sys")
    assert msg == "tv2|42|aa|0xbb|0xcc|0xdd|0xee|1|2|3|TS|sys"

    #: and a hash arriving WITHOUT the prefix is left alone, not truncated by two
    assert verify.validation_payload(
        number=42, block_hash="aa", prev_hash="0xbb", match_root="0xcc",
        event_root="0xdd", tx_root="0xee", match_count=1, event_count=2, tx_count=3,
        hash_timestamp="TS", creator_id="sys") == "tv2|42|aa|0xbb|0xcc|0xdd|0xee|1|2|3|TS|sys"


def test_the_THREE_PREFIXES_never_collide():
    """⛔ `v2|` is the block hash, `tv2|` a validation, `tr2|` a refusal. A digest produced
    under one must never be replayable as another — which is the whole reason the node does
    not sign the block-hash pre-image it just computed."""
    starts = [
        verify.hash_block_v2(1, "p", "m", "e", "t", 0, 1, 0, "TS", "sys"),
        verify.validation_payload(number=1, block_hash="h", prev_hash="p", match_root="m",
                                  event_root="e", tx_root="t", match_count=0,
                                  event_count=1, tx_count=0, hash_timestamp="TS",
                                  creator_id="sys"),
        verify.refusal_payload(number=1, validator_id="V", verdict="HASH_MISMATCH",
                               observed_block_hash="o", expected_block_hash="e",
                               observed_prev_hash="", expected_prev_hash="",
                               match_root="m", event_root="e", tx_root="t",
                               match_count=0, event_count=1, tx_count=0,
                               hash_timestamp="TS", creator_id="sys", reported_at="R"),
    ]
    assert starts[1].startswith("tv2|") and starts[2].startswith("tr2|")
    assert len({starts[1], starts[2]}) == 2


def test_the_REFUSAL_pre_image_COMMITS_THE_SIGNER():
    """⛔ `validator_id` sits immediately after the prefix. Without it, identity rested
    entirely on which row's `public_key_hex` the verification happened to run against — so
    the same signed bytes verified as a refusal by ANY validator sharing that key, and one
    stolen api_key manufactures consensus-dissent on the objection channel."""
    a = verify.refusal_payload(
        number=7, validator_id="VAL-A", verdict="HASH_MISMATCH", observed_block_hash="o",
        expected_block_hash="e", observed_prev_hash="op", expected_prev_hash="ep",
        match_root="m", event_root="ev", tx_root="t", match_count=1, event_count=2,
        tx_count=3, hash_timestamp="TS", creator_id="sys", reported_at="R")
    assert a == ("tr2|VAL-A|7|HASH_MISMATCH|o|e|op|ep|m|ev|t|1|2|3|TS|sys|R")
    b = verify.refusal_payload(
        number=7, validator_id="VAL-B", verdict="HASH_MISMATCH", observed_block_hash="o",
        expected_block_hash="e", observed_prev_hash="op", expected_prev_hash="ep",
        match_root="m", event_root="ev", tx_root="t", match_count=1, event_count=2,
        tx_count=3, hash_timestamp="TS", creator_id="sys", reported_at="R")
    assert a != b, "two validators must not produce identical refusal bytes"


# ── what the node DOES with a verdict ───────────────────────────────────────

def test_every_REFUSABLE_verdict_maps_to_a_name_the_platform_ACCEPTS():
    """⛔ THE PLATFORM REJECTS AN UNREVIEWED VERDICT STRING WITH A 400. The node's own
    verdict names are not the wire names: `COUNT_MISMATCH` and a malformed payload are both
    `CONTENTS_MALFORMED` on the wire, and `UNVALIDATABLE` is `FORMAT_NOT_VALIDATABLE`. A
    node that reports its internal name loses the refusal entirely — on the channel built
    because a refusal had nowhere to go."""
    assert verify.WIRE_VERDICTS == {
        "HASH_MISMATCH": "HASH_MISMATCH",
        "PREV_HASH_MISMATCH": "PREV_HASH_MISMATCH",
        "COUNT_MISMATCH": "CONTENTS_MALFORMED",
        "CONTENTS_MALFORMED": "CONTENTS_MALFORMED",
        "UNVALIDATABLE": "FORMAT_NOT_VALIDATABLE",
    }
    for v in verify.WIRE_VERDICTS.values():
        assert v in verify.PLATFORM_REFUSAL_VERDICTS, v
    #: every refusable verdict the checker can actually emit has a wire name
    for v in ("HASH_MISMATCH", "PREV_HASH_MISMATCH", "COUNT_MISMATCH", "CONTENTS_MALFORMED"):
        assert verify.should_refuse(verify.Verdict(ok=False, verdict=v, block_number=1))
        assert v in verify.WIRE_VERDICTS


def test_a_LEGACY_block_falls_back_to_v1_ATTESTATION_rather_than_being_dropped():
    """⛔ A REFUSAL WITH NO RETRY IS A DELETION. `/pending-blocks` deliberately keeps
    offering legacy blocks that have not met quorum — "they stay offered and remain
    rescuable" — so a v2 node that silently skipped them would make them unrescuable by the
    whole fleet, which is a worse outcome than the rubber stamp it replaced.

    ⚠️ AND IT IS NOT SIGNED AS VALIDATED. The v1 path signs the block hash and the platform
    records it as an attestation of receipt, which is exactly what it is. The two are
    distinguished cryptographically by which pre-image verifies, not by anything the node
    claims about itself — so this fallback cannot inflate a validated quorum."""
    c = _contents(format_version=1, validatable=False)
    v = verify.check_block(c, served_hash="0xlegacy", last_seen_hash=c["prev_hash"])
    assert v.verdict == "UNVALIDATABLE"
    assert verify.should_refuse(v) is False
    assert verify.should_attest_v1(v) is True

    #: and NOTHING else falls back — a block the node checked and disagreed with must
    #: never be rescued by attesting to it instead
    for bad in ("HASH_MISMATCH", "PREV_HASH_MISMATCH", "COUNT_MISMATCH", "CONTENTS_MALFORMED"):
        assert verify.should_attest_v1(
            verify.Verdict(ok=False, verdict=bad, block_number=1)) is False, bad
    assert verify.should_attest_v1(
        verify.Verdict(ok=True, verdict="OK", block_number=1)) is False


def test_a_MALFORMED_payload_becomes_a_VERDICT_and_never_an_exception():
    """⛔ `check_block` IS TOTAL: every payload the platform can serve produces a verdict.
    An exception escaping here would propagate into the poll loop and — depending on where
    it is caught — either kill the node or be swallowed into a broad handler and logged as
    a fetch failure, which is the shape that turns a tampering signal into a quiet retry.
    A payload the node cannot parse is a disagreement it CAN state."""
    c = _contents()
    del c["event_leaves"][0]["vault_key"]
    v = verify.check_block(c, served_hash="0xzz", last_seen_hash=c["prev_hash"])
    assert v.verdict == "CONTENTS_MALFORMED", v
    assert "vault_key" in v.detail, v.detail

    for missing in ("counts", "prev_hash", "hash_timestamp", "creator_id", "match_leaves"):
        broken = _contents()
        del broken[missing]
        got = verify.check_block(broken, served_hash="0xzz", last_seen_hash=None)
        assert got.verdict == "CONTENTS_MALFORMED", (missing, got)


def test_the_verdict_carries_THE_ROOTS_because_a_refusal_report_must_state_them():
    """⛔ A REFUSAL THAT SAYS ONLY "NO" IS NOT EVIDENCE. The `tr2` pre-image commits all
    three roots the node computed, so the report states WHERE the two sides diverge rather
    than merely that they do. A verdict that dropped them would force the loop to recompute
    them — a second implementation, in the one place a second implementation is definitely
    a defect."""
    c = _contents()
    v = verify.check_block(c, served_hash=_expected_hash(c), last_seen_hash=None)
    assert v.match_root == verify.merkle_root([]), v
    assert v.event_root == verify.merkle_root(
        [verify.sha256(verify.event_leaf(c["event_leaves"][0]))])
    assert v.tx_root == verify.merkle_root([])
    assert (v.match_count, v.event_count, v.tx_count) == (0, 1, 0)

    #: and a HASH_MISMATCH carries them too — that is the verdict that gets reported
    bad = verify.check_block(c, served_hash="0x" + "00" * 32, last_seen_hash=None)
    assert bad.verdict == "HASH_MISMATCH"
    assert bad.event_root == v.event_root and bad.match_root == v.match_root


@pytest.mark.parametrize("mangle,exc", [
    (lambda c: c.__setitem__("counts", None), "TypeError"),
    (lambda c: c["counts"].__setitem__("event_count", "seven"), "ValueError"),
    (lambda c: c.__setitem__("block_number", "forty-two"), "ValueError"),
    (lambda c: c.__setitem__("event_leaves", None), "TypeError"),
    (lambda c: c.__setitem__("event_leaves", ["not-a-dict"]), "TypeError"),
    (lambda c: c["event_leaves"][0].pop("grams"), "KeyError"),
])
def test_EVERY_malformed_SHAPE_becomes_a_verdict_not_just_a_missing_key(mangle, exc):
    """⚠️ THE CATCH LIST IS THREE TYPES AND THE TESTS ONLY PRODUCED ONE. Narrowing it to
    `KeyError` alone left the suite green: a count served as text, or a null where a list
    belongs, would still have escaped into the poll loop. A missing field is the malformed
    shape that is easiest to imagine, which is exactly why it was the only one written."""
    c = _contents()
    mangle(c)
    v = verify.check_block(c, served_hash="0xzz", last_seen_hash=None)
    assert v.verdict == "CONTENTS_MALFORMED", (exc, v)
    assert exc in v.detail, v.detail


def test_a_BUG_IN_THE_NODE_is_not_reported_as_the_platform_sending_bad_data():
    """⛔ THE OTHER HALF OF THE SAME GUARD. Catching `Exception` here would absorb a genuine
    defect in the node's own arithmetic and file it as `CONTENTS_MALFORMED` — an accusation
    against the platform, signed by this node, for a fault that is ours. A refusal channel
    that can manufacture evidence out of its own bugs is worse than no channel."""
    c = _contents()
    boom = RuntimeError("a defect in the node's own merkle code")

    def _explode(_hashes):
        raise boom

    real = verify.merkle_root
    verify.merkle_root = _explode
    try:
        with pytest.raises(RuntimeError) as caught:
            verify.check_block(c, served_hash="0xzz", last_seen_hash=None)
        assert caught.value is boom
    finally:
        verify.merkle_root = real

    #: and the control — with the real function back, the same payload verifies
    assert verify.check_block(c, served_hash=_expected_hash(c),
                              last_seen_hash=None).ok is True
