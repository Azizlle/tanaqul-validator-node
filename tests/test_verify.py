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
    """A block whose served hash is the one its own leaves produce.

    ⚠️ ABOVE THE LEGACY CEILING, DELIBERATELY. These fixtures used block #42, which is
    BELOW it — so once the gate stopped reading `format_version` and started deciding
    legacy-versus-tampered from the block NUMBER, every one of them silently moved onto the
    attest path. They had never exercised the branch that actually verifies.
    """
    d = {
        "block_number": 500, "format_version": 2, "validatable": True,
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


def _mr(c):
    """The `merkle_root` /pending-blocks would serve for this block: the match root."""
    return verify.merkle_root([verify.sha256(verify.match_leaf(x))
                               for x in c["match_leaves"]])


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
    v = verify.check_block(c, served_hash=_expected_hash(c), last_seen_hash=c["prev_hash"], served_merkle_root=_mr(c))
    assert v.ok is True and v.verdict == "OK", v


def test_a_TAMPERED_LEAF_is_caught_even_though_the_hash_is_self_consistent():
    """⛔ THE ATTACK THIS WHOLE MODULE EXISTS FOR. The platform serves a block whose hash
    matches its own served roots — but a leaf's CONTENT differs from what was sealed. The
    old node signed the served hash and could not have noticed. Recomputing from leaves
    means the node's root disagrees with the served hash."""
    c = _contents()
    honest = _expected_hash(c)
    tampered = _contents(event_leaves=[dict(c["event_leaves"][0], grams="999.0")])
    v = verify.check_block(tampered, served_hash=honest, last_seen_hash=c["prev_hash"], served_merkle_root=_mr(c))
    assert v.ok is False and v.verdict == "HASH_MISMATCH", v
    assert v.served_block_hash == honest
    assert v.computed_block_hash != honest


def test_a_BROKEN_CHAIN_is_refused_even_when_the_hash_recomputes():
    """⛔ TWO INDEPENDENT PROPERTIES. A block can be internally perfect and still not follow
    the block this node last saw — which is what a fork or a replayed history looks like."""
    c = _contents()
    v = verify.check_block(c, served_hash=_expected_hash(c),
                           last_seen_hash="0x" + "99" * 32, served_merkle_root=_mr(c))
    assert v.ok is False and v.verdict == "PREV_HASH_MISMATCH", v


def test_the_FIRST_block_a_node_sees_has_nothing_to_chain_to():
    """⛔ THE ADMIT CASE. A node with no history must not refuse everything — that is a
    refusal with no retry, which is a deletion."""
    c = _contents()
    v = verify.check_block(c, served_hash=_expected_hash(c), last_seen_hash=None, served_merkle_root=_mr(c))
    assert v.ok is True, v


def test_a_LEGACY_block_is_not_validatable_and_is_not_refused_either():
    """⛔ PRE-v2 BLOCKS CANNOT BE RECOMPUTED — no event_root or tx_root exists for
    them. Refusing them would strand the chain; signing them as if verified would be the
    rubber stamp this replaces. They are reported as UNVALIDATABLE so the caller decides."""
    c = _contents(block_number=10, format_version=1, validatable=False,
                  counts={"match_count": 0, "event_count": 0, "tx_count": 0},
                  event_leaves=[])
    v = verify.check_block(c, served_hash="0xwhatever", last_seen_hash=c["prev_hash"], served_merkle_root=_mr(c))
    assert v.ok is False and v.verdict == "UNVALIDATABLE", v


def test_COUNTS_disagreeing_with_the_LEAVES_is_its_own_verdict():
    """⛔ THE COUNTS ARE HASHED SEPARATELY FROM THE ROOTS, so a payload whose declared
    counts differ from the leaf lists it served is incoherent before any hashing. It
    would fail as a hash mismatch anyway — naming it distinctly is what makes the
    refusal report actionable instead of just negative."""
    c = _contents()
    c["counts"]["event_count"] = 7          # one leaf served, seven declared
    v = verify.check_block(c, served_hash="0xanything", last_seen_hash=c["prev_hash"], served_merkle_root=_mr(c))
    assert v.verdict == "COUNT_MISMATCH", v
    assert "seven" not in v.detail and "(1, 7, 0)" not in v.detail
    assert "(0, 7, 0)" in v.detail and "(0, 1, 0)" in v.detail, v.detail


#: ⛔ DELETED 2026-09-23, DELIBERATELY: `test_GENESIS_is_not_held_to_a_predecessor_it_
#: cannot_have` ENCODED THE DEFECT. It set `is_genesis: True` in the served payload, passed
#: a `last_seen_hash`, and asserted `ok is True` — so it pinned green the exact bypass an
#: adversarial review later executed: a FORKED block flagged genesis, signed under tv2,
#: with no refusal filed.
#: Repairing the code turned it red, and the reflex there is to trust the test.
#:
#: It is NOT replaced by a rename. The property it should have asserted is split across two
#: tests that assert DIFFERENT things on purpose:
#:   * `test_GENESIS_is_recognised_from_the_MARKER_not_from_a_FLAG_the_platform_SETS`
#:   * `test_the_platform_cannot_DECLARE_a_block_genesis_to_escape_the_chain_check`
#: and the no-history admit it partly stood for is
#: `test_the_FIRST_block_a_node_sees_has_nothing_to_chain_to`.


def test_UNVALIDATABLE_does_NOT_earn_a_signed_REFUSAL():
    """⛔ THE THIRD STATE, AND THE ONE THAT GETS COLLAPSED BY ACCIDENT. `ok is False`
    reads as "refuse" to any caller that checks one boolean — and refusing a legacy
    block accuses the platform of tampering on the strength of a format the node cannot
    read. Every legacy block on the chain would be reported as an attack."""
    c = _contents(block_number=10, format_version=1, validatable=False,
                  counts={"match_count": 0, "event_count": 0, "tx_count": 0},
                  event_leaves=[])
    v = verify.check_block(c, served_hash="0xwhatever", last_seen_hash=c["prev_hash"], served_merkle_root=_mr(c))
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
        "MATCH_ROOT_MISMATCH": "HASH_MISMATCH",
        "UNVALIDATABLE": "FORMAT_NOT_VALIDATABLE",
        "FORMAT_REFUSED": "FORMAT_NOT_VALIDATABLE",
    }
    for v in verify.WIRE_VERDICTS.values():
        assert v in verify.PLATFORM_REFUSAL_VERDICTS, v
    #: every refusable verdict the checker can actually emit has a wire name
    for v in ("HASH_MISMATCH", "PREV_HASH_MISMATCH", "COUNT_MISMATCH", "CONTENTS_MALFORMED",
              "MATCH_ROOT_MISMATCH", "FORMAT_REFUSED"):
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
    c = _contents(block_number=150, format_version=1, validatable=False)
    v = verify.check_block(c, served_hash="0xlegacy", last_seen_hash=c["prev_hash"],
                           served_merkle_root=_mr(c))
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
    v = verify.check_block(c, served_hash="0xzz", last_seen_hash=c["prev_hash"], served_merkle_root=_mr(c))
    assert v.verdict == "CONTENTS_MALFORMED", v
    assert "vault_key" in v.detail, v.detail

    for missing in ("counts", "prev_hash", "hash_timestamp", "creator_id", "match_leaves"):
        broken = _contents()
        del broken[missing]
        got = verify.check_block(broken, served_hash="0xzz", last_seen_hash=None, served_merkle_root=_mr(c))
        assert got.verdict == "CONTENTS_MALFORMED", (missing, got)


def test_the_verdict_carries_THE_ROOTS_because_a_refusal_report_must_state_them():
    """⛔ A REFUSAL THAT SAYS ONLY "NO" IS NOT EVIDENCE. The `tr2` pre-image commits all
    three roots the node computed, so the report states WHERE the two sides diverge rather
    than merely that they do. A verdict that dropped them would force the loop to recompute
    them — a second implementation, in the one place a second implementation is definitely
    a defect."""
    c = _contents()
    v = verify.check_block(c, served_hash=_expected_hash(c), last_seen_hash=None, served_merkle_root=_mr(c))
    assert v.match_root == verify.merkle_root([]), v
    assert v.event_root == verify.merkle_root(
        [verify.sha256(verify.event_leaf(c["event_leaves"][0]))])
    assert v.tx_root == verify.merkle_root([])
    assert (v.match_count, v.event_count, v.tx_count) == (0, 1, 0)

    #: and a HASH_MISMATCH carries them too — that is the verdict that gets reported
    bad = verify.check_block(c, served_hash="0x" + "00" * 32, last_seen_hash=None, served_merkle_root=_mr(c))
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
    v = verify.check_block(c, served_hash="0xzz", last_seen_hash=None, served_merkle_root=_mr(c))
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
            verify.check_block(c, served_hash="0xzz", last_seen_hash=None, served_merkle_root=_mr(c))
        assert caught.value is boom
    finally:
        verify.merkle_root = real

    #: and the control — with the real function back, the same payload verifies
    assert verify.check_block(c, served_hash=_expected_hash(c),
                              last_seen_hash=None, served_merkle_root=_mr(c)).ok is True


# ── genesis, derived from an artifact rather than asserted by the platform ──

GENESIS_ROOT = verify.sha256("genesis")


def _genesis(**over):
    d = dict(_contents(), block_number=1, prev_hash="0x" + "00" * 64,
             creator_id="genesis", counts={"match_count": 0, "event_count": 0,
                                           "tx_count": 0}, event_leaves=[])
    d.update(over)
    return d


def test_GENESIS_is_recognised_from_the_MARKER_not_from_a_FLAG_the_platform_SETS():
    """⛔ THE FALSE ACCUSATION THIS ROUND EXISTS TO PREVENT. The platform substitutes
    `sha256("genesis")` for a genesis block's match_root; the node computed
    `merkle_root([])` = `sha256("empty")` and therefore disagreed with a block that is
    correct by construction — refusing it, and filing a `tr2`-SIGNED accusation that the
    platform sealed something it cannot reproduce. Every node, every poll, forever.

    ⛔ AND THE MARKER IS CHECKED, NOT TAKEN. `is_genesis` in the served contents is an
    unsigned field chosen by the party being verified — committed by no pre-image — so
    trusting it let the platform disable the chain check on any block it liked. The node
    now derives it: `merkle_root` from /pending-blocks must equal a CONSTANT this node
    holds. The platform cannot assert genesis, only exhibit it."""
    assert GENESIS_ROOT != verify.merkle_root([]), "the two roots must actually differ"

    c = _genesis()
    honest = verify.hash_block_v2(
        number=1, prev_hash=c["prev_hash"], match_root=GENESIS_ROOT,
        event_root=verify.merkle_root([]), tx_root=verify.merkle_root([]),
        match_count=0, event_count=0, tx_count=0,
        hash_timestamp=c["hash_timestamp"], creator_id="genesis")

    v = verify.check_block(c, served_hash=honest, last_seen_hash=None,
                           served_merkle_root=GENESIS_ROOT)
    assert v.verdict != "HASH_MISMATCH", f"the node refused a correct genesis block: {v}"
    assert verify.should_refuse(v) is False, "a correct genesis must never be accused"


def test_the_platform_cannot_DECLARE_a_block_genesis_to_escape_the_chain_check():
    """⛔ THE BYPASS. With `is_genesis` taken from the payload, a FORKED block flagged
    genesis was signed under tv2 — the strong signature that survives the cutover — with no
    refusal. The marker is a constant, so a block that is not genesis cannot claim to be."""
    c = _contents(is_genesis=True)          # the payload LIES
    v = verify.check_block(c, served_hash=_expected_hash(c),
                           last_seen_hash="0x" + "99" * 32,
                           served_merkle_root=verify.merkle_root([]))
    assert v.verdict == "PREV_HASH_MISMATCH", f"a forked block claimed genesis: {v}"
    assert verify.should_refuse(v) is True


def test_a_TAMPERED_merkle_root_column_is_caught():
    """⛔ THE PLATFORM SIGNS tv2 WITH `block.merkle_root` — a COLUMN — while the node
    merkles the leaves. Nothing compared the two, so a column edited away from the leaves
    it summarises was invisible to both sides of the seam."""
    c = _contents()
    v = verify.check_block(c, served_hash=_expected_hash(c), last_seen_hash=None,
                           served_merkle_root="0x" + "77" * 32)
    assert v.verdict == "MATCH_ROOT_MISMATCH", v
    assert verify.should_refuse(v) is True


#: ⛔ TWO TESTS DELETED HERE 2026-09-24, AND NEITHER IS REPLACED BY A RENAME.
#:
#:   * `test_a_NEW_block_claiming_v1_is_REFUSED_because_the_flag_is_UNSIGNED`
#:   * `test_a_MISSING_format_version_is_not_DEFAULTED_to_legacy`
#:
#: Both asserted how the gate responds to `format_version` — one to a lie, one to an
#: absence. **The gate no longer reads that field at all**, so the property each asserted
#: has ceased to exist rather than moved: there is nothing left to lie about and nothing
#: left to omit.
#:
#: ⚠️ What replaces them is NOT a same-shaped test. It is
#: `test_the_GATE_reads_NO_FIELD_the_pre_image_does_not_COMMIT`, which asserts the
#: CATEGORY is empty, and `test_the_DECISION_still_works_with_format_version_ABSENT_or_
#: LYING`, which proves the field is inert in both directions. Stated plainly because the
#: last deletion in this file was justified by a comment naming three successors, two of
#: which asserted the opposite property.

# ── the legacy ceiling ──────────────────────────────────────────────────────

def test_a_LEGACY_block_AT_OR_BELOW_the_ceiling_is_attested_not_refused():
    """⚠️ They stay offered so they remain rescuable, and a refusal with no path back is a
    deletion. Below the ceiling, legacy is a closed historical set."""
    c = _contents(block_number=verify.LEGACY_BLOCK_CEILING,
                  format_version=1, validatable=False)
    v = verify.check_block(c, served_hash="0xold", last_seen_hash=None,
                           served_merkle_root=verify.merkle_root([]))
    assert v.verdict == "UNVALIDATABLE"
    assert verify.should_attest_v1(v) is True and verify.should_refuse(v) is False



def test_the_ceiling_is_a_PINNED_NUMBER_not_a_moving_target():
    """⚠️ Measured from the live chain when the node shipped, not remembered. A ceiling
    derived at runtime from whatever the platform reports would be the same unsigned switch
    one level up."""
    assert isinstance(verify.LEGACY_BLOCK_CEILING, int)
    #: ⛔ PINNED EXACTLY, BOTH DIRECTIONS. This read `>= 198`, which pins only the SAFE
    #: direction and admits every value that disarms the guard: raised to 1,000,000,000 it
    #: passed, and `format_version` is then once more one unsigned platform field that
    #: turns verification off on any block. Every other ceiling test uses
    #: `LEGACY_BLOCK_CEILING + 1`, so the VALUE is invisible to all of them — the rule was
    #: observed and the number was not.
    #:
    #: ⚠️ Raising this is a deliberate act with a measurement behind it. The chain had 198
    #: blocks on 2026-09-23 (public explorer API, all 198 CONFIRMED), and every block after
    #: the ceiling must be v2. Changing it means re-measuring, in the same commit.
    assert verify.LEGACY_BLOCK_CEILING == 198, (
        "the legacy ceiling moved. It is a measured fact about the live chain, not a "
        "tunable: raising it re-admits the format_version bypass on every block below the "
        "new value.")


# ── contentless: one predicate, shared with the platform ───────────────────

def test_a_CONTENTLESS_block_is_NOT_signed_as_VALIDATED():
    """⛔ THE SILENT FAILURE. `/contents` reports `validatable` from `format_version >= 2`
    alone, while the platform's `sign_block` ALSO requires content — two renderings of one
    question, and the node honoured the weaker one. It verified a contentless block, signed
    `tv2`, and the platform never tried that pre-image: 401 forever, no refusal filed, no
    alarm, the block's commission never distributed and nothing reporting it.

    ⚠️ What a v2 signature proves is POSSESSION OF THE LEAF SET. With no events and no
    transactions there is no leaf set to possess — both roots are a constant — so a node
    doing no work could format the string."""
    c = _genesis()
    honest = verify.hash_block_v2(
        number=1, prev_hash=c["prev_hash"], match_root=GENESIS_ROOT,
        event_root=verify.merkle_root([]), tx_root=verify.merkle_root([]),
        match_count=0, event_count=0, tx_count=0,
        hash_timestamp=c["hash_timestamp"], creator_id="genesis")
    v = verify.check_block(c, served_hash=honest, last_seen_hash=None,
                           served_merkle_root=GENESIS_ROOT)
    assert v.ok is False, "a contentless block must not be signed as validated"
    assert v.verdict == "UNVALIDATABLE" and verify.should_attest_v1(v) is True


def test_a_CONTENTLESS_block_ABOVE_the_ceiling_is_refused():
    """⛔ THE PLATFORM'S OWN RULE FORBIDS IT — a block exists when custody moves, and the
    seal refuses a contentless one structurally. Above the ceiling such a block cannot have
    been sealed honestly, so attesting it would launder a state the chain disallows."""
    n = verify.LEGACY_BLOCK_CEILING + 1
    c = _contents(block_number=n, counts={"match_count": 0, "event_count": 0, "tx_count": 0},
                  event_leaves=[])
    v = verify.check_block(c, served_hash="0xx", last_seen_hash=None,
                           served_merkle_root=verify.merkle_root([]))
    assert verify.should_refuse(v) is True, v
    assert verify.WIRE_VERDICTS[v.verdict] in verify.PLATFORM_REFUSAL_VERDICTS


def test_check_block_REQUIRES_the_served_merkle_root():
    """⛔ NO DEFAULT. A `served_merkle_root=None` default would let every existing call site
    keep the old behaviour silently — the shape where a fix ships inert."""
    import inspect
    sig = inspect.signature(verify.check_block)
    p = sig.parameters["served_merkle_root"]
    assert p.default is inspect.Parameter.empty, (
        "served_merkle_root has a default, so a caller that never passes it keeps the "
        "genesis defect with no error")


def test_a_CONTENT_BEARING_GENESIS_uses_the_SUBSTITUTED_match_root():
    """⛔ THE SUBSTITUTION MIRRORS THE PLATFORM'S RULE, WHICH IS KEYED ON THE MARKER AND NOT
    ON BLOCK #1 OR ON EMPTINESS. `recompute_block_roots` applies it to ANY block whose
    stored `merkle_root` is `sha256("genesis")`, so the node must too or it disagrees with
    a block the platform considers correct — the false-accusation defect again.

    ⚠️ REACHABLE ONLY WITH CONTENT, and that is why this test exists. The contentless rule
    added alongside makes a v2 check unreachable for an EMPTY genesis, so the substitution
    was measured by nothing: the mutation that merkles the match set instead SURVIVED. A
    structural fix leaving its neighbour's guard unable to fail is the new boundary, and
    this is it. Genesis sealed WITH an initial custody event is exactly what §7b's "a block
    exists when custody moves" would produce on a relaunch."""
    c = _contents(block_number=1, prev_hash="0x" + "00" * 64, creator_id="genesis")
    honest = verify.hash_block_v2(
        number=1, prev_hash=c["prev_hash"], match_root=GENESIS_ROOT,
        event_root=verify.merkle_root(
            [verify.sha256(verify.event_leaf(c["event_leaves"][0]))]),
        tx_root=verify.merkle_root([]), match_count=0, event_count=1, tx_count=0,
        hash_timestamp=c["hash_timestamp"], creator_id="genesis")

    v = verify.check_block(c, served_hash=honest, last_seen_hash=None,
                           served_merkle_root=GENESIS_ROOT)
    assert v.ok is True, f"a content-bearing genesis was refused: {v}"
    assert v.match_root == GENESIS_ROOT, (
        "the node merkled the match set instead of using the substituted marker")

    #: the control — merkling the (empty) match set gives a DIFFERENT root, so this test
    #: can tell the two apart rather than passing because they coincide
    assert verify.merkle_root([]) != GENESIS_ROOT


# ── round two: the genesis exemption, and the field it rested on ───────────

def test_a_MARKER_BLOCK_AT_ANY_HEIGHT_is_still_chain_checked():
    """⛔ THE ROUND-ONE BLOCKER, LIVE AGAIN UNDER A DIFFERENT FIELD. Replacing the payload's
    `is_genesis` boolean with a check against `GENESIS_MARKER` looked like deriving the
    answer from an artifact. It is not: **`sha256("genesis")` is a public constant**, so
    "exhibiting genesis" is writing one computable value into one unsigned field. Nothing
    binds the marker to block #1, so a block at ANY height could set it and skip the chain
    check — then be signed `tv2` as validated, because the platform builds `tv2` with
    `match_root = block.merkle_root` and therefore agrees.

    ⭐ THE EXEMPTION WAS ALSO DEAD CODE. For a real genesis the node holds no verified
    predecessor — `state.verified.get(0)` is always None — so `last_seen_hash` is already
    None and the exemption could never fire for the block it was written for. It bought
    nothing and cost the round."""
    c = _contents(block_number=500, prev_hash="0x" + "ff" * 32)
    honest = verify.hash_block_v2(
        number=500, prev_hash=c["prev_hash"], match_root=GENESIS_ROOT,
        event_root=verify.merkle_root(
            [verify.sha256(verify.event_leaf(c["event_leaves"][0]))]),
        tx_root=verify.merkle_root([]), match_count=0, event_count=1, tx_count=0,
        hash_timestamp=c["hash_timestamp"], creator_id=c["creator_id"])

    v = verify.check_block(c, served_hash=honest, last_seen_hash="0x" + "11" * 32,
                           served_merkle_root=GENESIS_ROOT)
    assert v.verdict == "PREV_HASH_MISMATCH", (
        f"a marker block at height 500 bought its way out of the chain check: {v}")
    assert verify.should_refuse(v) is True


def test_a_REAL_GENESIS_is_admitted_because_there_is_NO_PREDECESSOR_not_by_exemption():
    """⚠️ THE PROPERTY THE DELETED EXEMPTION WAS SUPPOSED TO PROTECT, asserted by the
    mechanism that actually provides it. Genesis is block #1, the node never verified a
    block #0, so `last_seen_hash` is None and the chain check does not run."""
    c = _contents(block_number=1, prev_hash="0x" + "00" * 64, creator_id="genesis")
    honest = verify.hash_block_v2(
        number=1, prev_hash=c["prev_hash"], match_root=GENESIS_ROOT,
        event_root=verify.merkle_root(
            [verify.sha256(verify.event_leaf(c["event_leaves"][0]))]),
        tx_root=verify.merkle_root([]), match_count=0, event_count=1, tx_count=0,
        hash_timestamp=c["hash_timestamp"], creator_id="genesis")
    v = verify.check_block(c, served_hash=honest, last_seen_hash=None,
                           served_merkle_root=GENESIS_ROOT)
    assert v.ok is True, v


# ── round two: an absent merkle_root must not fail open ────────────────────

def test_an_ABSENT_merkle_root_is_UNCHECKABLE_it_does_not_fail_open():
    """⛔ ONE NULL COLUMN REINSTATED THE HEADLINE. `blocks.merkle_root` is nullable and the
    loop passed `b.get("merkle_root") or ""`, and the match-root guard read
    `if not is_genesis and served_merkle_root and ...` — so an empty value short-circuited
    it. Measured: a tampered column served normally gave MATCH_ROOT_MISMATCH; the SAME
    tampering served as `""` gave OK.

    ⛔ AND IT WAS WORSE FOR GENESIS. Served as `""` the marker cannot be recognised, so a
    correct genesis block became a `tr2`-SIGNED HASH_MISMATCH — the exact accusation this
    module was rewritten to prevent, restored by a NULL.

    ⚠️ A BLOCK AWAITING A READ MAY NOT GUESS. Without the field the node cannot decide
    whether this is genesis or whether the column agrees with the leaves, so it signs
    nothing and accuses nobody — it does not fall back to attestation either, because that
    would let a NULL downgrade every block the way `format_version` once did."""
    c = _contents(block_number=300)
    honest = _expected_hash(c)

    for absent in ("", None):
        v = verify.check_block(c, served_hash=honest, last_seen_hash=None,
                               served_merkle_root=absent)
        assert v.verdict == "UNCHECKABLE", (absent, v)
        assert v.ok is False
        assert verify.should_refuse(v) is False, "a missing field is not an accusation"
        assert verify.should_attest_v1(v) is False, "a NULL must not downgrade the block"

    #: the control — with the field present the same block verifies
    assert verify.check_block(c, served_hash=honest, last_seen_hash=None,
                              served_merkle_root=_mr(c)).ok is True


def test_a_TAMPERED_column_cannot_hide_behind_an_EMPTY_one():
    c = _contents(block_number=300)
    honest = _expected_hash(c)
    assert verify.check_block(c, served_hash=honest, last_seen_hash=None,
                              served_merkle_root="0x" + "77" * 32
                              ).verdict == "MATCH_ROOT_MISMATCH"
    assert verify.check_block(c, served_hash=honest, last_seen_hash=None,
                              served_merkle_root="").verdict == "UNCHECKABLE"


def test_the_SERVED_validatable_flag_cannot_manufacture_an_ACCUSATION():
    """⛔ AN UNSIGNED PLATFORM FIELD STILL CONTROLLED THE GATE — in the accusing direction.
    The node computes `block_is_validatable` itself and then ALSO required the served flag,
    so `validatable: false` on a perfectly good v2 block above the ceiling produced
    FORMAT_REFUSED and a `tr2`-signed accusation. Deleting the conjunct survived the whole
    suite: neither direction of the belt-and-braces was tested.

    ⚠️ The node's own computation is the answer. The served flag is advisory — it is
    checked for DISAGREEMENT, which is worth knowing, but a block the node can verify is
    never refused because the platform said not to bother."""
    c = _contents(block_number=verify.LEGACY_BLOCK_CEILING + 1, validatable=False)
    v = verify.check_block(c, served_hash=_expected_hash(c), last_seen_hash=None,
                           served_merkle_root=_mr(c))
    assert v.verdict != "FORMAT_REFUSED", (
        f"the platform turned a verifiable block into a signed accusation by clearing a "
        f"flag: {v}")
    assert v.ok is True, v



def test_a_MATCH_ROOT_MISMATCH_states_BOTH_SIDES_of_the_disagreement():
    """⛔ A REFUSAL THAT SAYS ONLY "NO" IS NOT EVIDENCE. This verdict populated the node's
    computed `match_root` and left both hash fields empty, so on the wire it became
    `HASH_MISMATCH` with `expected_block_hash=""` — a stored row reading "hash mismatch,
    expected (no hash)", carrying no record of what the platform held. That directly
    contradicts the pre-image's own promise that the report states the disagreement itself
    rather than merely that one occurred."""
    c = _contents(block_number=300)
    honest = _expected_hash(c)
    v = verify.check_block(c, served_hash=honest, last_seen_hash=None,
                           served_merkle_root="0x" + "77" * 32)
    assert v.verdict == "MATCH_ROOT_MISMATCH"
    assert v.served_block_hash == honest, "what the platform stores is not recorded"
    assert v.computed_block_hash, "the node's own block hash is not recorded"
    assert v.match_root == _mr(c), (
        "the root the node computed is not recorded, so the row states nothing about WHAT "
        "the node thinks the leaves merkle to")
    assert v.event_root and v.tx_root, "the other roots are not recorded either"

    #: ⚠️ AND THE TWO BLOCK HASHES ARE EQUAL HERE, WHICH IS THE TRUTH AND NOT A GAP. The
    #: hash commits to the match_root the NODE computed, so a block whose stored COLUMN
    #: disagrees with its leaves still hashes identically on both sides — that is exactly
    #: why this verdict has to exist separately from HASH_MISMATCH. The other half of the
    #: disagreement is the platform's own column, which it already holds.
    assert v.computed_block_hash == honest


# ── THE CLASS, not the instance ────────────────────────────────────────────

def test_the_GATE_reads_NO_FIELD_the_pre_image_does_not_COMMIT():
    """⛔⛔ THE CLASS BEHIND THREE ROUNDS OF FINDINGS. Each round closed the instance a seat
    named and left the category intact, so the next round found it in the next field:

        round 1  `format_version`  — one unsigned field turned verification off
        round 2  `is_genesis`      — replaced by a check against a PUBLIC constant, still
                                     unsigned, still a bypass at any height
        round 2  `validatable`     — could turn a good block into a signed accusation

    The general form is one sentence: **the node's decision depended on a field the
    verified party supplies and no signed pre-image commits.** A fix that makes one such
    field safe moves the defect to the next one; the only fix that closes it empties the
    category.

    ⭐ SO THE ALLOWED SET IS DERIVED FROM `hash_block_v2`'s OWN SIGNATURE. Every term of the
    v2 pre-image is committed by the hash the node is checking, so a lie about any of them
    changes that hash and is caught by the arithmetic. Anything else is a field the platform
    can set freely — and the gate must not read it.

    ⚠️ This is the test, not the fix: a fourth field cannot be introduced without failing
    here. Inexpressible rather than remembered."""
    import ast
    import inspect
    import textwrap

    #: the pre-image's terms, read off the function that builds it
    committed = set(inspect.signature(verify.hash_block_v2).parameters)

    #: how each served key reaches a committed term. The VALUES are checked against
    #: `committed` below, so this mapping cannot quietly admit a term the hash omits.
    SERVED_TO_TERM = {
        "block_number": "number", "prev_hash": "prev_hash",
        "hash_timestamp": "hash_timestamp", "creator_id": "creator_id",
        "counts": "match_count",            # carries all three
        "match_leaves": "match_root", "event_leaves": "event_root",
        "tx_leaves": "tx_root",
    }
    unknown = {t for t in SERVED_TO_TERM.values() if t not in committed}
    assert not unknown, f"the mapping claims terms the pre-image does not commit: {unknown}"

    #: ⛔ AND THE MAPPING MUST BE INJECTIVE, or the allowed set can be widened by ALIASING.
    #: Checking only that every VALUE is a committed term is not enough: adding
    #: `"format_version": "number"` passes that check — `number` really is committed — and
    #: quietly re-admits the exact field this whole class is about. Measured: that mutation
    #: SURVIVED. One served key per committed term makes the alias a collision.
    terms = list(SERVED_TO_TERM.values())
    dupes = {t for t in terms if terms.count(t) > 1}
    assert not dupes, (
        f"two served keys claim the same pre-image term {sorted(dupes)}. One of them is an "
        f"ALIAS, and an alias is how an uncommitted field re-enters the allowed set while "
        f"every value still looks committed.")

    tree = ast.parse(textwrap.dedent(inspect.getsource(verify._check_block)))
    read: set[str] = set()
    for n in ast.walk(tree):
        #: contents["x"]
        if (isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name)
                and n.value.id == "contents" and isinstance(n.slice, ast.Constant)):
            read.add(n.slice.value)
        #: contents.get("x", ...)
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "get" and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "contents" and n.args
                and isinstance(n.args[0], ast.Constant)):
            read.add(n.args[0].value)

    assert read, "the scan found no field reads at all — it is pointed at the wrong thing"
    uncommitted = read - set(SERVED_TO_TERM)
    assert not uncommitted, (
        f"the gate reads {sorted(uncommitted)}, which the v2 pre-image does not commit. "
        f"A field the verified party can set freely must not influence whether or how "
        f"verification happens — that is the defect this platform has now shipped three "
        f"times in three different fields. Read it for diagnostics if you must; do not "
        f"decide on it.")


def test_the_DECISION_still_works_with_format_version_ABSENT_or_LYING():
    """⛔ THE CLASS, DEMONSTRATED. `format_version` is not committed, so the node no longer
    reads it — which means a payload that omits it, or lies about it in either direction,
    changes nothing. Round one's blocker cannot be expressed."""
    c = _contents(block_number=500)
    honest = _expected_hash(c)

    for fv in (1, 2, 99, None):
        probe = _contents(block_number=500)
        if fv is None:
            del probe["format_version"]
        else:
            probe["format_version"] = fv
        v = verify.check_block(probe, served_hash=honest, last_seen_hash=None,
                               served_merkle_root=_mr(probe))
        assert v.ok is True, (
            f"format_version={fv} changed the outcome for a block that verifies: {v}")

    #: and a block that does NOT verify is refused above the ceiling whatever it claims
    bad = _contents(block_number=500)
    bad["format_version"] = 1
    v = verify.check_block(bad, served_hash="0x" + "00" * 32, last_seen_hash=None,
                           served_merkle_root=_mr(bad))
    assert v.verdict == "HASH_MISMATCH" and verify.should_refuse(v), v
