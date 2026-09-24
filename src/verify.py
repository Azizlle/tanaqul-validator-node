"""Independent verification of a sealed block, computed from the leaves served.

⛔ WHY THE NODE COMPUTES THIS ITSELF. Before this module the node took `block_hash` out of
the payload the platform sent and signed it. No recomputation, no chain check. A validator
signature therefore attested to one thing only: that a node received a string and signed
it. The quorum was real and the cryptography was real; the thing attested was the
platform's own claim about itself.

⛔ A SECOND IMPLEMENTATION, DELIBERATELY. Everywhere else in this system a duplicated
implementation is a defect waiting to drift. Here it is the entire point: importing the
platform's hashing would verify the platform's arithmetic with the platform's code, and a
bug in that code would verify itself. Independent verification requires an independent
implementation — written from the documented pre-image, not copied from the other side.

⚠️ AND THE ENDPOINT IS BUILT SO THE SHORTCUT IS UNAVAILABLE. `/blocks/{n}/contents`
deliberately does NOT serve `event_root` or `tx_root`, and a backend test pins that
omission. If it served them, a node could compare the platform's number to the platform's
number and call it verification. It serves leaf FIELD DICTS, so the node builds every leaf
payload itself and checks the leaf FORMAT too.

⚠️ THREE DETAILS THAT DECIDE WHETHER THIS AGREES WITH THE CHAIN:
      - the empty root is `sha256("empty")`, not the hash of an empty string;
      - merkle pairs concatenate the HEX TEXT, not the decoded bytes — the conventional
        construction gives a different root and would refuse every block;
      - `hash_timestamp` is used VERBATIM as served. Re-serialising it is the v1 defect,
        where a transient `now.isoformat()` was hashed while the row kept another instant.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List


def sha256(data: str) -> str:
    """SHA-256 of the UTF-8 bytes, 0x-prefixed — the chain's canonical digest."""
    return "0x" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def merkle_root(hashes: List[str]) -> str:
    """Merkle root over 0x-prefixed leaf hashes.

    ⚠️ Pairs are concatenated as HEX STRINGS. An odd level duplicates its last node.
    """
    if not hashes:
        return sha256("empty")
    nodes = [h.replace("0x", "") for h in hashes]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [
            hashlib.sha256((nodes[i] + nodes[i + 1]).encode()).hexdigest()
            for i in range(0, len(nodes), 2)
        ]
    return "0x" + nodes[0]


def hash_block_v2(
    number: int,
    prev_hash: str,
    match_root: str,
    event_root: str,
    tx_root: str,
    match_count: int,
    event_count: int,
    tx_count: int,
    hash_timestamp: str,
    creator_id: str,
) -> str:
    """The v2 content-committed block hash — positional and pipe-delimited.

    ⚠️ `hash_timestamp` is the exact string the block stores. Never reformat it.
    """
    return sha256(
        f"v2|{number}|{prev_hash}|{match_root}|{event_root}|{tx_root}"
        f"|{match_count}|{event_count}|{tx_count}"
        f"|{hash_timestamp}|{creator_id}"
    )


# ── leaf pre-images ─────────────────────────────────────────────────────────
#
# ⛔ THE NODE BUILDS THESE, IT DOES NOT RECEIVE THEM. `/contents` serves field dicts;
# if it served the finished strings the node would be hashing the platform's rendering
# of a leaf and could not detect a leaf whose FIELDS say something other than its
# string. Building them here means the leaf FORMAT is verified too.
#
# ⚠️ Every field is indexed, never `.get(...)`. The server already normalises NULLs to
# "" and 0 before serving, so a key that is absent means the payload is not the payload
# this protocol describes — and defaulting it would let the node hash something the
# seal never hashed and still call it a match.


def match_leaf(f: dict) -> str:
    """`MATCH|id|buy_order_id|sell_order_id|metal|quantity_grams|price_per_gram|matched_at`"""
    return (
        f"MATCH|{f['id']}|{f['buy_order_id']}|{f['sell_order_id']}|{f['metal']}|"
        f"{f['quantity_grams']}|{f['price_per_gram']}|{f['matched_at']}"
    )


def event_leaf(f: dict) -> str:
    """`E|id|event_hash|event_type|metal|grams|vault_key`

    ⚠️ The field ORDER of the pre-image is not the field order of the dict: `grams`
    is served third and hashed fifth. Read the format string, not the JSON.
    """
    return (
        f"E|{f['id']}|{f['event_hash']}|{f['event_type']}|"
        f"{f['metal']}|{f['grams']}|{f['vault_key']}"
    )


def tx_leaf(f: dict) -> str:
    """`T|id|tx_hash|tx_type|metal|grams|total_grams|from_vault_key|to_vault_key`"""
    return (
        f"T|{f['id']}|{f['tx_hash']}|{f['tx_type']}|{f['metal']}|"
        f"{f['grams']}|{f['total_grams']}|{f['from_vault_key']}|{f['to_vault_key']}"
    )


# ── the verdict ─────────────────────────────────────────────────────────────

#: ⛔ THE GENESIS MARKER, HELD AS A CONSTANT SO THE PLATFORM CANNOT ASSERT GENESIS — ONLY
#: EXHIBIT IT. A genesis block's match_root is not the merkle of its (empty) match set; the
#: platform substitutes this value. The node used to take `is_genesis` from the served
#: payload, an unsigned field committed by no pre-image, which meant the party being
#: verified could switch the chain check off on any block it chose. It is now derived: the
#: `merkle_root` served by /pending-blocks must equal this exact constant.
GENESIS_MARKER = sha256("genesis")

#: ⛔ WHERE LEGACY ENDS. Measured from the live chain on 2026-09-23 — the public explorer
#: API reported block #198 as the tip, sealed 2026-09-20 — not remembered and not asked of
#: the platform at runtime.
#:
#: `format_version` is a field the platform sets and no pre-image commits, so while the
#: node honoured it unconditionally ONE FIELD TURNED VERIFICATION OFF: a block whose hash
#: does not match its own contents was signed as an attestation of receipt, and while
#: `require_validated_signatures` is off that still reaches quorum. A platform that wanted
#: to avoid being checked would set it.
#:
#: A fixed ceiling makes legacy a CLOSED HISTORICAL SET rather than a switch. At or below
#: it, a v1 block is attested — those blocks stay offered so they remain rescuable, and a
#: refusal with no path back is a deletion. Above it, claiming v1 is refused.
LEGACY_BLOCK_CEILING = 198

OK = "OK"
HASH_MISMATCH = "HASH_MISMATCH"
PREV_HASH_MISMATCH = "PREV_HASH_MISMATCH"
COUNT_MISMATCH = "COUNT_MISMATCH"
CONTENTS_MALFORMED = "CONTENTS_MALFORMED"
MATCH_ROOT_MISMATCH = "MATCH_ROOT_MISMATCH"
#: the node could not check it, and it is old enough that this is expected -> attest
#: the node was not given what it needs to decide — neither a signature nor an accusation
UNCHECKABLE = "UNCHECKABLE"
UNVALIDATABLE = "UNVALIDATABLE"
#: the node could not check it and it is NOT old enough for that to be honest -> refuse
FORMAT_REFUSED = "FORMAT_REFUSED"


@dataclass(frozen=True)
class Committed:
    """Exactly the terms the v2 pre-image commits — and nothing else survives parsing.

    ⛔⛔ THIS TYPE IS THE CLASS FIX. Four rounds of findings were one defect: the gate
    decided on a field the verified party supplies and no pre-image commits. The third
    repair was an AST detector that looked for reads of the payload dict, and a §14 seat
    defeated it with `_c = contents` — 180 tests green, the blocker restored verbatim.

    ⭐ A DETECTOR PINS A SPELLING; A TYPE PINS THE PROPERTY. The gate never receives the
    payload, so `format_version` is not merely unread — it is **unreachable**. Adding a
    field here is the only way to make one reachable, and
    `test_the_GATE_CANNOT_REACH_a_field_the_pre_image_does_not_COMMIT` checks these fields
    against `hash_block_v2`'s signature as a BIJECTION, both directions.

    ⚠️ The leaf lists stand for the three roots: they are what the roots are computed from,
    which is the only reason a list belongs on a record of committed terms.
    """
    number: int
    prev_hash: str
    hash_timestamp: str
    creator_id: str
    match_count: int
    event_count: int
    tx_count: int
    match_leaves: tuple
    event_leaves: tuple
    tx_leaves: tuple


def parse_contents(contents: dict) -> Committed:
    """Build the committed record from a served payload, at the boundary.

    ⛔ EVERY FIELD IS INDEXED. A `.get(..., default)` here would let an absence become a
    value and travel inward as though it had been served — the second class, which already
    cost a NULL `merkle_root` turning a correct genesis block into a signed accusation.
    A payload missing any committed term is not a payload this protocol describes.

    ⚠️ Fields the payload carries and the hash does NOT commit — `format_version`,
    `validatable`, `is_genesis` — are dropped here, deliberately and silently. They may be
    logged by a caller; they may not reach a decision.
    """
    counts = contents["counts"]
    return Committed(
        number=int(contents["block_number"]),
        prev_hash=contents["prev_hash"],
        hash_timestamp=contents["hash_timestamp"],
        creator_id=contents["creator_id"],
        match_count=int(counts["match_count"]),
        event_count=int(counts["event_count"]),
        tx_count=int(counts["tx_count"]),
        match_leaves=tuple(contents["match_leaves"]),
        event_leaves=tuple(contents["event_leaves"]),
        tx_leaves=tuple(contents["tx_leaves"]),
    )


@dataclass(frozen=True)
class Verdict:
    """What the node concluded, and enough evidence to say why in a refusal report.

    ⚠️ `ok is False` does NOT mean "refuse". `UNVALIDATABLE` is a third state: the node
    could not check this block, which is not the same as having checked it and
    disagreed. Signing it as verified would be the rubber stamp this module replaces;
    reporting it as a refusal would accuse the platform of tampering on the strength of
    a format the node cannot read. The caller decides — see `should_refuse`.
    """
    ok: bool
    verdict: str
    block_number: int
    served_block_hash: str = ""
    computed_block_hash: str = ""
    served_prev_hash: str = ""
    expected_prev_hash: str = ""
    #: the roots THIS node computed — carried because the `tr2` pre-image commits them,
    #: so the loop states the disagreement rather than recomputing it a second time
    match_root: str = ""
    event_root: str = ""
    tx_root: str = ""
    match_count: int = 0
    event_count: int = 0
    tx_count: int = 0
    hash_timestamp: str = ""
    creator_id: str = ""
    detail: str = ""


def should_refuse(v: Verdict) -> bool:
    """A verdict earns a signed refusal only when the node actually checked and disagreed."""
    return v.verdict in (HASH_MISMATCH, PREV_HASH_MISMATCH, COUNT_MISMATCH,
                         CONTENTS_MALFORMED, MATCH_ROOT_MISMATCH, FORMAT_REFUSED)


def _check_block(c: Committed, served_hash: str, last_seen_hash: str | None,
                 served_merkle_root: str) -> Verdict:
    """Recompute a block from its served leaves and judge it.

    `served_hash` is the block hash the PLATFORM stores (from `/pending-blocks`), never
    anything out of `contents` — comparing a payload against itself proves nothing.

    `last_seen_hash` is the hash of the last block THIS node verified, or None when it
    has no history. ⚠️ None admits the block: a node that refuses everything until it
    has a predecessor can never acquire one, and a refusal with no path to retry is a
    deletion, not a check.
    """
    number = c.number
    _ec, _tc = c.event_count, c.tx_count

    #: ⛔⛔ THE DECISION READS ONLY WHAT THE HASH COMMITS. Three rounds of findings were one
    #: class: the gate depended on a field the verified party supplies and no pre-image
    #: commits — `format_version`, then `is_genesis`, then `validatable`. Closing each
    #: instance moved the defect to the next field. The category is empty now, and
    #: `test_the_GATE_reads_NO_FIELD_the_pre_image_does_not_COMMIT` derives the allowed set
    #: from `hash_block_v2`'s own signature so a fourth cannot be added without failing.
    #:
    #: ⭐ `format_version` IS NOT READ AT ALL. The node does not need to be told the format:
    #: a block whose leaves reproduce its stored hash IS v2, and one whose leaves do not is
    #: either legacy or tampered — a question the BLOCK NUMBER answers, and the number is
    #: committed. Being told is the part that was forgeable.
    _legacy = number <= LEGACY_BLOCK_CEILING

    #: ⛔ NO LEAF SET, NOTHING TO POSSESS. `carries_validatable_content` reads the COUNTS,
    #: which the pre-image commits, so a lie about them changes the hash and is caught.
    if not carries_validatable_content(_ec, _tc):
        return Verdict(
            ok=False, verdict=(UNVALIDATABLE if _legacy else FORMAT_REFUSED),
            block_number=number, served_block_hash=served_hash,
            event_count=_ec, tx_count=_tc,
            detail=(
                f"block #{number} carries {_ec} event(s) and {_tc} transaction(s), so there "
                f"is no leaf set to possess and no v2 signature could prove anything. "
                + (f"At or below the legacy ceiling ({LEGACY_BLOCK_CEILING}) that is "
                   f"expected — not a disagreement."
                   if _legacy else
                   f"ABOVE the legacy ceiling ({LEGACY_BLOCK_CEILING}) a block exists only "
                   f"when custody moves, so this cannot have been sealed honestly.")))

    matches, events, txs = c.match_leaves, c.event_leaves, c.tx_leaves

    #: ⛔ THE COUNTS ARE HASHED SEPARATELY FROM THE ROOTS, so a payload whose counts
    #: disagree with its own leaf lists is incoherent before any hashing happens. It
    #: would surface as a hash mismatch anyway; naming it distinctly is the difference
    #: between a refusal report that can be acted on and one that says only "no".
    served_counts = (c.match_count, c.event_count, c.tx_count)
    actual_counts = (len(matches), len(events), len(txs))
    if served_counts != actual_counts:
        return Verdict(
            ok=False, verdict=COUNT_MISMATCH, block_number=number,
            served_block_hash=served_hash,
            detail=f"block #{number} declares counts {served_counts} "
                   f"(match, event, tx) and served {actual_counts} leaves.")

    computed_match_root = merkle_root([sha256(match_leaf(f)) for f in matches])

    #: ⛔ AN ABSENT `merkle_root` IS NOT AN EMPTY ONE, AND IT MUST NOT FAIL OPEN. The column
    #: is nullable and the loop passes `or ""`; the match-root guard used to read
    #: `if ... and served_merkle_root and ...`, so an empty value short-circuited it —
    #: measured, a tampered column served as "" verified as OK. Worse for genesis: without
    #: the field the marker cannot be recognised, so a correct genesis block became a
    #: `tr2`-SIGNED accusation, which is the exact catastrophe this module was rewritten to
    #: prevent, restored by a NULL.
    #:
    #: ⚠️ A BLOCK AWAITING A READ MAY NOT GUESS. The node signs nothing and accuses nobody,
    #: and it does NOT fall back to attestation — that would let a NULL column downgrade
    #: every block the way `format_version` once did.
    if not served_merkle_root:
        return Verdict(
            ok=False, verdict=UNCHECKABLE, block_number=number,
            served_block_hash=served_hash,
            match_count=served_counts[0], event_count=served_counts[1],
            tx_count=served_counts[2],
            detail=f"block #{number} was served without a merkle_root, so the node cannot "
                   f"tell whether it is genesis or whether the stored root agrees with the "
                   f"leaves. Not a disagreement — the node was not given enough to check.")

    #: ⛔ GENESIS IS DERIVED FROM THE MARKER, NEVER FROM THE PAYLOAD'S `is_genesis`. The
    #: platform substitutes `sha256("genesis")` for a genesis block's match_root, so a node
    #: that merkled the (empty) match set disagreed with a block correct by construction —
    #: and refused it, filing a SIGNED accusation that the platform sealed something it
    #: cannot reproduce. `merkle_root` comes from /pending-blocks and is compared to a
    #: constant this node holds: the platform can exhibit genesis, not declare it.
    #: ⛔ THE MARKER IS BOUND TO BLOCK #1. `GENESIS_MARKER` is `sha256("genesis")` — a
    #: PUBLIC constant published in this repo — so recognising it alone let the platform
    #: exhibit genesis at ANY height, and a marker block's match_root is the marker rather
    #: than the merkle of its leaves. A §14 seat swapped a whole match set at block #500
    #: (grams 1.000 -> 999999.000) and the node still returned OK: **the entire match set
    #: was uncommitted, at any height, forever.**
    #:
    #: ⚠️ Genesis is block #1 by construction — `POST /blocks/genesis` creates #1 — so the
    #: number is the binding the marker lacks, and the number IS committed by the hash.
    is_genesis = (served_merkle_root == GENESIS_MARKER and number == 1)

    match_root = effective_match_root(served_merkle_root, computed_match_root)
    event_root = merkle_root([sha256(event_leaf(f)) for f in events])
    tx_root = merkle_root([sha256(tx_leaf(f)) for f in txs])

    computed = hash_block_v2(
        number=number,
        prev_hash=c.prev_hash,
        match_root=match_root,
        event_root=event_root,
        tx_root=tx_root,
        match_count=served_counts[0],
        event_count=served_counts[1],
        tx_count=served_counts[2],
        hash_timestamp=c.hash_timestamp,
        creator_id=c.creator_id,
    )

    #: everything the `tr2` pre-image commits, computed once and carried on every verdict
    #: built from here down
    _roots = dict(match_root=match_root, event_root=event_root, tx_root=tx_root,
                  match_count=served_counts[0], event_count=served_counts[1],
                  tx_count=served_counts[2],
                  hash_timestamp=c.hash_timestamp,
                  creator_id=c.creator_id)

    #: ⛔ THE CHECK THIS MODULE EXISTS FOR. Until now the node signed `served_hash`
    #: itself, so a block whose stored hash was internally consistent but whose CONTENT
    #: differed from what was sealed passed unchallenged — there was nothing to
    #: challenge it with.
    #: ⛔ AND THE COLUMN MUST AGREE WITH THE LEAVES IT SUMMARISES. The platform signs
    #: `tv2` with `block.merkle_root` — a stored column — while the node merkles the served
    #: leaves, and nothing compared the two: a column edited away from its leaves was
    #: invisible to both sides of the seam.
    #:
    #: ⚠️ CHECKED AFTER THE HASH IS COMPUTED, DELIBERATELY, so the report can state BOTH
    #: SIDES. Returning early left both hash fields empty and the row read "hash mismatch,
    #: expected (no hash)" — a refusal that says only "no" is not evidence.
    #: ⛔ AND THE CEILING DOES NOT DISABLE THIS. It used to read `and not _legacy`, which
    #: switched the match-root commitment off for every block at or below 198 — i.e. the
    #: WHOLE CHAIN as it exists today. Introduced to close one class, it opened a hole
    #: across all 198 blocks, and it was invisible because the fixtures had been moved
    #: ABOVE the ceiling precisely so they would exercise the verifying branch.
    if not is_genesis and computed_match_root != served_merkle_root:
        return Verdict(
            ok=False, verdict=MATCH_ROOT_MISMATCH, block_number=number,
            served_block_hash=served_hash, computed_block_hash=computed,
            served_prev_hash=c.prev_hash, **_roots,
            detail=f"block #{number} stores merkle_root {served_merkle_root} but its "
                   f"{len(matches)} served match leaf/leaves merkle to "
                   f"{computed_match_root}.")

    #: ⚠️ AND BELOW THE CEILING A FAILED RECOMPUTATION IS NOT AN ACCUSATION. v1 hashed a
    #: timestamp that was never persisted, so no arithmetic here can reach those blocks —
    #: which is indistinguishable from tampering without trusting a format field. The
    #: ceiling is the honest discriminator: a closed historical set, attested; everything
    #: after it must reproduce.
    if computed != served_hash and _legacy:
        return Verdict(
            ok=False, verdict=UNVALIDATABLE, block_number=number,
            served_block_hash=served_hash, computed_block_hash=computed, **_roots,
            detail=f"block #{number} does not reproduce its stored hash and sits at or "
                   f"below the legacy ceiling ({LEGACY_BLOCK_CEILING}); pre-v2 blocks "
                   f"hashed a timestamp that was never persisted, so this is expected.")

    if computed != served_hash:
        return Verdict(
            ok=False, verdict=HASH_MISMATCH, block_number=number,
            served_block_hash=served_hash, computed_block_hash=computed, **_roots,
            detail=f"block #{number} hashes to {computed} from its own served leaves; "
                   f"the platform stores {served_hash}.")

    #: ⛔ A SECOND, INDEPENDENT PROPERTY. A block can be internally perfect and still
    #: not follow the block this node last verified — which is what a fork, a rollback
    #: or a replayed history looks like from here.
    #:
    #: ⛔ AND THERE IS NO GENESIS EXEMPTION, DELIBERATELY. One stood here — `and not
    #: is_genesis` — and it was BOTH dead code and the whole attack surface. Dead, because
    #: for a real genesis this node has never verified a block #0, so `last_seen_hash` is
    #: already None and the branch cannot be reached. The attack surface, because
    #: `GENESIS_MARKER` is a PUBLIC constant in an unsigned field with no binding to block
    #: #1: a block at ANY height could exhibit it and skip this check, then be signed `tv2`
    #: as validated because the platform builds `tv2` from the same column and agrees.
    #:
    #: ⚠️ A node with no history still has no opinion — that is `last_seen_hash is None`,
    #: which is the honest reason and the only one needed.
    if last_seen_hash is not None:
        if c.prev_hash != last_seen_hash:
            return Verdict(
                ok=False, verdict=PREV_HASH_MISMATCH, block_number=number,
                served_block_hash=served_hash, computed_block_hash=computed,
                served_prev_hash=c.prev_hash,
                expected_prev_hash=last_seen_hash, **_roots,
                detail=f"block #{number} follows {c.prev_hash}; this node "
                       f"last verified {last_seen_hash}.")

    return Verdict(ok=True, verdict=OK, block_number=number,
                   served_block_hash=served_hash, computed_block_hash=computed,
                   served_prev_hash=c.prev_hash, **_roots)


# ── the signed pre-images ───────────────────────────────────────────────────
#
# ⛔ THREE PREFIXES, THREE MEANINGS. `v2|` is the block hash, `tv2|` a validation, `tr2|`
# a refusal. A digest produced under one can never be replayed as another — which is why
# a node never signs the `v2|` string it just computed: that digest is already public as
# the block hash, so a signature over it would prove nothing about who computed it.


def validation_payload(
    number: int,
    block_hash: str,
    prev_hash: str,
    match_root: str,
    event_root: str,
    tx_root: str,
    match_count: int,
    event_count: int,
    tx_count: int,
    hash_timestamp: str,
    creator_id: str,
) -> str:
    """The exact string a validating v2 node signs.

    ⛔ `block_hash` GOES IN WITHOUT ITS `0x`; `prev_hash` and all three roots keep theirs.
    The platform builds this with `block.hash[2:]` and passes the rest through unchanged.
    All five are 0x-prefixed hex on the wire and exactly one is stripped, so there is no
    way to infer this from the data — a node that treats them alike signs different bytes,
    receives one deliberately uninformative 401, and reports itself healthy while
    attesting nothing.
    """
    _bh = block_hash[2:] if block_hash.startswith("0x") else block_hash
    return (
        f"tv2|{number}|{_bh}|{prev_hash}|{match_root}|{event_root}|{tx_root}"
        f"|{match_count}|{event_count}|{tx_count}|{hash_timestamp}|{creator_id}"
    )


def refusal_payload(
    number: int, validator_id: str, verdict: str, observed_block_hash: str,
    expected_block_hash: str, observed_prev_hash: str, expected_prev_hash: str,
    match_root: str, event_root: str, tx_root: str, match_count: int,
    event_count: int, tx_count: int, hash_timestamp: str, creator_id: str,
    reported_at: str,
) -> str:
    """The exact string a refusing node signs.

    ⛔ THE VERDICT IS INSIDE THE SIGNED BYTES. `tv2` carries no verdict, so an
    `approved=False` flag beside it would be written by the party being objected to — and
    a refusal the accused can edit is not evidence.

    ⛔ AND IT COMMITS THE SIGNER. `validator_id` sits immediately after the prefix.
    Without it, identity rests on whichever row's public key the verification happens to
    run against, so the same bytes verify as a refusal by any validator sharing that key.

    ⚠️ `expected_*` are what THIS NODE computed; `observed_*` are what it was served. The
    report therefore states the disagreement itself, not merely that one occurred.
    """
    return (
        f"tr2|{validator_id}|{number}|{verdict}|{observed_block_hash}|{expected_block_hash}"
        f"|{observed_prev_hash}|{expected_prev_hash}|{match_root}|{event_root}|{tx_root}"
        f"|{match_count}|{event_count}|{tx_count}|{hash_timestamp}|{creator_id}"
        f"|{reported_at}"
    )


# ── what the node DOES with a verdict ───────────────────────────────────────

#: The verdict strings the platform will store. Anything else is a 400 — an unreviewed
#: verdict is a bug in the node, not a dispute, and the platform says so rather than
#: recording a string nobody has agreed the meaning of.
PLATFORM_REFUSAL_VERDICTS = ("FORMAT_NOT_VALIDATABLE", "HASH_MISMATCH",
                             "PREV_HASH_MISMATCH", "CONTENTS_MALFORMED")

#: ⛔ THE NODE'S OWN VERDICT NAMES ARE NOT THE WIRE NAMES. The checker distinguishes a
#: count disagreement from a malformed payload because the two want different words in a
#: report; the wire does not, and reporting an internal name loses the refusal entirely —
#: on the one channel built because a refusal had nowhere to go.
WIRE_VERDICTS = {
    HASH_MISMATCH: "HASH_MISMATCH",
    PREV_HASH_MISMATCH: "PREV_HASH_MISMATCH",
    COUNT_MISMATCH: "CONTENTS_MALFORMED",
    MATCH_ROOT_MISMATCH: "HASH_MISMATCH",
    FORMAT_REFUSED: "FORMAT_NOT_VALIDATABLE",
    CONTENTS_MALFORMED: "CONTENTS_MALFORMED",
    UNVALIDATABLE: "FORMAT_NOT_VALIDATABLE",
}


def block_is_validatable(format_version: int, event_count: int, tx_count: int) -> bool:
    """The PLATFORM's rule for whether a block can be validated, mirrored for agreement.

    ⛔ THE GATE IN THIS MODULE DOES NOT CALL IT, DELIBERATELY, AND THAT IS NOT DEAD CODE.
    It takes `format_version` — a field no pre-image commits — so using it to decide would
    reopen the class that produced three rounds of findings. Its consumer is the SEAM: it
    is a vector kind in `spec/agreement_vectors.json`, run here and against the platform's
    own implementation, so the two sides provably agree about a rule the platform applies
    and this node deliberately declines to depend on.
    #: (`test_the_GATE_reads_NO_FIELD_the_pre_image_does_not_COMMIT` is what would fail if
    #: someone wired it back into the decision.)

    ⛔ THE PLATFORM ANSWERS THIS IN ONE PLACE AND THE NODE MUST NOT ANSWER IT IN ANOTHER.
    `/contents` used to report `validatable` from `format_version >= 2` alone while the
    platform's signature gate ALSO required content, and honouring the weaker answer meant
    signing a `tv2` pre-image the platform never tries: 401 forever, no refusal filed, no
    alarm, the block's commission never distributed.
    """
    return int(format_version or 1) >= 2 and carries_validatable_content(event_count, tx_count)


def effective_match_root(stored_merkle_root: str, computed_match_root: str) -> str:
    """Which match_root a block's v2 hash actually commits to — the platform's rule, named.

    ⛔ A GENESIS BLOCK'S match_root IS NOT THE MERKLE OF ITS MATCH SET. The platform
    substitutes the marker, and the node merkled the set instead — so it disagreed with a
    block correct by construction, refused it, and filed a `tr2`-SIGNED accusation that the
    platform had sealed something it cannot reproduce. Every node, every poll, forever.

    ⚠️ KEYED ON THE MARKER, NOT ON BLOCK #1 AND NOT ON EMPTINESS — an admin can mint a
    non-genesis block #1, and a relaunch may seal genesis WITH an initial custody event.
    And the marker is a CONSTANT held here, so the platform can exhibit genesis, never
    declare it.
    """
    return stored_merkle_root if stored_merkle_root == GENESIS_MARKER else computed_match_root


def carries_validatable_content(event_count: int, tx_count: int) -> bool:
    """Whether a block has a leaf set to possess — the platform's own predicate, by name.

    ⛔ THE NODE MUST NOT SIGN `tv2` FOR A BLOCK THE PLATFORM WILL NOT VERIFY AS v2.
    `/contents` reports `validatable` from `format_version >= 2` alone; the platform's
    `sign_block` ALSO requires this. Two renderings of one question, and honouring the
    weaker one meant the node verified a contentless block, signed `tv2`, and the platform
    never tried that pre-image — 401 on every poll forever, no refusal filed, no alarm, the
    block's commission never distributed and nothing anywhere reporting it.

    ⚠️ What a v2 signature proves is POSSESSION OF THE LEAF SET. With no events and no
    transactions there is no leaf set: both roots are a compile-time constant and every
    other term is served, so a node doing zero work could format the string.
    """
    return (event_count or 0) > 0 or (tx_count or 0) > 0


def should_attest_v1(v: Verdict) -> bool:
    """Whether to fall back to the v1 attestation-of-receipt signature.

    ⛔ ONLY FOR A BLOCK THE NODE COULD NOT CHECK, NEVER ONE IT DISAGREED WITH.
    `/pending-blocks` deliberately keeps offering legacy blocks that have not met quorum so
    they remain rescuable; a v2 node that dropped them would make them unrescuable
    fleet-wide, which is a worse failure than the rubber stamp this replaces.

    ⚠️ This cannot inflate a validated quorum. The platform decides which scheme a
    signature belongs to by trying the v2 pre-image FIRST and falling back — the answer is
    cryptographic, never self-reported — so a v1 signature is recorded as an attestation of
    receipt, which is exactly what it is.
    """
    return v.verdict == UNVALIDATABLE


def check_block(contents: dict, served_hash: str, last_seen_hash: str | None,
                served_merkle_root: str) -> Verdict:
    """`_check_block`, made TOTAL: every payload the platform can serve yields a verdict.

    ⛔ AN EXCEPTION MUST NOT ESCAPE INTO THE POLL LOOP. It would either kill the node or —
    far likelier, and worse — be caught by a broad handler upstream and logged as a fetch
    failure, turning a tampering signal into a quiet retry. That is the swallow shape this
    platform has shipped before.

    ⚠️ The catch is NARROW ON PURPOSE. `KeyError`/`TypeError`/`ValueError` are what a
    malformed payload produces — a missing field, a string where a count belongs. Catching
    `Exception` here would absorb a genuine bug in the arithmetic above and report it as
    the platform's malformed data, which is an accusation against the wrong party.
    """
    try:
        return _check_block(parse_contents(contents), served_hash, last_seen_hash,
                            served_merkle_root)
    except (KeyError, TypeError, ValueError) as e:
        try:
            number = int(contents["block_number"])
        except (KeyError, TypeError, ValueError):
            number = 0
        return Verdict(
            ok=False, verdict=CONTENTS_MALFORMED, block_number=number,
            served_block_hash=served_hash,
            detail=f"block #{number} contents are not readable as a v2 payload: "
                   f"{type(e).__name__}: {e}")
