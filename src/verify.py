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

OK = "OK"
HASH_MISMATCH = "HASH_MISMATCH"
PREV_HASH_MISMATCH = "PREV_HASH_MISMATCH"
COUNT_MISMATCH = "COUNT_MISMATCH"
CONTENTS_MALFORMED = "CONTENTS_MALFORMED"
UNVALIDATABLE = "UNVALIDATABLE"


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
                         CONTENTS_MALFORMED)


def _check_block(contents: dict, served_hash: str, last_seen_hash: str | None) -> Verdict:
    """Recompute a block from its served leaves and judge it.

    `served_hash` is the block hash the PLATFORM stores (from `/pending-blocks`), never
    anything out of `contents` — comparing a payload against itself proves nothing.

    `last_seen_hash` is the hash of the last block THIS node verified, or None when it
    has no history. ⚠️ None admits the block: a node that refuses everything until it
    has a predecessor can never acquire one, and a refusal with no path to retry is a
    deletion, not a check.
    """
    number = int(contents["block_number"])

    #: ⛔ PRE-v2 BLOCKS CANNOT BE RECOMPUTED — v1 hashed a timestamp that was
    #: never persisted, so no arithmetic here can reach their committed hash. Checked
    #: FIRST, before anything is computed from them, so the node never reports a
    #: mismatch it manufactured out of a format it cannot read.
    if not contents.get("validatable") or int(contents.get("format_version", 1)) < 2:
        return Verdict(
            ok=False, verdict=UNVALIDATABLE, block_number=number,
            served_block_hash=served_hash,
            detail=f"block #{number} is format_version "
                   f"{contents.get('format_version')}; v1 blocks carry no recomputable "
                   f"hash. Not a disagreement — the node cannot check this block.")

    counts = contents["counts"]
    matches, events, txs = (contents["match_leaves"], contents["event_leaves"],
                            contents["tx_leaves"])

    #: ⛔ THE COUNTS ARE HASHED SEPARATELY FROM THE ROOTS, so a payload whose counts
    #: disagree with its own leaf lists is incoherent before any hashing happens. It
    #: would surface as a hash mismatch anyway; naming it distinctly is the difference
    #: between a refusal report that can be acted on and one that says only "no".
    served_counts = (int(counts["match_count"]), int(counts["event_count"]),
                     int(counts["tx_count"]))
    actual_counts = (len(matches), len(events), len(txs))
    if served_counts != actual_counts:
        return Verdict(
            ok=False, verdict=COUNT_MISMATCH, block_number=number,
            served_block_hash=served_hash,
            detail=f"block #{number} declares counts {served_counts} "
                   f"(match, event, tx) and served {actual_counts} leaves.")

    match_root = merkle_root([sha256(match_leaf(f)) for f in matches])
    event_root = merkle_root([sha256(event_leaf(f)) for f in events])
    tx_root = merkle_root([sha256(tx_leaf(f)) for f in txs])

    computed = hash_block_v2(
        number=number,
        prev_hash=contents["prev_hash"],
        match_root=match_root,
        event_root=event_root,
        tx_root=tx_root,
        match_count=served_counts[0],
        event_count=served_counts[1],
        tx_count=served_counts[2],
        hash_timestamp=contents["hash_timestamp"],
        creator_id=contents["creator_id"],
    )

    #: everything the `tr2` pre-image commits, computed once and carried on every verdict
    #: built from here down
    _roots = dict(match_root=match_root, event_root=event_root, tx_root=tx_root,
                  match_count=served_counts[0], event_count=served_counts[1],
                  tx_count=served_counts[2],
                  hash_timestamp=contents["hash_timestamp"],
                  creator_id=contents["creator_id"])

    #: ⛔ THE CHECK THIS MODULE EXISTS FOR. Until now the node signed `served_hash`
    #: itself, so a block whose stored hash was internally consistent but whose CONTENT
    #: differed from what was sealed passed unchallenged — there was nothing to
    #: challenge it with.
    if computed != served_hash:
        return Verdict(
            ok=False, verdict=HASH_MISMATCH, block_number=number,
            served_block_hash=served_hash, computed_block_hash=computed, **_roots,
            detail=f"block #{number} hashes to {computed} from its own served leaves; "
                   f"the platform stores {served_hash}.")

    #: ⛔ A SECOND, INDEPENDENT PROPERTY. A block can be internally perfect and still
    #: not follow the block this node last verified — which is what a fork, a rollback
    #: or a replayed history looks like from here.
    #: ⚠️ Genesis has no predecessor and a node with no history has no opinion; neither
    #: is a disagreement.
    if last_seen_hash is not None and not contents.get("is_genesis"):
        if contents["prev_hash"] != last_seen_hash:
            return Verdict(
                ok=False, verdict=PREV_HASH_MISMATCH, block_number=number,
                served_block_hash=served_hash, computed_block_hash=computed,
                served_prev_hash=contents["prev_hash"],
                expected_prev_hash=last_seen_hash, **_roots,
                detail=f"block #{number} follows {contents['prev_hash']}; this node "
                       f"last verified {last_seen_hash}.")

    return Verdict(ok=True, verdict=OK, block_number=number,
                   served_block_hash=served_hash, computed_block_hash=computed,
                   served_prev_hash=contents["prev_hash"], **_roots)


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
    CONTENTS_MALFORMED: "CONTENTS_MALFORMED",
    UNVALIDATABLE: "FORMAT_NOT_VALIDATABLE",
}


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


def check_block(contents: dict, served_hash: str, last_seen_hash: str | None) -> Verdict:
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
        return _check_block(contents, served_hash, last_seen_hash)
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
