"""The node half of the cross-repo agreement run.

⛔ WHY TWO KINDS OF TEST EXIST FOR ONE PIECE OF ARITHMETIC, and why neither replaces the
other:

  * `test_verify.py` pins CORRECTNESS, from the documented rules — the empty root is
    sha256 of the word "empty", merkle pairs concatenate hex TEXT, `hash_timestamp` is
    used verbatim. Written from the spec so it fails if either side drifts toward a
    plausible-looking alternative.
  * THIS file pins AGREEMENT. `spec/agreement_vectors.json` is one artifact, run by this
    suite against the node's implementation and by the platform's cross-repo job against
    its own.

⚠️ WHICH SUITE CATCHES WHAT, stated exactly, because a vaguer sentence here was wrong. A
change to the PLATFORM's implementation reddens the platform's CI. A change to the NODE's
reddens this suite. A change that edits the node's code AND these vectors together agrees
with itself — and is caught by the correctness tests in `test_verify.py`, which are written
from the documented rules rather than from either implementation. "Both go red" was a
promise the mechanism does not make; the pair of test kinds is what actually holds.

Agreement alone would happily pin two copies of the same mistake; correctness alone would
let the two sides be independently right about different things. The pair is the check.

⚠️ AND THIS IS THE ONE PLACE A SECOND IMPLEMENTATION IS CORRECT. Everywhere else two
renderings of one truth is a defect waiting to drift. Here the node exists to check the
platform, so importing the platform's hashing would verify its arithmetic with its own
code and a bug would verify itself. Independent — but not unpinned, which is this file.
"""
import json
import os
import pathlib

import pytest

os.environ.setdefault("TANAQUL_VALIDATOR_ID", "ci")
os.environ.setdefault("TANAQUL_API_KEY", "ci")
os.environ.setdefault("TANAQUL_BACKEND_URL", "https://example.test")

from src import verify  # noqa: E402

VECTORS_PATH = pathlib.Path(__file__).resolve().parent.parent / "spec" / "agreement_vectors.json"
V = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

KINDS = ("sha256", "merkle_root", "match_leaf", "event_leaf", "tx_leaf",
         "hash_block_v2", "validation_payload", "refusal_payload",
         "effective_match_root", "carries_validatable_content",
         "block_is_validatable")


def _cases(kind):
    return [pytest.param(c, id=f"{kind}[{i}]") for i, c in enumerate(V[kind])]


@pytest.mark.parametrize("c", _cases("sha256"))
def test_sha256_vectors(c):
    assert verify.sha256(c["input"]) == c["output"]


@pytest.mark.parametrize("c", _cases("merkle_root"))
def test_merkle_root_vectors(c):
    assert verify.merkle_root(c["leaves"]) == c["output"]


@pytest.mark.parametrize("c", _cases("match_leaf"))
def test_match_leaf_vectors(c):
    assert verify.match_leaf(c["fields"]) == c["output"]


@pytest.mark.parametrize("c", _cases("event_leaf"))
def test_event_leaf_vectors(c):
    assert verify.event_leaf(c["fields"]) == c["output"]


@pytest.mark.parametrize("c", _cases("tx_leaf"))
def test_tx_leaf_vectors(c):
    assert verify.tx_leaf(c["fields"]) == c["output"]


@pytest.mark.parametrize("c", _cases("hash_block_v2"))
def test_hash_block_v2_vectors(c):
    assert verify.hash_block_v2(**c["fields"]) == c["output"]


@pytest.mark.parametrize("c", _cases("validation_payload"))
def test_validation_payload_vectors(c):
    assert verify.validation_payload(**c["fields"]) == c["output"]


@pytest.mark.parametrize("c", _cases("refusal_payload"))
def test_refusal_payload_vectors(c):
    assert verify.refusal_payload(**c["fields"]) == c["output"]


@pytest.mark.parametrize("c", _cases("effective_match_root"))
def test_effective_match_root_vectors(c):
    """⛔ THE RULE THAT COST THIS BATCH A ROUND. It lived as an inline conditional in one
    file and could therefore be pinned by nothing — the node disagreed with a correct
    genesis block and filed a signed accusation. It is a named function on both sides now,
    so the vectors carry it."""
    assert verify.effective_match_root(**c["fields"]) == c["output"]


@pytest.mark.parametrize("c", _cases("block_is_validatable"))
def test_block_is_validatable_vectors(c):
    """⛔ THE WHOLE CONDITION, not its format half. Answering it two ways is what let the
    node sign a pre-image the platform never tries."""
    assert verify.block_is_validatable(**c["fields"]) is c["output"]


@pytest.mark.parametrize("c", _cases("carries_validatable_content"))
def test_carries_validatable_content_vectors(c):
    """⛔ THE OTHER RULE WITH TWO RENDERINGS. `/contents` answered it one way and
    `sign_block` another; the node honoured the weaker and signed a pre-image the platform
    never tries."""
    assert verify.carries_validatable_content(**c["fields"]) is c["output"]


def test_the_vector_file_is_not_EMPTY_or_PARTIAL():
    """⛔ THE ENTRY WITNESS. Every test above is parametrized over the file, so an empty or
    truncated file produces ZERO test cases and a green suite — the shape where a check
    passes because nothing ran. Floors, not exact counts: adding a vector must not require
    editing a number, but losing a whole category must fail."""
    missing = [k for k in KINDS if not V.get(k)]
    assert not missing, f"vector categories absent — nothing was checked for: {missing}"
    total = sum(len(V[k]) for k in KINDS)
    assert total >= 20, f"only {total} vectors; the file has been truncated"


def test_every_vector_category_is_EXERCISED_by_a_test_in_this_file():
    """⚠️ A category added to the file and to no test is a vector nobody runs — it reads as
    coverage in a diff and checks nothing. This derives the exercised set from the module
    rather than from a list someone must remember to extend."""
    src = pathlib.Path(__file__).read_text(encoding="utf-8")
    exercised = {k for k in V if isinstance(V[k], list) and f'_cases("{k}")' in src}
    declared = {k for k in V if isinstance(V[k], list) and not k.startswith("_")}
    assert declared == exercised, f"vector categories with no test: {declared - exercised}"
