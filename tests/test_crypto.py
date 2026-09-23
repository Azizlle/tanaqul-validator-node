"""Tests for src/crypto.py — key persistence and signing."""
import os
import tempfile
from src import crypto


def test_generate_and_persist_key():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "key.pem")
        sk1 = crypto.load_or_create_key(path)
        assert os.path.exists(path)
        # File mode is restrictive
        assert oct(os.stat(path).st_mode)[-3:] == "600"

        # Reload — should be the same key
        sk2 = crypto.load_or_create_key(path)
        assert sk1.to_pem() == sk2.to_pem()


def test_sign_block_hash_deterministic_length():
    with tempfile.TemporaryDirectory() as d:
        sk = crypto.load_or_create_key(os.path.join(d, "k.pem"))
        sig1 = crypto.sign_block_hash(sk, "0xabcdef")
        sig2 = crypto.sign_block_hash(sk, "0xabcdef")
        # ECDSA is randomized; sigs differ but length is fixed (NIST256p → 64 bytes → 128 hex)
        assert len(sig1) == 128
        assert len(sig2) == 128


def test_public_key_hex_format():
    with tempfile.TemporaryDirectory() as d:
        sk = crypto.load_or_create_key(os.path.join(d, "k.pem"))
        pk = crypto.public_key_hex(sk)
        assert len(pk) == 128  # NIST256p uncompressed → 64 bytes
        assert all(c in "0123456789abcdef" for c in pk)


def test_the_DIGEST_ALGORITHM_is_pinned_to_SHA_256():
    """⛔ ONE TOKEN BETWEEN WORKING AND A FLEET-WIDE SIGNING OUTAGE, AND NOTHING WATCHED IT.
    `python-ecdsa` defaults to **SHA-1**; the platform verifies with
    `ec.ECDSA(hashes.SHA256())`. Dropping `hashfunc=hashlib.sha256` left the whole suite
    green — every signature in the fleet rejected, every node reporting healthy, and no
    test anywhere noticing.

    ⚠️ AND THE AGREEMENT VECTORS STRUCTURALLY CANNOT SEE THIS. They pin the pre-image
    STRINGS; the digest algorithm is the one term of the signing contract that is not a
    string. The seam check is blind to it by construction, which is exactly why it needs
    its own test — and why the batch that rewrote this file was the moment it mattered.
    """
    import hashlib

    from ecdsa import SigningKey, SECP256k1, VerifyingKey
    from ecdsa.util import sigdecode_string

    sk = SigningKey.generate(curve=SECP256k1)
    msg = "tv2|1|aa|0xbb|0xcc|0xdd|0xee|0|1|0|TS|sys"
    sig = bytes.fromhex(crypto.sign_message(sk, msg))
    vk: VerifyingKey = sk.get_verifying_key()

    assert vk.verify(sig, msg.encode("utf-8"), hashfunc=hashlib.sha256,
                     sigdecode=sigdecode_string), "not verifiable under SHA-256"

    #: the control — the library's own default must NOT verify it, or this proves nothing
    import ecdsa
    try:
        ok_under_default = vk.verify(sig, msg.encode("utf-8"), sigdecode=sigdecode_string)
    except ecdsa.BadSignatureError:
        ok_under_default = False
    assert not ok_under_default, (
        "the signature verifies under python-ecdsa's default digest too, so this test "
        "cannot tell a pinned SHA-256 from an unpinned one")


def test_sign_block_hash_strips_0x_and_sign_message_does_NOT():
    """⚠️ ONE SIGNING IMPLEMENTATION, ONE NAMED TRANSFORMATION. The v1 pre-image is a bare
    hash; `tv2`/`tr2` are whole strings whose every character is committed, so stripping
    anything from one would sign bytes neither side can reconstruct.

    ⚠️ VERIFIED, NOT COMPARED. ECDSA signing is randomised — two signatures over identical
    bytes differ — so signature equality proves nothing here and would fail on correct
    code. Assert what the signature is OVER.
    """
    import hashlib

    from ecdsa import SigningKey, SECP256k1, BadSignatureError
    from ecdsa.util import sigdecode_string

    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()

    def _over(sig_hex: str, message: str) -> bool:
        try:
            return vk.verify(bytes.fromhex(sig_hex), message.encode("utf-8"),
                             hashfunc=hashlib.sha256, sigdecode=sigdecode_string)
        except BadSignatureError:
            return False

    assert _over(crypto.sign_block_hash(sk, "0xabcd"), "abcd"), "the 0x was not stripped"
    assert not _over(crypto.sign_block_hash(sk, "0xabcd"), "0xabcd")

    assert _over(crypto.sign_message(sk, "0xabcd"), "0xabcd"), "sign_message stripped a prefix"
    assert not _over(crypto.sign_message(sk, "0xabcd"), "abcd")
