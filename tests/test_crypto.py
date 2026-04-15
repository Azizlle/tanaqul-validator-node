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
