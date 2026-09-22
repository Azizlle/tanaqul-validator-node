"""ECDSA key generation, persistence, and block signing."""
import hashlib
import os
import logging
from ecdsa import SigningKey, NIST256p, BadSignatureError

logger = logging.getLogger("validator.crypto")


def load_or_create_key(path: str) -> SigningKey:
    """Load ECDSA key from disk; generate + persist if absent.

    The key persists in /data so the validator's identity survives restarts.
    Container must mount /data as a volume in production.
    """
    if os.path.exists(path):
        with open(path, "rb") as f:
            sk = SigningKey.from_pem(f.read())
        logger.info(f"Loaded existing signing key from {path}")
        return sk

    # Ensure parent dir exists
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    sk = SigningKey.generate(curve=NIST256p)
    pem = sk.to_pem()
    # Atomic write via tmpfile + rename
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(pem)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    logger.warning(f"Generated NEW signing key at {path}")
    return sk


def sign_message(sk: SigningKey, message: str) -> str:
    """Sign a pre-image VERBATIM. Returns a hex-encoded signature.

    ⛔ NO PREFIX STRIPPING, EVER. `sign_block_hash` strips a leading `0x` because a bare
    block hash is what the v1 pre-image is; the `tv2` and `tr2` pre-images are whole
    strings whose every character is committed, and stripping anything from one would
    produce a signature over bytes neither side can reconstruct.

    P2-003 2026-05-29: the hash function is pinned to SHA-256 (python-ecdsa defaults to
    SHA-1). It MUST match the backend's verifier, which uses
    `cryptography.hazmat.primitives.hashes.SHA256()`.
    """
    return sk.sign(message.encode("utf-8"), hashfunc=hashlib.sha256).hex()


def sign_block_hash(sk: SigningKey, block_hash: str) -> str:
    """Sign a bare block hash — the v1 attestation-of-receipt signature.

    The hash arrives as `0x…` and the backend verifies against it stripped, so the prefix
    comes off here. One signing implementation: this is `sign_message` with that one
    transformation named.
    """
    return sign_message(sk, block_hash[2:] if block_hash.startswith("0x") else block_hash)


def public_key_hex(sk: SigningKey) -> str:
    """Return uncompressed public key as hex (for backend registration)."""
    return sk.get_verifying_key().to_string().hex()
