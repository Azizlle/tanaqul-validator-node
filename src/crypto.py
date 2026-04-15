"""ECDSA key generation, persistence, and block signing."""
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


def sign_block_hash(sk: SigningKey, block_hash: str) -> str:
    """Sign a block hash. Returns hex-encoded signature."""
    # block_hash arrives as "0x..." — strip prefix before signing
    payload = block_hash[2:] if block_hash.startswith("0x") else block_hash
    sig = sk.sign(payload.encode("utf-8"))
    return sig.hex()


def public_key_hex(sk: SigningKey) -> str:
    """Return uncompressed public key as hex (for backend registration)."""
    return sk.get_verifying_key().to_string().hex()
