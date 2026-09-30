"""Ed25519 key management.

Generate, save, and load Ed25519 signing keys. Uses PyNaCl (``nacl`` package).

Private key bytes are never written to a log, a finding, or a report.
Only the fingerprint (SHA-256 of the public key bytes, first 16 hex chars)
appears in signed entries.

Key files are raw hex-encoded bytes. Not PEM, not JWK. The format is
one line: 64 hex chars for the private key, 32 hex chars for the public key.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def generate_keypair(path: Path) -> tuple[Path, Path]:
    """Write ``<path>.key`` and ``<path>.pub``.

    Returns the two paths (private, public). The private key file is 64
    hex chars (32-byte seed). The public key file is 32 hex chars.

    Overwrites existing files.
    """
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    priv_path = path.with_suffix(".key") if path.suffix != ".key" else path
    pub_path = path.with_suffix(".pub") if path.suffix != ".pub" else Path(str(path)[:-4] + ".pub")
    # Ensure the base name is shared even if path has no suffix
    base = path.with_suffix("")
    priv_path = base.with_suffix(".key")
    pub_path = base.with_suffix(".pub")

    priv_path.parent.mkdir(parents=True, exist_ok=True)
    # bytes(sk) is the 32-byte seed; the verify key is sk.verify_key
    priv_path.write_text(bytes(sk).hex() + "\n", encoding="utf-8")
    pub_path.write_text(bytes(sk.verify_key).hex() + "\n", encoding="utf-8")
    return priv_path, pub_path


def load_private(path: Path):
    """Load an Ed25519 SigningKey from a .key file (32-byte hex seed).

    Returns a ``nacl.signing.SigningKey``.
    """
    from nacl.signing import SigningKey

    raw = path.read_text(encoding="utf-8").strip()
    seed = bytes.fromhex(raw)
    if len(seed) != 32:
        raise ValueError(f"private key at {path} must be 32 bytes (64 hex chars), got {len(seed)}")
    return SigningKey(seed)


def load_public(path: Path):
    """Load an Ed25519 VerifyKey from a .pub file (32-byte hex).

    Returns a ``nacl.signing.VerifyKey``.
    """
    from nacl.signing import VerifyKey

    raw = path.read_text(encoding="utf-8").strip()
    key_bytes = bytes.fromhex(raw)
    if len(key_bytes) != 32:
        raise ValueError(
            f"public key at {path} must be 32 bytes (64 hex chars), got {len(key_bytes)}"
        )
    return VerifyKey(key_bytes)


def fingerprint(pub_key_bytes: bytes) -> str:
    """SHA-256 of the public key bytes, first 16 hex chars.

    This is what appears in signed entries. The private key is never logged.
    """
    return hashlib.sha256(pub_key_bytes).hexdigest()[:16]


def sign(sk, data: bytes) -> str:
    """Sign bytes with an Ed25519 SigningKey. Returns hex-encoded 64-byte signature."""
    signed = sk.sign(data)
    # signed.signature is the 64-byte detached signature
    return signed.signature.hex()


def verify(pub_key, data: bytes, sig_hex: str) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    from nacl.exceptions import BadSignatureError

    try:
        sig_bytes = bytes.fromhex(sig_hex)
        pub_key.verify(data, sig_bytes)
        return True
    except (BadSignatureError, ValueError):
        return False
