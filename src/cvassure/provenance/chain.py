"""Signed audit-log chain.

Implements the same three-method interface as ``LocalSha256Chain``
(append, verify, head) but adds Ed25519 signatures to every entry and
optionally builds a Merkle tree over the entry_hash values.

``make_chain()`` in ``audit.py`` tries::

    importlib.import_module("cvassure.provenance.chain")

and uses this class when it imports. If the import fails (PyNaCl not
installed) the unsigned fallback is used automatically.

An entry written by ``SignedChain`` carries:
  - ``chained_signed: true`` (instead of ``chained_not_signed: true``)
  - ``sig``: 64-byte Ed25519 signature, hex-encoded
  - ``pubkey_fp``: fingerprint of the signing key (SHA-256, first 16 hex)

``LocalSha256Chain.verify()`` refuses entries with a ``sig`` field, so
the two backends can never silently pass each other's logs.
"""

from __future__ import annotations

import json
import os
import tempfile
import warnings
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cvassure.core.hashing import canonical_json, sha256_hex

GENESIS = "0" * 64


def _entry_hash(entry: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical JSON of the entry minus entry_hash and sig."""
    body = {k: v for k, v in entry.items() if k not in ("entry_hash", "sig")}
    return sha256_hex(canonical_json(body))


class SignedChain:
    """Append-only signed audit log chain.

    Loads Ed25519 keys from ``private_key_path`` and ``public_key_path``.
    If neither is given, an ephemeral keypair is generated and a warning
    is emitted — the log is still signed, but the key is not persisted
    for later verification by a third party.

    Optionally builds a Merkle tree (``use_merkle=True``) over the
    entry_hash values. The Merkle root is included in the ``run_end``
    entry when present.
    """

    def __init__(
        self,
        path: Path,
        *,
        deterministic_ts: str | None = None,
        fresh: bool = True,
        private_key_path: Path | None = None,
        public_key_path: Path | None = None,
        use_merkle: bool = True,
    ) -> None:
        from cvassure.provenance.keys import fingerprint, load_private, load_public

        self.path = path
        self.deterministic_ts = deterministic_ts
        self._seq = 0
        self._prev = GENESIS
        self._merkle = None
        self._ephemeral_dir = None

        # Key setup
        if private_key_path and public_key_path:
            self._sk = load_private(private_key_path)
            self._vk = load_public(public_key_path)
        elif private_key_path:
            self._sk = load_private(private_key_path)
            self._vk = self._sk.verify_key
        else:
            warnings.warn(
                "No key paths given to SignedChain. Generating an ephemeral keypair. "
                "The log is signed, but verification requires the ephemeral public key.",
                stacklevel=2,
            )
            from cvassure.provenance.keys import generate_keypair

            self._ephemeral_dir = tempfile.mkdtemp(prefix="cvassure_ephemeral_")
            ep = Path(self._ephemeral_dir) / "ephemeral"
            generate_keypair(ep)
            self._sk = load_private(ep.with_suffix(".key"))
            self._vk = load_public(ep.with_suffix(".pub"))

        self._pubkey_fp = fingerprint(bytes(self._vk))

        # Merkle tree
        if use_merkle:
            from cvassure.provenance.merkle import MerkleTree

            self._merkle = MerkleTree()

        # Log file setup
        path.parent.mkdir(parents=True, exist_ok=True)
        if fresh and path.exists():
            path.unlink()
        elif path.exists() and path.stat().st_size > 0:
            self._seq, self._prev = self._resume()

    def _resume(self) -> tuple[int, str]:
        """Resume from an existing log file."""
        last: dict[str, Any] | None = None
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    last = rec
                    if self._merkle is not None:
                        eh = rec.get("entry_hash", "")
                        if eh:
                            self._merkle.add_leaf(eh)
        if last is None:
            return 0, GENESIS
        return int(last["seq"]), str(last["entry_hash"])

    def _now(self) -> str:
        if self.deterministic_ts is not None:
            return self.deterministic_ts
        return (
            __import__("datetime")
            .datetime.now(__import__("datetime").timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )

    def append(self, event: str, data: Mapping[str, Any]) -> Mapping[str, Any]:
        """Build, sign, and fsync one entry."""
        from cvassure.provenance.keys import sign

        self._seq += 1
        entry: dict[str, Any] = {
            "seq": self._seq,
            "ts": self._now(),
            "event": event,
            "data": dict(data),
            "prev_hash": self._prev,
            "pubkey_fp": self._pubkey_fp,
            "chained_signed": True,
        }
        entry["entry_hash"] = _entry_hash(entry)

        # Sign the canonical body (everything except "sig")
        body_bytes = canonical_json({k: v for k, v in entry.items() if k != "sig"}).encode("utf-8")
        entry["sig"] = sign(self._sk, body_bytes)

        line = canonical_json(entry) + "\n"
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

        self._prev = entry["entry_hash"]
        if self._merkle is not None:
            self._merkle.add_leaf(entry["entry_hash"])
        return entry

    def head(self) -> str:
        """The entry_hash of the last written entry."""
        return self._prev

    def merkle_root(self) -> str | None:
        """Current Merkle root, or None if the tree is not in use."""
        if self._merkle is None:
            return None
        return self._merkle.root()

    def verify(self) -> bool:
        """Verify the hash chain and every Ed25519 signature.

        Returns True if everything checks out.
        """
        from cvassure.provenance.keys import verify

        if not self.path.is_file():
            return False

        prev = GENESIS
        n = 0
        with open(self.path, encoding="utf-8") as fh:
            for _lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False
                n += 1
                # Sequence
                if entry.get("seq") != n:
                    return False
                # Chain linkage
                if entry.get("prev_hash") != prev:
                    return False
                # Entry hash
                if entry.get("entry_hash") != _entry_hash(entry):
                    return False
                # Signature
                sig = entry.get("sig")
                if not sig:
                    return False  # unsigned entry in a signed chain
                body = {k: v for k, v in entry.items() if k != "sig"}
                body_bytes = canonical_json(body).encode("utf-8")
                if not verify(self._vk, body_bytes, sig):
                    return False
                prev = entry["entry_hash"]
        return n > 0 or self._seq == 0

    @property
    def pubkey_fingerprint(self) -> str:
        """Public-key fingerprint embedded in every signed entry."""
        return self._pubkey_fp
