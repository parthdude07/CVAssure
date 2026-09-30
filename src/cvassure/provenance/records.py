"""Signed inference records.

Each record is a canonical JSON line with:
  seq, ts, input_hash, model_digest, config_hash, output, nonce,
  prev_hash, entry_hash, sig, pubkey_fp

The chain works exactly like the audit log: each entry hashes the
previous entry_hash, and a signature covers the canonical body.

A record whose signature fails or whose entry_hash does not match the
body is detected by ``detect_edit``. A record with a reused nonce is
detected by ``detect_replay``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cvassure.core.hashing import canonical_json, sha256_hex

GENESIS = "0" * 64


def _entry_hash(entry: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON of the entry, excluding entry_hash and sig."""
    body = {k: v for k, v in entry.items() if k not in ("entry_hash", "sig")}
    return sha256_hex(canonical_json(body))


def sign_record(
    *,
    seq: int,
    ts: str,
    input_hash: str,
    model_digest: str,
    config_hash: str,
    output: Any,
    nonce: str,
    prev_hash: str,
    private_key,
    public_key,
) -> dict[str, Any]:
    """Build, hash, and sign one inference record.

    Args:
        private_key: nacl.signing.SigningKey
        public_key: nacl.signing.VerifyKey (used to derive fingerprint)

    Returns the complete signed record dict.
    """
    from cvassure.provenance.keys import fingerprint, sign

    entry: dict[str, Any] = {
        "seq": seq,
        "ts": ts,
        "input_hash": input_hash,
        "model_digest": model_digest,
        "config_hash": config_hash,
        "output": output,
        "nonce": nonce,
        "prev_hash": prev_hash,
        "pubkey_fp": fingerprint(bytes(public_key)),
        "chained_signed": True,
    }
    entry["entry_hash"] = _entry_hash(entry)
    body_bytes = canonical_json({k: v for k, v in entry.items() if k != "sig"}).encode("utf-8")
    entry["sig"] = sign(private_key, body_bytes)
    return entry


def verify_record(record: dict[str, Any], public_key) -> bool:
    """Return True if entry_hash and sig both verify.

    A record with a missing or null sig is not a signed record — returns False.
    """
    from cvassure.provenance.keys import verify

    sig = record.get("sig")
    if not sig:
        return False
    # Recompute entry_hash
    if record.get("entry_hash") != _entry_hash(record):
        return False
    body = {k: v for k, v in record.items() if k != "sig"}
    body_bytes = canonical_json(body).encode("utf-8")
    return verify(public_key, body_bytes, sig)


@dataclass(frozen=True)
class EditEvidence:
    """One detected edit or signature failure."""

    lineno: int
    seq: int | None
    reason: str


@dataclass(frozen=True)
class ReplayEvidence:
    """One detected replay (reused nonce or duplicate entry)."""

    lineno: int
    seq: int | None
    nonce: str
    reason: str


def write_signed_records(
    path: Path, records_data: list[dict[str, Any]], private_key, public_key
) -> None:
    """Write a chain of signed inference records to a JSONL file.

    ``records_data`` is a list of dicts, each with keys:
    ``input_hash``, ``model_digest``, ``config_hash``, ``output``.
    ``ts``, ``nonce``, and ``seq`` are assigned here.
    """
    import secrets

    path.parent.mkdir(parents=True, exist_ok=True)
    prev = GENESIS
    lines = []
    for i, data in enumerate(records_data, 1):
        ts = data.get("ts", f"2026-01-01T00:00:{i % 60:02d}Z")
        nonce = data.get("nonce", secrets.token_hex(16))
        entry = sign_record(
            seq=i,
            ts=ts,
            input_hash=data.get("input_hash", ""),
            model_digest=data.get("model_digest", ""),
            config_hash=data.get("config_hash", ""),
            output=data.get("output", {}),
            nonce=nonce,
            prev_hash=prev,
            private_key=private_key,
            public_key=public_key,
        )
        prev = entry["entry_hash"]
        lines.append(canonical_json(entry))

    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def detect_edit(path: Path, public_key) -> list[EditEvidence]:
    """Return evidence of edited records (hash or signature fails).

    Does NOT verify the chain linkage — that is detect_chain_break.
    """
    evidence = []
    if not path.is_file():
        return evidence
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            evidence.append(
                EditEvidence(
                    lineno=lineno,
                    seq=None,
                    reason=f"JSON parse error: {exc}",
                )
            )
            continue
        seq = rec.get("seq")
        # Check entry_hash
        if rec.get("entry_hash") != _entry_hash(rec):
            evidence.append(
                EditEvidence(lineno=lineno, seq=seq, reason="entry_hash does not match body")
            )
            continue
        # Check signature
        if rec.get("sig") and not verify_record(rec, public_key):
            evidence.append(
                EditEvidence(lineno=lineno, seq=seq, reason="Ed25519 signature invalid")
            )
    return evidence


def detect_replay(path: Path) -> list[ReplayEvidence]:
    """Return evidence of replayed records (reused nonce).

    A nonce that appears more than once means a record was copied and
    re-submitted (replay attack).
    """
    if not path.is_file():
        return []
    seen_nonces: dict[str, tuple[int, int]] = {}  # nonce -> (lineno, seq)
    evidence = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        nonce = rec.get("nonce")
        seq = rec.get("seq")
        if nonce and nonce in seen_nonces:
            first_lineno, first_seq = seen_nonces[nonce]
            evidence.append(
                ReplayEvidence(
                    lineno=lineno,
                    seq=seq,
                    nonce=nonce,
                    reason=(
                        f"nonce {nonce!r} already used at line {first_lineno} "
                        f"(seq {first_seq}) — replay detected"
                    ),
                )
            )
        elif nonce:
            seen_nonces[nonce] = (lineno, seq)
    return evidence


def detect_chain_break(path: Path) -> list[EditEvidence]:
    """Return evidence of chain linkage failures (prev_hash mismatch or seq gap)."""
    if not path.is_file():
        return []
    prev = GENESIS
    expected_seq = 1
    evidence = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            evidence.append(EditEvidence(lineno=lineno, seq=None, reason="JSON parse error"))
            expected_seq += 1
            continue
        seq = rec.get("seq")
        if seq != expected_seq:
            evidence.append(
                EditEvidence(lineno=lineno, seq=seq, reason=f"seq {seq}, expected {expected_seq}")
            )
        if rec.get("prev_hash") != prev:
            evidence.append(
                EditEvidence(
                    lineno=lineno, seq=seq, reason="prev_hash does not match previous entry_hash"
                )
            )
        prev = rec.get("entry_hash", prev)
        expected_seq += 1
    return evidence


def read_records(path: Path) -> list[dict[str, Any]]:
    """Read all records from a JSONL file. Returns an empty list if missing."""
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out
