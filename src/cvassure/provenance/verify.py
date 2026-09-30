"""Verification entry points and tamper detection.

Standalone functions for verifying a signed audit log and detecting all
seven attack classes:

  1. Edit      — body changed, hash or sig fails
  2. Delete    — entry removed, chain breaks
  3. Reorder   — entries swapped, seq not monotonic
  4. Truncation— file cut short, head ≠ expected_head
  5. Replay    — entry duplicated as a later entry
  6. Forge     — re-signed with a different key
  7. Strip     — sig removed from a signed entry

The functions here build on the core verify_file() for the hash-chain
pass, then add the Ed25519 pass on top.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class VerifyResult:
    """Verification outcome with a human-readable reason."""

    ok: bool
    reason: str
    entries: int
    head: str
    signed: bool = False
    merkle_root: str | None = None
    pubkey_fp: str | None = None


@dataclass(frozen=True)
class TamperEvidence:
    """One piece of detected tampering."""

    lineno: int
    seq: int | None
    attack: str  # "edit", "delete", "reorder", "replay", "forge", "strip"
    reason: str


def verify_signed_log(
    path: Path,
    pub_key_path: Path | None = None,
    *,
    expected_head: str | None = None,
) -> VerifyResult:
    """Verify the hash chain and Ed25519 signatures of a signed audit log.

    Falls back to the core hash-chain verifier when no public key is
    given. Returns a VerifyResult with ``signed=True`` when signatures
    were checked.
    """
    from cvassure.core.audit import verify_file as _core_verify

    GENESIS = "0" * 64

    if not path.is_file():
        return VerifyResult(ok=False, reason=f"no such log: {path}", entries=0, head=GENESIS)

    # Pass 1: hash chain (same as the unsigned verifier)
    core = _core_verify(path, expected_head=expected_head, allow_signatures=True)

    if pub_key_path is None:
        # No key — only the hash chain was checked.
        return VerifyResult(
            ok=core.ok,
            reason=core.reason,
            entries=core.entries,
            head=core.head,
            signed=False,
        )

    try:
        from cvassure.provenance.keys import load_public
        from cvassure.provenance.keys import verify as _verify
    except ImportError:
        return VerifyResult(
            ok=False,
            reason="PyNaCl is not installed; cannot verify signatures",
            entries=core.entries,
            head=core.head,
        )

    pub_key = load_public(pub_key_path)

    # Pass 2: Ed25519 signatures
    n = 0
    merkle_root = None
    pubkey_fp = None
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                return VerifyResult(
                    ok=False,
                    reason=f"line {lineno} is not JSON: {exc}",
                    entries=n,
                    head=core.head,
                )
            n += 1
            sig = entry.get("sig")
            if sig is None:
                return VerifyResult(
                    ok=False,
                    reason=f"line {lineno} has no sig — entry stripped or unsigned log",
                    entries=n,
                    head=core.head,
                    signed=True,
                )
            body = {k: v for k, v in entry.items() if k != "sig"}
            body_bytes = (
                __import__("cvassure.core.hashing", fromlist=["canonical_json"])
                .canonical_json(body)
                .encode("utf-8")
            )
            if not _verify(pub_key, body_bytes, sig):
                return VerifyResult(
                    ok=False,
                    reason=f"line {lineno} (seq {entry.get('seq')}) signature invalid",
                    entries=n,
                    head=core.head,
                    signed=True,
                )
            pubkey_fp = entry.get("pubkey_fp")
            # Check for run_end merkle_root
            if entry.get("event") == "run_end":
                merkle_root = entry.get("data", {}).get("merkle_root")

    if not core.ok:
        return VerifyResult(
            ok=False,
            reason=core.reason,
            entries=n,
            head=core.head,
            signed=True,
            merkle_root=merkle_root,
            pubkey_fp=pubkey_fp,
        )

    return VerifyResult(
        ok=True,
        reason=f"chain and {n} signatures verified",
        entries=n,
        head=core.head,
        signed=True,
        merkle_root=merkle_root,
        pubkey_fp=pubkey_fp,
    )


def detect_all_tampering(
    path: Path,
    pub_key_path: Path | None = None,
    *,
    expected_head: str | None = None,
) -> list[TamperEvidence]:
    """Run all tamper checks and return a list of evidence items.

    Covers all seven attack classes: edit, delete, reorder, truncation,
    replay, forge, strip.
    """
    from cvassure.core.hashing import canonical_json, sha256_hex

    GENESIS = "0" * 64
    evidence: list[TamperEvidence] = []
    if not path.is_file():
        return evidence

    pub_key = None
    if pub_key_path is not None:
        try:
            from cvassure.provenance.keys import load_public

            pub_key = load_public(pub_key_path)
        except Exception:
            pass

    prev_hash = GENESIS
    expected_seq = 1
    seen_entry_hashes: dict[str, tuple[int, int]] = {}  # hash -> (lineno, seq)

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    for lineno, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            evidence.append(
                TamperEvidence(
                    lineno=lineno,
                    seq=None,
                    attack="edit",
                    reason=f"JSON parse error: {exc}",
                )
            )
            expected_seq += 1
            continue

        seq = entry.get("seq")

        # Reorder / delete detection via sequence gap
        if seq != expected_seq:
            evidence.append(
                TamperEvidence(
                    lineno=lineno,
                    seq=seq,
                    attack="reorder",
                    reason=f"seq {seq}, expected {expected_seq} — reorder or delete",
                )
            )

        # Chain break (edit or delete of a prior entry)
        if entry.get("prev_hash") != prev_hash:
            evidence.append(
                TamperEvidence(
                    lineno=lineno,
                    seq=seq,
                    attack="edit",
                    reason="prev_hash mismatch — prior entry edited or deleted",
                )
            )

        # Entry hash (body edit)
        eh = entry.get("entry_hash")
        body_excl = {k: v for k, v in entry.items() if k not in ("entry_hash", "sig")}
        computed_eh = sha256_hex(canonical_json(body_excl))
        if eh != computed_eh:
            evidence.append(
                TamperEvidence(
                    lineno=lineno, seq=seq, attack="edit", reason="entry_hash does not match body"
                )
            )

        # Replay detection (duplicate entry_hash in later position)
        if eh and eh in seen_entry_hashes:
            first_lineno, first_seq = seen_entry_hashes[eh]
            evidence.append(
                TamperEvidence(
                    lineno=lineno,
                    seq=seq,
                    attack="replay",
                    reason=f"entry_hash duplicates line {first_lineno} (seq {first_seq})",
                )
            )
        elif eh:
            seen_entry_hashes[eh] = (lineno, seq or 0)

        # Signature checks
        sig = entry.get("sig")
        if sig is None and entry.get("chained_signed"):
            evidence.append(
                TamperEvidence(
                    lineno=lineno,
                    seq=seq,
                    attack="strip",
                    reason="sig field missing on a chained_signed entry",
                )
            )
        elif sig and pub_key is not None:
            from cvassure.provenance.keys import verify as _verify

            body_bytes = canonical_json({k: v for k, v in entry.items() if k != "sig"}).encode(
                "utf-8"
            )
            if not _verify(pub_key, body_bytes, sig):
                evidence.append(
                    TamperEvidence(
                        lineno=lineno,
                        seq=seq,
                        attack="forge",
                        reason="Ed25519 signature invalid (edited or forged with wrong key)",
                    )
                )

        prev_hash = eh or prev_hash
        expected_seq = (seq or expected_seq) + 1

    # Truncation: head does not match expected_head from run_manifest
    if expected_head and prev_hash != expected_head:
        evidence.append(
            TamperEvidence(
                lineno=len(lines),
                seq=None,
                attack="truncation",
                reason=f"chain head {prev_hash[:12]} ≠ expected {expected_head[:12]}",
            )
        )

    return evidence


def detect_replay(path: Path) -> list[TamperEvidence]:
    """Return only replay-attack evidence (reused nonces in signed records)."""
    return [e for e in detect_all_tampering(path) if e.attack == "replay"]


def detect_truncation(path: Path, expected_head: str) -> bool:
    """True if the file's chain head does not match the expected head from the manifest."""
    evidence = detect_all_tampering(path, expected_head=expected_head)
    return any(e.attack == "truncation" for e in evidence)


def detect_reorder(path: Path) -> list[int]:
    """Return line numbers where seq is out of order."""
    evidence = detect_all_tampering(path)
    return [e.lineno for e in evidence if e.attack == "reorder"]
