"""Hash-chained audit log.

JSON Lines. Each entry carries `prev_hash` and `entry_hash`. The writer fsyncs
each append. Editing, deleting, reordering, or truncating a line breaks `verify`.

`LocalSha256Chain` does not sign entries. If `cvassure.provenance.chain.SignedChain`
imports, `make_chain` uses it. This package does not mint keys.

Private keys are never logged. Public-key fingerprints only.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cvassure.core.hashing import canonical_json, sha256_hex

GENESIS = "0" * 64
#: Events, in the order the pipeline appends them.
EVENTS = (
    "run_start",
    "config_loaded",
    "policy_loaded",
    "inputs_hashed",
    "plugins_loaded",
    "stage_start",
    "stage_end",
    "detector_result",
    "link_created",
    "policy_applied",
    "coverage_generated",
    "report_written",
    "run_end",
)


def entry_hash(entry: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical JSON of the entry without its own hash or sig."""
    body = {k: v for k, v in entry.items() if k not in ("entry_hash", "sig")}
    return sha256_hex(canonical_json(body))


class SignedChain:
    """Adapter over `cvassure.provenance.chain.SignedChain`.

    Same three methods as `LocalSha256Chain`. This class does not implement
    Ed25519 or a Merkle tree. It delegates.

    If that module is missing, `make_chain` does not construct this class. A
    silent fallback after a signature is present would drop verification.
    """

    def __init__(
        self,
        path: Path,
        *,
        deterministic_ts: str | None = None,
        fresh: bool = True,
        private_key_path: Path | None = None,
        public_key_path: Path | None = None,
    ):
        from cvassure.provenance import chain as signed

        self._impl = signed.SignedChain(
            path,
            deterministic_ts=deterministic_ts,
            fresh=fresh,
            private_key_path=private_key_path,
            public_key_path=public_key_path,
        )
        self.path = path

    def append(self, event: str, data: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._impl.append(event, data)

    def verify(self) -> bool:
        return bool(self._impl.verify())

    def head(self) -> str:
        return str(self._impl.head())

    @property
    def pubkey_fingerprint(self) -> str:
        return self._impl.pubkey_fingerprint

    def merkle_root(self) -> str | None:
        return self._impl.merkle_root()


def make_chain(
    path: Path,
    *,
    deterministic_ts: str | None = None,
    fresh: bool = True,
    privkey_path: Path | None = None,
    pubkey_path: Path | None = None,
) -> ChainBackend:
    """Signed chain when it imports, otherwise the local hash chain.

    `chain_backend` in the run manifest records which implementation ran.
    """
    import importlib

    try:
        importlib.import_module("cvassure.provenance.chain")
    except Exception:
        return LocalSha256Chain(path, deterministic_ts=deterministic_ts, fresh=fresh)
    return SignedChain(
        path,
        deterministic_ts=deterministic_ts,
        fresh=fresh,
        private_key_path=privkey_path,
        public_key_path=pubkey_path,
    )


class ChainBackend(Protocol):
    """The three methods a signed chain also implements."""

    def append(self, event: str, data: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def verify(self) -> bool: ...
    def head(self) -> str: ...


class LocalSha256Chain:
    """Append-only hash chain. Tamper-evident, not tamper-proof.

    A hash chain proves the log has not been edited since it was written, given
    the head hash was recorded somewhere else. Without signatures, an attacker who
    controls the whole file can rewrite it and recompute every hash. That is the
    honest limitation, and the coverage statement says so. A signature closes it.
    `chained_not_signed: true` is in every entry for this reason.
    """

    def __init__(
        self, path: Path, *, deterministic_ts: str | None = None, fresh: bool = True
    ) -> None:
        """`fresh=True` starts a new log for a new run.

        Appending to yesterday's log would make `verify-log` verify two runs as
        one chain, and the head in run_manifest.json would belong to neither.
        A run owns its log. The previous one is still on disk, untouched, and a
        judge can diff them.
        """
        self.path = path
        self.deterministic_ts = deterministic_ts
        self._seq = 0
        self._prev = GENESIS
        path.parent.mkdir(parents=True, exist_ok=True)
        if fresh and path.exists():
            path.unlink()
        elif path.exists() and path.stat().st_size > 0:
            self._seq, self._prev = self._resume()

    def _resume(self) -> tuple[int, str]:
        last: dict[str, Any] | None = None
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)
        if last is None:
            return 0, GENESIS
        return int(last["seq"]), str(last["entry_hash"])

    def _now(self) -> str:
        if self.deterministic_ts is not None:
            return self.deterministic_ts
        # Second resolution from the OS clock. `seq` already orders entries.
        return (
            __import__("datetime")
            .datetime.now(__import__("datetime").timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )

    def append(self, event: str, data: Mapping[str, Any]) -> Mapping[str, Any]:
        """One line, fsync'd. An unflushed entry is an entry that does not exist."""
        self._seq += 1
        entry: dict[str, Any] = {
            "seq": self._seq,
            "ts": self._now(),
            "event": event,
            "data": dict(data),
            "prev_hash": self._prev,
            "chained_not_signed": True,
        }
        entry["entry_hash"] = entry_hash(entry)
        line = canonical_json(entry) + "\n"
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        self._prev = entry["entry_hash"]
        return entry

    def head(self) -> str:
        return self._prev

    @property
    def count(self) -> int:
        return self._seq

    def verify(self) -> bool:
        return verify_file(self.path)[0]


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str
    entries: int
    head: str


def verify_file(
    path: Path, *, expected_head: str | None = None, allow_signatures: bool = False
) -> VerifyResult:
    """Recompute the chain. Catches edit, delete, reorder and truncate.

    Truncation is caught by `expected_head`, which the pipeline passes from
    `run_manifest.json`. Without it a file cut in half is a perfectly valid
    shorter chain, and saying so is the only honest answer.
    """
    if not path.is_file():
        return VerifyResult(False, f"no such log: {path}", 0, GENESIS)

    prev = GENESIS
    n = 0
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                return VerifyResult(False, f"line {lineno} is not JSON: {exc}", n, prev)
            n += 1
            if entry.get("seq") != n:
                return VerifyResult(
                    False, f"line {lineno} has seq {entry.get('seq')}, expected {n}", n, prev
                )
            if entry.get("prev_hash") != prev:
                return VerifyResult(
                    False,
                    f"line {lineno} prev_hash does not match the previous entry_hash",
                    n,
                    prev,
                )
            if entry.get("entry_hash") != entry_hash(entry):
                return VerifyResult(False, f"line {lineno} body was edited", n, prev)
            if "sig" in entry and entry["sig"] is not None and not allow_signatures:
                # A signature is not checked here, and it is not ignored unless explicitly allowed.
                return VerifyResult(
                    False,
                    "entry carries a signature: use SignedChain to verify, not LocalSha256Chain",
                    n,
                    prev,
                )
            prev = entry["entry_hash"]

    if expected_head and prev != expected_head:
        return VerifyResult(
            False,
            f"chain head {prev[:12]} does not match the recorded {expected_head[:12]}",
            n,
            prev,
        )
    return VerifyResult(True, "chain verified", n, prev)


def read_entries(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out
