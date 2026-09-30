"""Tests for cvassure.provenance.chain — SignedChain."""

from __future__ import annotations

import json


def _make_keys(tmp_path):
    from cvassure.provenance.keys import generate_keypair, load_private, load_public

    priv_path, pub_path = generate_keypair(tmp_path / "k")
    return priv_path, pub_path, load_private(priv_path), load_public(pub_path)


# ── Basic construction ────────────────────────────────────────────────────────


def test_signed_chain_appends_and_verifies(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, sk, vk = _make_keys(tmp_path)
    chain = SignedChain(
        tmp_path / "audit.log", private_key_path=priv_path, public_key_path=pub_path
    )
    for i in range(5):
        chain.append(f"event_{i}", {"i": i})
    assert chain.verify() is True


def test_every_entry_has_sig(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    chain = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path)
    chain.append("run_start", {"tool_version": "0.1.0"})
    chain.append("run_end", {"status": "ok"})

    for line in log.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entry = json.loads(line)
            assert "sig" in entry and entry["sig"], "every entry must have sig"
            assert entry.get("chained_signed") is True


def test_entries_have_no_chained_not_signed(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    chain = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path)
    chain.append("event", {})

    entry = json.loads(log.read_text(encoding="utf-8").strip())
    assert "chained_not_signed" not in entry


def test_pubkey_fingerprint_in_every_entry(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    chain = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path)
    chain.append("event", {})
    fp = chain.pubkey_fingerprint
    entry = json.loads(log.read_text(encoding="utf-8").strip())
    assert entry["pubkey_fp"] == fp


def test_head_equals_last_entry_hash(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    chain = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path)
    for i in range(3):
        chain.append("e", {"i": i})

    last_hash = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])["entry_hash"]
    assert chain.head() == last_hash


# ── Deterministic timestamps ──────────────────────────────────────────────────


def test_deterministic_ts_mode(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    chain = SignedChain(
        log,
        private_key_path=priv_path,
        public_key_path=pub_path,
        deterministic_ts="1970-01-01T00:00:42Z",
    )
    chain.append("event", {})
    entry = json.loads(log.read_text(encoding="utf-8").strip())
    assert entry["ts"] == "1970-01-01T00:00:42Z"


# ── fresh=True clears old log ─────────────────────────────────────────────────


def test_fresh_true_deletes_old_log(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    c1 = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path, fresh=True)
    c1.append("old_event", {})
    c1.head()

    c2 = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path, fresh=True)
    c2.append("new_event", {})
    # Log only has 1 entry after fresh
    lines = [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1


# ── Tamper detection via verify() ─────────────────────────────────────────────


def test_verify_fails_on_tampered_entry(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    chain = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path)
    chain.append("event_a", {"x": 1})
    chain.append("event_b", {"x": 2})

    lines = log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["data"]["x"] = 99  # tamper
    lines[0] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    chain2 = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path, fresh=False)
    assert chain2.verify() is False


def test_verify_fails_on_missing_sig(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    chain = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path)
    chain.append("event", {})

    lines = log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    del entry["sig"]
    lines[0] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    chain2 = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path, fresh=False)
    assert chain2.verify() is False


# ── LocalSha256Chain refuses signed entries ───────────────────────────────────


def test_local_chain_refuses_signed_entries(tmp_path):
    """An entry with sig= must not pass LocalSha256Chain verification."""
    from cvassure.core.audit import verify_file
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    chain = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path)
    chain.append("signed_event", {})

    result = verify_file(log)
    assert result.ok is False
    assert "signature" in result.reason.lower() or "SignedChain" in result.reason


# ── Merkle integration ────────────────────────────────────────────────────────


def test_merkle_root_is_string_when_enabled(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    chain = SignedChain(
        tmp_path / "log", private_key_path=priv_path, public_key_path=pub_path, use_merkle=True
    )
    chain.append("e", {})
    chain.append("f", {})
    root = chain.merkle_root()
    assert isinstance(root, str) and len(root) == 64


def test_merkle_root_is_none_when_disabled(tmp_path):
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path, *_ = _make_keys(tmp_path)
    chain = SignedChain(
        tmp_path / "log", private_key_path=priv_path, public_key_path=pub_path, use_merkle=False
    )
    chain.append("e", {})
    assert chain.merkle_root() is None


# ── Ephemeral key fallback ────────────────────────────────────────────────────


def test_ephemeral_chain_still_signs(tmp_path):
    """No key paths → ephemeral key, but entries still get signed."""
    import warnings

    from cvassure.provenance.chain import SignedChain

    log = tmp_path / "log"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        chain = SignedChain(log)
        chain.append("event", {})

    lines = log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    assert "sig" in entry and entry["sig"]
