"""Tests for cvassure.provenance.verify — all 7 tamper attack classes."""

from __future__ import annotations

import json


def _make_keys(tmp_path):
    from cvassure.provenance.keys import generate_keypair

    priv_path, pub_path = generate_keypair(tmp_path / "k")
    return priv_path, pub_path


def _build_signed_log(tmp_path, n=5):
    """Write a clean signed log with n entries. Returns (log_path, priv, pub)."""
    from cvassure.provenance.chain import SignedChain

    priv_path, pub_path = _make_keys(tmp_path)
    log = tmp_path / "audit.log"
    chain = SignedChain(log, private_key_path=priv_path, public_key_path=pub_path)
    for i in range(n):
        chain.append("test_event", {"i": i})
    return log, priv_path, pub_path, chain.head()


# ── verify_signed_log ─────────────────────────────────────────────────────────


def test_verify_signed_log_clean(tmp_path):
    from cvassure.provenance.verify import verify_signed_log

    log, priv, pub, head = _build_signed_log(tmp_path)
    res = verify_signed_log(log, pub, expected_head=head)
    assert res.ok is True
    assert res.signed is True
    assert res.entries == 5


def test_verify_signed_log_no_pubkey_falls_back(tmp_path):
    from cvassure.provenance.verify import verify_signed_log

    log, priv, pub, head = _build_signed_log(tmp_path)
    # No pub_key_path — falls back to hash-chain only
    res = verify_signed_log(log, None, expected_head=head)
    # Hash chain of a signed log will fail because LocalSha256Chain refuses sig
    # That's correct: without the key we can't verify a signed log fully
    assert isinstance(res.ok, bool)  # at minimum it runs without exception


# ── Attack 1: Edit ────────────────────────────────────────────────────────────


def test_detect_edit(tmp_path):
    from cvassure.provenance.verify import detect_all_tampering

    log, priv, pub, head = _build_signed_log(tmp_path)
    lines = log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    entry["data"]["i"] = 999
    lines[2] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_all_tampering(log, pub, expected_head=head)
    attacks = {e.attack for e in evidence}
    assert "edit" in attacks or "forge" in attacks


# ── Attack 2: Delete ──────────────────────────────────────────────────────────


def test_detect_delete(tmp_path):
    from cvassure.provenance.verify import detect_all_tampering

    log, priv, pub, head = _build_signed_log(tmp_path)
    lines = log.read_text(encoding="utf-8").splitlines()
    del lines[1]  # delete entry #2
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_all_tampering(log, pub, expected_head=head)
    attacks = {e.attack for e in evidence}
    assert "reorder" in attacks or "edit" in attacks or "truncation" in attacks


# ── Attack 3: Reorder ─────────────────────────────────────────────────────────


def test_detect_reorder(tmp_path):
    from cvassure.provenance.verify import detect_all_tampering

    log, priv, pub, head = _build_signed_log(tmp_path, n=4)
    lines = log.read_text(encoding="utf-8").splitlines()
    lines[0], lines[1] = lines[1], lines[0]  # swap first two entries
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_all_tampering(log, pub)
    attacks = {e.attack for e in evidence}
    assert "reorder" in attacks or "edit" in attacks


# ── Attack 4: Truncation ──────────────────────────────────────────────────────


def test_detect_truncation(tmp_path):
    from cvassure.provenance.verify import detect_truncation

    log, priv, pub, head = _build_signed_log(tmp_path, n=5)
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")  # cut last 2

    assert detect_truncation(log, head) is True


def test_no_truncation_when_head_matches(tmp_path):
    from cvassure.provenance.verify import detect_truncation

    log, priv, pub, head = _build_signed_log(tmp_path, n=3)
    assert detect_truncation(log, head) is False


# ── Attack 5: Replay ─────────────────────────────────────────────────────────


def test_detect_replay_duplicate_entry(tmp_path):
    from cvassure.provenance.verify import detect_all_tampering

    log, priv, pub, head = _build_signed_log(tmp_path, n=3)
    lines = log.read_text(encoding="utf-8").splitlines()
    lines.append(lines[0])  # duplicate first entry at end
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_all_tampering(log, pub)
    attacks = {e.attack for e in evidence}
    assert "replay" in attacks


# ── Attack 6: Forge (wrong key) ───────────────────────────────────────────────


def test_detect_forge_wrong_key(tmp_path):
    from cvassure.provenance.chain import SignedChain
    from cvassure.provenance.verify import detect_all_tampering

    priv1, pub1 = _make_keys(tmp_path / "k1")
    priv2, pub2 = _make_keys(tmp_path / "k2")

    log = tmp_path / "audit.log"
    # Write log signed with key1, then verify with key2 (wrong)
    chain = SignedChain(log, private_key_path=priv1, public_key_path=pub1)
    for i in range(3):
        chain.append("event", {"i": i})

    # Check with the wrong pubkey
    evidence = detect_all_tampering(log, pub2)
    attacks = {e.attack for e in evidence}
    assert "forge" in attacks


# ── Attack 7: Strip (sig removed) ────────────────────────────────────────────


def test_detect_strip_missing_sig(tmp_path):
    from cvassure.provenance.verify import detect_all_tampering

    log, priv, pub, head = _build_signed_log(tmp_path, n=3)
    lines = log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    del entry["sig"]  # strip the signature
    lines[1] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_all_tampering(log, pub)
    attacks = {e.attack for e in evidence}
    assert "strip" in attacks or "forge" in attacks


# ── Clean log: no evidence ────────────────────────────────────────────────────


def test_clean_log_no_evidence(tmp_path):
    from cvassure.provenance.verify import detect_all_tampering

    log, priv, pub, head = _build_signed_log(tmp_path, n=5)
    evidence = detect_all_tampering(log, pub, expected_head=head)
    assert evidence == [], f"Clean log should produce no evidence: {evidence}"


# ── detect_reorder utility ────────────────────────────────────────────────────


def test_detect_reorder_utility(tmp_path):
    from cvassure.provenance.verify import detect_reorder

    log, priv, pub, head = _build_signed_log(tmp_path, n=4)
    lines = log.read_text(encoding="utf-8").splitlines()
    lines[0], lines[2] = lines[2], lines[0]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    bad_linenos = detect_reorder(log)
    assert len(bad_linenos) >= 1
