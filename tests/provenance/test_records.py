"""Tests for cvassure.provenance.records — signed inference records."""

from __future__ import annotations

import json
import secrets


def _make_keys(tmp_path):
    from cvassure.provenance.keys import generate_keypair, load_private, load_public

    priv_path, pub_path = generate_keypair(tmp_path / "k")
    return load_private(priv_path), load_public(pub_path)


def _sample_data(n=5):
    return [
        {
            "input_hash": f"sha256:{i:064x}",
            "model_digest": "sha256:model-fixture",
            "config_hash": "sha256:config-fixture",
            "output": {"label": i % 2, "score": 0.9},
            "nonce": secrets.token_hex(16),
        }
        for i in range(n)
    ]


# ── sign_record ───────────────────────────────────────────────────────────────


def test_sign_record_returns_all_fields(tmp_path):
    from cvassure.provenance.records import sign_record

    sk, vk = _make_keys(tmp_path)
    rec = sign_record(
        seq=1,
        ts="2026-01-01T00:00:01Z",
        input_hash="sha256:abc",
        model_digest="sha256:def",
        config_hash="sha256:ghi",
        output={"label": 0},
        nonce="aabbcc",
        prev_hash="0" * 64,
        private_key=sk,
        public_key=vk,
    )
    for field in ("seq", "ts", "entry_hash", "sig", "pubkey_fp", "prev_hash", "nonce"):
        assert field in rec, f"missing field: {field}"


def test_verify_record_round_trip(tmp_path):
    from cvassure.provenance.records import sign_record, verify_record

    sk, vk = _make_keys(tmp_path)
    rec = sign_record(
        seq=1,
        ts="2026-01-01T00:00:01Z",
        input_hash="sha256:abc",
        model_digest="sha256:def",
        config_hash="sha256:ghi",
        output={},
        nonce="nn",
        prev_hash="0" * 64,
        private_key=sk,
        public_key=vk,
    )
    assert verify_record(rec, vk) is True


def test_verify_record_fails_on_tampered_output(tmp_path):
    from cvassure.provenance.records import sign_record, verify_record

    sk, vk = _make_keys(tmp_path)
    rec = sign_record(
        seq=1,
        ts="2026-01-01T00:00:01Z",
        input_hash="sha256:abc",
        model_digest="sha256:def",
        config_hash="sha256:ghi",
        output={"label": 0},
        nonce="nn",
        prev_hash="0" * 64,
        private_key=sk,
        public_key=vk,
    )
    tampered = dict(rec)
    tampered["output"] = {"label": 1}  # change the output
    assert verify_record(tampered, vk) is False


def test_verify_record_no_sig_returns_false(tmp_path):
    from cvassure.provenance.records import verify_record

    _, vk = _make_keys(tmp_path)
    rec = {"seq": 1, "output": {}, "entry_hash": "x", "nonce": "y"}
    assert verify_record(rec, vk) is False


# ── write_signed_records / detect_edit ────────────────────────────────────────


def test_write_and_detect_no_edits(tmp_path):
    from cvassure.provenance.records import detect_edit, write_signed_records

    sk, vk = _make_keys(tmp_path)
    path = tmp_path / "records.jsonl"
    write_signed_records(path, _sample_data(5), sk, vk)
    evidence = detect_edit(path, vk)
    assert evidence == [], f"Unexpected edit evidence: {evidence}"


def test_detect_edit_catches_tampered_output(tmp_path):
    from cvassure.provenance.records import detect_edit, write_signed_records

    sk, vk = _make_keys(tmp_path)
    path = tmp_path / "records.jsonl"
    write_signed_records(path, _sample_data(5), sk, vk)

    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])
    rec["output"] = {"label": 99}  # tamper
    lines[2] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_edit(path, vk)
    assert len(evidence) >= 1
    seqs = [e.seq for e in evidence]
    assert 3 in seqs  # record #3 (0-indexed line 2)


def test_detect_edit_catches_entry_hash_mismatch(tmp_path):
    from cvassure.provenance.records import detect_edit, write_signed_records

    sk, vk = _make_keys(tmp_path)
    path = tmp_path / "records.jsonl"
    write_signed_records(path, _sample_data(3), sk, vk)

    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["entry_hash"] = "a" * 64  # corrupt hash without re-signing
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_edit(path, vk)
    assert any("entry_hash" in e.reason for e in evidence)


# ── detect_replay ─────────────────────────────────────────────────────────────


def test_detect_replay_clean(tmp_path):
    from cvassure.provenance.records import detect_replay, write_signed_records

    sk, vk = _make_keys(tmp_path)
    path = tmp_path / "records.jsonl"
    write_signed_records(path, _sample_data(5), sk, vk)
    assert detect_replay(path) == []


def test_detect_replay_catches_reused_nonce(tmp_path):
    from cvassure.provenance.records import detect_replay, write_signed_records

    sk, vk = _make_keys(tmp_path)
    path = tmp_path / "records.jsonl"
    write_signed_records(path, _sample_data(4), sk, vk)

    lines = path.read_text(encoding="utf-8").splitlines()
    # Copy line 0 (nonce from record #1) and append as a new line
    rec0 = json.loads(lines[0])
    rec_copy = dict(rec0)  # same nonce!
    rec_copy["seq"] = 99
    lines.append(json.dumps(rec_copy))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_replay(path)
    assert len(evidence) >= 1
    assert evidence[0].nonce == rec0["nonce"]
    assert "replay" in evidence[0].reason.lower()


# ── detect_chain_break ────────────────────────────────────────────────────────


def test_detect_chain_break_clean(tmp_path):
    from cvassure.provenance.records import detect_chain_break, write_signed_records

    sk, vk = _make_keys(tmp_path)
    path = tmp_path / "records.jsonl"
    write_signed_records(path, _sample_data(5), sk, vk)
    assert detect_chain_break(path) == []


def test_detect_chain_break_after_deletion(tmp_path):
    from cvassure.provenance.records import detect_chain_break, write_signed_records

    sk, vk = _make_keys(tmp_path)
    path = tmp_path / "records.jsonl"
    write_signed_records(path, _sample_data(5), sk, vk)

    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # delete record #2
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_chain_break(path)
    assert len(evidence) >= 1
