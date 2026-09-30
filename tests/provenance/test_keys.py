"""Tests for cvassure.provenance.keys."""

from __future__ import annotations

import pytest


def test_generate_keypair_creates_files(tmp_path):
    from cvassure.provenance.keys import generate_keypair

    priv, pub = generate_keypair(tmp_path / "test_key")
    assert priv.is_file()
    assert pub.is_file()
    assert priv.suffix == ".key"
    assert pub.suffix == ".pub"


def test_private_key_is_64_hex_chars(tmp_path):
    from cvassure.provenance.keys import generate_keypair

    priv, _ = generate_keypair(tmp_path / "k")
    raw = priv.read_text(encoding="utf-8").strip()
    assert len(raw) == 64, "private key seed must be 32 bytes = 64 hex chars"
    assert all(c in "0123456789abcdef" for c in raw)


def test_public_key_is_64_hex_chars(tmp_path):
    from cvassure.provenance.keys import generate_keypair

    _, pub = generate_keypair(tmp_path / "k")
    raw = pub.read_text(encoding="utf-8").strip()
    assert len(raw) == 64, "public key must be 32 bytes = 64 hex chars"


def test_load_private_and_public(tmp_path):
    from cvassure.provenance.keys import generate_keypair, load_private, load_public

    priv_path, pub_path = generate_keypair(tmp_path / "k")
    sk = load_private(priv_path)
    vk = load_public(pub_path)
    # Verify they correspond
    assert bytes(sk.verify_key) == bytes(vk)


def test_sign_verify_round_trip(tmp_path):
    from cvassure.provenance.keys import generate_keypair, load_private, load_public, sign, verify

    priv_path, pub_path = generate_keypair(tmp_path / "k")
    sk = load_private(priv_path)
    vk = load_public(pub_path)
    data = b"hello cvassure"
    sig = sign(sk, data)
    assert verify(vk, data, sig) is True


def test_verify_wrong_data_fails(tmp_path):
    from cvassure.provenance.keys import generate_keypair, load_private, load_public, sign, verify

    priv_path, pub_path = generate_keypair(tmp_path / "k")
    sk = load_private(priv_path)
    vk = load_public(pub_path)
    sig = sign(sk, b"original")
    assert verify(vk, b"tampered", sig) is False


def test_verify_wrong_key_fails(tmp_path):
    from cvassure.provenance.keys import generate_keypair, load_private, load_public, sign, verify

    p1, p2 = generate_keypair(tmp_path / "k1"), generate_keypair(tmp_path / "k2")
    sk1 = load_private(p1[0])
    vk2 = load_public(p2[1])
    sig = sign(sk1, b"data")
    assert verify(vk2, b"data", sig) is False


def test_fingerprint_is_16_hex(tmp_path):
    from cvassure.provenance.keys import fingerprint, generate_keypair, load_public

    _, pub_path = generate_keypair(tmp_path / "k")
    vk = load_public(pub_path)
    fp = fingerprint(bytes(vk))
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_is_stable(tmp_path):
    from cvassure.provenance.keys import fingerprint, generate_keypair, load_public

    _, pub_path = generate_keypair(tmp_path / "k")
    vk = load_public(pub_path)
    assert fingerprint(bytes(vk)) == fingerprint(bytes(vk))


def test_private_key_never_in_fingerprint(tmp_path):
    """The fingerprint must only expose the public key, not private key bytes."""
    from cvassure.provenance.keys import fingerprint, generate_keypair, load_private, load_public

    priv_path, pub_path = generate_keypair(tmp_path / "k")
    sk = load_private(priv_path)
    vk = load_public(pub_path)
    # The private key seed differs from the public key bytes
    priv_fp = fingerprint(bytes(sk))  # using private key bytes
    pub_fp = fingerprint(bytes(vk))  # using public key bytes
    # They should differ (private != public in Ed25519)
    assert priv_fp != pub_fp


def test_load_private_bad_length(tmp_path):
    from cvassure.provenance.keys import load_private

    bad = tmp_path / "bad.key"
    bad.write_text("deadbeef\n", encoding="utf-8")  # too short
    with pytest.raises(ValueError, match="32 bytes"):
        load_private(bad)


def test_load_public_bad_length(tmp_path):
    from cvassure.provenance.keys import load_public

    bad = tmp_path / "bad.pub"
    bad.write_text("deadbeef\n", encoding="utf-8")  # too short
    with pytest.raises(ValueError, match="32 bytes"):
        load_public(bad)


def test_overwrite_generates_new_keypair(tmp_path):
    from cvassure.provenance.keys import generate_keypair, load_public

    p1, p2 = generate_keypair(tmp_path / "k")
    vk1 = load_public(p2)
    p1b, p2b = generate_keypair(tmp_path / "k")  # overwrites
    vk2 = load_public(p2b)
    # New key should differ from old key (with overwhelming probability)
    assert bytes(vk1) != bytes(vk2)
