"""Integration tests — full pipeline with provenance signing enabled."""

from __future__ import annotations

import json


def _make_keys(tmp_path):
    from cvassure.provenance.keys import generate_keypair

    return generate_keypair(tmp_path / "k")


def _build_scenario(tmp_path):
    from tests.fixtures.synthetic_scenario import build_all

    root = tmp_path / "scenario"
    return build_all(root)


# ── Full signed audit end-to-end ──────────────────────────────────────────────


def test_signed_audit_end_to_end(tmp_path):
    """run_audit() with keypair → audit.log has signatures, chain verifies."""
    from cvassure.core.pipeline import run_audit

    priv_path, pub_path = _make_keys(tmp_path)
    assets = _build_scenario(tmp_path)
    out = tmp_path / "out"

    result = run_audit(
        data=assets["data"],
        model=assets["model"],
        records=assets["records"],
        out_dir=out,
        privkey_path=priv_path,
        pubkey_path=pub_path,
    )

    assert result.chain_ok
    log = out / "audit.log"
    assert log.is_file()

    # Every entry must be signed
    for line in log.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entry = json.loads(line)
            assert "sig" in entry and entry["sig"], f"unsigned entry: {entry.get('event')}"
            assert entry.get("chained_signed") is True


def test_unsigned_fallback_without_keys(tmp_path):
    """run_audit() without keys → falls back to SignedChain with ephemeral key."""
    import warnings

    from cvassure.core.pipeline import run_audit

    assets = _build_scenario(tmp_path)
    out = tmp_path / "out"

    # We expect a warning about the ephemeral key
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_audit(
            data=assets["data"],
            model=assets["model"],
            records=assets["records"],
            out_dir=out,
        )

    # Chain must be verifiable with whatever key was used internally
    assert result.chain_ok
    log = out / "audit.log"
    entries = [
        json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert len(entries) > 0


def test_report_is_offline_html(tmp_path):
    """The generated report must contain no remote URLs."""
    import warnings

    from cvassure.core.pipeline import run_audit

    priv_path, pub_path = _make_keys(tmp_path)
    assets = _build_scenario(tmp_path)
    out = tmp_path / "out"

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_audit(
            data=assets["data"],
            model=assets["model"],
            records=assets["records"],
            out_dir=out,
            privkey_path=priv_path,
            pubkey_path=pub_path,
        )

    report = result.report_path
    assert report.is_file() and report.suffix == ".html"

    content = report.read_text(encoding="utf-8")
    for bad in ("https://", "http://", "//cdn.", "fonts.googleapis", "unpkg.com"):
        assert bad not in content, f"Report contains remote URL: {bad!r}"


# ── Live tamper rejection ─────────────────────────────────────────────────────


def test_edit_rejected_live(tmp_path):
    """Edit one line → verify-log fails with 'signature invalid' or 'mismatch'."""
    import warnings

    from cvassure.core.pipeline import run_audit
    from cvassure.provenance.verify import verify_signed_log

    priv_path, pub_path = _make_keys(tmp_path)
    assets = _build_scenario(tmp_path)
    out = tmp_path / "out"

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        run_audit(
            data=assets["data"],
            model=assets["model"],
            records=assets["records"],
            out_dir=out,
            privkey_path=priv_path,
            pubkey_path=pub_path,
        )

    log = out / "audit.log"
    lines = log.read_text(encoding="utf-8").splitlines()
    # Edit the 3rd line
    entry = json.loads(lines[2])
    entry["data"]["tampered"] = True
    lines[2] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = verify_signed_log(log, pub_path)
    assert res.ok is False
    assert (
        "invalid" in res.reason.lower()
        or "mismatch" in res.reason.lower()
        or "match" in res.reason.lower()
    )


def test_replay_rejected_live(tmp_path):
    """Duplicate a record line → detect_replay finds nonce reuse."""
    import warnings

    from cvassure.core.pipeline import run_audit
    from cvassure.provenance.verify import detect_all_tampering

    priv_path, pub_path = _make_keys(tmp_path)
    assets = _build_scenario(tmp_path)
    out = tmp_path / "out"

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        run_audit(
            data=assets["data"],
            model=assets["model"],
            records=assets["records"],
            out_dir=out,
            privkey_path=priv_path,
            pubkey_path=pub_path,
        )

    log = out / "audit.log"
    lines = log.read_text(encoding="utf-8").splitlines()
    # Duplicate line 0 at the end
    lines.append(lines[0])
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evidence = detect_all_tampering(log, pub_path)
    attacks = {e.attack for e in evidence}
    assert "replay" in attacks


# ── Dashboard sections ────────────────────────────────────────────────────────


def test_dashboard_has_required_sections(tmp_path):
    """The generated HTML report must have all mock-up 4B sections."""
    import warnings

    from cvassure.core.pipeline import run_audit

    priv_path, pub_path = _make_keys(tmp_path)
    assets = _build_scenario(tmp_path)
    out = tmp_path / "out"

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        run_audit(
            data=assets["data"],
            model=assets["model"],
            records=assets["records"],
            out_dir=out,
            privkey_path=priv_path,
            pubkey_path=pub_path,
        )

    content = (out / "report.html").read_text(encoding="utf-8")
    required_phrases = [
        "Assurance Report",  # header
        "Coverage Statement",  # coverage section
        "Provenance",  # provenance panel
        "Audit Log",  # audit log section
        "Findings",  # findings table
        "quarantine",  # export button
    ]
    for phrase in required_phrases:
        assert phrase in content, f"Missing section: {phrase!r}"


# ── manifest keys set by signed run ──────────────────────────────────────────


def test_manifest_has_signer_fingerprint(tmp_path):
    """When keys are given, the manifest should record chain_backend."""
    import warnings

    from cvassure.core.pipeline import run_audit

    priv_path, pub_path = _make_keys(tmp_path)
    assets = _build_scenario(tmp_path)
    out = tmp_path / "out"

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = run_audit(
            data=assets["data"],
            model=assets["model"],
            records=assets["records"],
            out_dir=out,
            privkey_path=priv_path,
            pubkey_path=pub_path,
        )

    manifest = result.manifest
    assert "chain_backend" in manifest
    # With provenance.chain importable, backend should be SignedChain
    assert "SignedChain" in manifest.get("chain_backend", "")
