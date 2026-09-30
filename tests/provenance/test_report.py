"""Tests for the offline HTML dashboard (cvassure.provenance.report)."""

from __future__ import annotations

import json


def _make_minimal_out_dir(tmp_path, *, with_findings=True):
    """Write the minimal set of files render_report expects."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "evidence").mkdir()

    if with_findings:
        findings = [
            {
                "schema_version": "1.0",
                "id": "F-012",
                "asset": "data",
                "reason": "Patch-trigger cluster in class 0 from source C-07",
                "evidence": ["evidence/f012.png"],
                "severity": 0.93,
                "confidence": 0.88,
                "access_level": "black-box",
                "limitations": "Requires embeddings to work.",
                "disposition": "quarantine",
                "linked_findings": ["F-019"],
                "source_id": "C-07",
                "batch_id": "B-3",
                "tags": ["patch_trigger"],
                "link_hints": {
                    "trigger": {"kind": "patch_library", "patch_id": "p001"},
                    "target_class": 0,
                    "source_id": "C-07",
                },
                "stub": False,
                "metadata": {},
            },
            {
                "schema_version": "1.0",
                "id": "F-019",
                "asset": "model",
                "reason": "Anomalously small reconstructed trigger for class 0 (MAD score 3.4)",
                "evidence": ["evidence/f019.png"],
                "severity": 0.88,
                "confidence": 0.79,
                "access_level": "white-box",
                "limitations": "Neural-Cleanse style; unreliable for blended triggers.",
                "disposition": "review",
                "linked_findings": ["F-012"],
                "tags": ["trigger_reconstructed"],
                "link_hints": {
                    "trigger": {"kind": "reconstructed", "mask_path": "evidence/f019.png"},
                    "target_class": 0,
                },
                "stub": False,
                "metadata": {},
            },
            {
                "schema_version": "1.0",
                "id": "F-027",
                "asset": "records",
                "reason": "Edited output and replayed record both rejected by signed chain",
                "evidence": ["evidence/f027.png"],
                "severity": 1.0,
                "confidence": 1.0,
                "access_level": "not-applicable",
                "limitations": "A compromised signing key defeats this scheme.",
                "disposition": "rejected",
                "linked_findings": [],
                "tags": ["verification_failed", "replay"],
                "stub": False,
                "metadata": {},
            },
            {
                "schema_version": "1.0",
                "id": "F-033",
                "asset": "shift",
                "reason": "Batch B-5 shows step-change manipulation signature",
                "evidence": ["evidence/f033.png"],
                "severity": 0.81,
                "confidence": 0.75,
                "access_level": "black-box",
                "limitations": "Undetermined cases fall back to REVIEW.",
                "disposition": "review",
                "linked_findings": [],
                "tags": ["manipulation"],
                "batch_id": "B-5",
                "stub": False,
                "metadata": {},
            },
        ]
        (out / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    else:
        (out / "findings.json").write_text("[]", encoding="utf-8")

    manifest = {
        "payload_sha256": "a" * 64,
        "report_file_sha256": "b" * 64,
        "audit_head": "c" * 64,
        "chain_verified": True,
        "tool_version": "0.1.0",
        "seed": 42,
        "git_commit": "test",
        "policy_hash": "d" * 64,
        "chain_backend": "SignedChain",
        "signed": True,
        "signer_fingerprint": "e1e2e3e4e5e6e7e8",
        "merkle_root": "f" * 64,
        "stub_flags": {"stub_ran": False, "stubs": []},
    }
    (out / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (out / "coverage.json").write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "attack_class": "Patch trigger",
                        "status": "Supported",
                        "measured": "87%",
                        "reason": "",
                    },
                    {
                        "attack_class": "Adaptive attacker",
                        "status": "Unsupported",
                        "measured": None,
                        "reason": "Attacker knows the detectors",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (out / "quarantine.json").write_text(
        json.dumps({"samples": ["s001", "s007"]}), encoding="utf-8"
    )
    return out


# ── Core structure ────────────────────────────────────────────────────────────


def test_render_report_creates_html(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    path = render_report(out)
    assert path.is_file()
    assert path.suffix == ".html"


def test_html_is_valid_document(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    path = render_report(out)
    content = path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "<html" in content
    assert "</html>" in content


def test_no_remote_urls(tmp_path):
    """The report must not reference any external URLs — it must be offline."""
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    path = render_report(out)
    content = path.read_text(encoding="utf-8")

    # These patterns would indicate a remote resource
    BAD = ["http://", "https://", "//cdn.", "fonts.googleapis", "unpkg.com", "jsdelivr"]
    for bad in BAD:
        assert bad not in content, f"Remote URL found: {bad!r}"


def test_verdict_banner_present(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    content = render_report(out).read_text(encoding="utf-8")
    assert "C-07" in content  # top quarantine finding source


def test_findings_table_has_all_ids(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    content = render_report(out).read_text(encoding="utf-8")
    for fid in ("F-012", "F-019", "F-027", "F-033"):
        assert fid in content, f"Finding {fid} missing from report"


def test_quarantine_export_button_present(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    content = render_report(out).read_text(encoding="utf-8")
    assert "dlQuarantine" in content or "quarantine" in content.lower()


def test_payload_sha256_in_report(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    content = render_report(out).read_text(encoding="utf-8")
    # At least the first characters of the payload hash should appear
    assert "aaaaaaaaaaaa" in content  # first 12 of "a" * 64


def test_coverage_section_present(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    content = render_report(out).read_text(encoding="utf-8")
    assert "Patch trigger" in content
    assert "Unsupported" in content


def test_provenance_panel_present(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    content = render_report(out).read_text(encoding="utf-8")
    assert "SignedChain" in content
    assert "e1e2e3e4e5e6e7e8" in content  # signer fingerprint


def test_shift_timeline_present(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    content = render_report(out).read_text(encoding="utf-8")
    # The shift finding for B-5 manipulation should appear
    assert "B-5" in content or "MAN" in content


def test_no_findings_renders_clean(tmp_path):
    """Empty findings.json should not crash the renderer."""
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path, with_findings=False)
    path = render_report(out)
    content = path.read_text(encoding="utf-8")
    assert "<html" in content


def test_report_has_meta_description(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    content = render_report(out).read_text(encoding="utf-8")
    assert '<meta name="description"' in content


def test_qr_code_present(tmp_path):
    from cvassure.provenance.report import render_report

    out = _make_minimal_out_dir(tmp_path)
    content = render_report(out).read_text(encoding="utf-8")
    # QR code should be embedded as a base64 PNG or there's a fallback message
    assert "data:image/png;base64," in content or "qrcode" in content.lower()
