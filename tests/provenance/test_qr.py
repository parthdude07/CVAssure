"""Tests for cvassure.provenance.qr — offline QR code renderer."""

from __future__ import annotations

import base64


def _is_valid_png(data: bytes) -> bool:
    """Minimal PNG header check."""
    return data[:8] == b"\x89PNG\r\n\x1a\n"


def test_render_qr_writes_png(tmp_path):
    from cvassure.provenance.qr import render_qr

    out = tmp_path / "test.png"
    render_qr("cvassure:sha256:deadbeef", out)
    assert out.is_file()
    assert _is_valid_png(out.read_bytes())


def test_render_qr_base64_is_data_uri(tmp_path):
    from cvassure.provenance.qr import render_qr_base64

    b64 = render_qr_base64("cvassure:sha256:deadbeef")
    assert b64.startswith("data:image/png;base64,")
    raw = base64.b64decode(b64.split(",", 1)[1])
    assert _is_valid_png(raw)


def test_render_qr_base64_no_remote_url(tmp_path):
    from cvassure.provenance.qr import render_qr_base64

    b64 = render_qr_base64("hello")
    assert "http://" not in b64
    assert "https://" not in b64


def test_payload_qr_content_format(tmp_path):
    from cvassure.provenance.qr import payload_qr_content

    sha = "a" * 64
    content = payload_qr_content(sha)
    assert content == f"cvassure:sha256:{sha}"


def test_different_data_different_qr(tmp_path):
    from cvassure.provenance.qr import render_qr_base64

    b1 = render_qr_base64("payload_a")
    b2 = render_qr_base64("payload_b")
    assert b1 != b2


def test_render_qr_png_size(tmp_path):
    from cvassure.provenance.qr import render_qr

    out = tmp_path / "qr.png"
    render_qr("test", out, size=160)
    assert out.stat().st_size > 100  # at least a real PNG
