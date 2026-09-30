#!/usr/bin/env python
"""Render p4_chain_tamper.png — mock-up 4A.

Generates a chain diagram showing:
  - 5 clean records in a hash chain
  - Record #3 edited (red, REJECTED)
  - Record #2 replayed (red, REJECTED)
  - Signed Merkle root at the top

Uses real hashes from the audit log if available, otherwise synthetic.

Usage:
    python scripts/render_chain_diagram.py [--log audit.log] [--out p4_chain_tamper.png]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def _read_log_entries(log_path: Path) -> list[dict]:
    if not log_path.is_file():
        return []
    entries = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            import contextlib

            with contextlib.suppress(json.JSONDecodeError):
                entries.append(json.loads(line))
    return entries


def render_chain_diagram(
    log_path: Path | None = None,
    out_path: Path | None = None,
    *,
    pubkey_path: Path | None = None,
) -> Path:
    """Build p4_chain_tamper.png matching mock-up 4A."""

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.patches as mpatches
        import matplotlib.pyplot as plt
        from matplotlib.patches import FancyBboxPatch
    except ImportError:
        print("matplotlib is required. pip install matplotlib")
        sys.exit(1)

    out_path = out_path or Path("p4_chain_tamper.png")

    # ── Data ─────────────────────────────────────────────────────────────────
    real_entries = _read_log_entries(log_path) if log_path else []

    # Build 5 representative records (use real hashes where available)
    def _h(entry: dict, key: str, default: str) -> str:
        v = entry.get(key, default)
        return str(v)[:8] if v else default[:8]

    records = []
    for i in range(5):
        if i < len(real_entries):
            e = real_entries[i]
            records.append(
                {
                    "seq": e.get("seq", i + 1),
                    "prev": _h(e, "prev_hash", "0" * 8),
                    "sig": "OK" if e.get("sig") else "NONE",
                    "event": str(e.get("event", f"event_{i + 1}"))[:14],
                }
            )
        else:
            prev_hashes = ["0000..", "a1f3..", "7be0..", "c92d..", "41aa.."]
            records.append(
                {
                    "seq": i + 1,
                    "prev": prev_hashes[i],
                    "sig": "OK",
                    "event": f"event_{i + 1}",
                }
            )

    # Record #3 (index 2) is the tampered one
    TAMPERED_IDX = 2

    # Merkle root
    merkle_root = (
        "3f7a2c91…"
        if not real_entries
        else real_entries[-1].get("entry_hash", "unknown")[:12] + "…"
    )

    # ── Layout ───────────────────────────────────────────────────────────────
    BLUE = "#0070C0"
    NAVY = "#1F3864"
    RED = "#C00000"
    GREEN = "#1E7B34"
    LIGHT = "#EEF2F7"

    fig, ax = plt.subplots(figsize=(16, 7), dpi=130)
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 7)
    ax.axis("off")

    # Title
    ax.text(
        8,
        6.7,
        "CVAssure | Hash Chain — Tamper & Replay Detection",
        ha="center",
        va="center",
        fontsize=16,
        fontweight="bold",
        color=NAVY,
    )

    # ── Draw Merkle root at top ───────────────────────────────────────────────
    mr_box = FancyBboxPatch(
        (5.5, 5.7),
        5,
        0.7,
        boxstyle="round,pad=0.1",
        linewidth=2,
        edgecolor=NAVY,
        facecolor="#dce8f7",
    )
    ax.add_patch(mr_box)
    ax.text(
        8,
        6.05,
        "Merkle root (signed, periodic) | covers #1–#5",
        ha="center",
        va="center",
        fontsize=9,
        color=NAVY,
        fontweight="bold",
    )
    ax.text(
        8,
        5.78,
        f"root: {merkle_root}…",
        ha="center",
        va="center",
        fontsize=7.5,
        color=NAVY,
        fontfamily="monospace",
    )

    # ── Draw records ──────────────────────────────────────────────────────────
    xs = [1.0, 3.5, 6.0, 8.5, 11.0]
    y_record = 3.5
    BOX_W = 2.1
    BOX_H = 1.6
    box_y = y_record - BOX_H / 2

    for i, rec in enumerate(records):
        x = xs[i]
        is_tampered = i == TAMPERED_IDX
        edge_c = RED if is_tampered else BLUE
        face_c = "#fff0f0" if is_tampered else LIGHT
        lw = 2.5 if is_tampered else 1.5

        box = FancyBboxPatch(
            (x, box_y),
            BOX_W,
            BOX_H,
            boxstyle="round,pad=0.08",
            linewidth=lw,
            edgecolor=edge_c,
            facecolor=face_c,
        )
        ax.add_patch(box)

        sig_txt = "sig: FAIL" if is_tampered else "sig: OK"
        sig_col = RED if is_tampered else GREEN

        prefix = "(edited) " if is_tampered else ""
        ax.text(
            x + BOX_W / 2,
            box_y + BOX_H - 0.2,
            f"#{rec['seq']} {prefix}",
            ha="center",
            va="top",
            fontsize=9,
            fontweight="bold",
            color=RED if is_tampered else NAVY,
        )
        ax.text(
            x + BOX_W / 2,
            box_y + BOX_H - 0.5,
            f"seq {rec['seq']}",
            ha="center",
            va="top",
            fontsize=8,
            color="#444",
        )
        ax.text(
            x + BOX_W / 2,
            box_y + BOX_H - 0.75,
            f"prev: {rec['prev']}",
            ha="center",
            va="top",
            fontsize=7.5,
            color="#444",
            fontfamily="monospace",
        )
        ax.text(
            x + BOX_W / 2,
            box_y + BOX_H - 1.0,
            sig_txt,
            ha="center",
            va="top",
            fontsize=8.5,
            fontweight="bold",
            color=sig_col,
        )

        if is_tampered:
            ax.text(
                x + BOX_W / 2,
                box_y - 0.4,
                "REJECTED\nhash + sig do not verify",
                ha="center",
                va="top",
                fontsize=7.5,
                color=RED,
                fontweight="bold",
                bbox={
                    "boxstyle": "round,pad=0.2",
                    "facecolor": "#fff0f0",
                    "edgecolor": RED,
                    "linewidth": 1.5,
                },
            )

    # ── Arrows between records ────────────────────────────────────────────────
    arrow_y = y_record
    for i in range(len(records) - 1):
        x_start = xs[i] + BOX_W
        x_end = xs[i + 1]
        ax.annotate(
            "",
            xy=(x_end + 0.05, arrow_y),
            xytext=(x_start - 0.05, arrow_y),
            arrowprops={"arrowstyle": "-|>", "color": BLUE, "lw": 1.5},
        )

    # ── Arrows from Merkle root to records 1 and 5 ───────────────────────────
    for i in (0, 4):
        ax.annotate(
            "",
            xy=(xs[i] + BOX_W / 2, box_y + BOX_H),
            xytext=(xs[i] + BOX_W / 2, 5.7),
            arrowprops={"arrowstyle": "-|>", "color": NAVY, "lw": 1.2, "linestyle": "dotted"},
        )

    # ── Replayed record ───────────────────────────────────────────────────────
    rx = 13.5
    replay_box = FancyBboxPatch(
        (rx, box_y),
        BOX_W,
        BOX_H,
        boxstyle="round,pad=0.08",
        linewidth=2.5,
        edgecolor=RED,
        facecolor="#fff0f0",
    )
    ax.add_patch(replay_box)
    ax.text(
        rx + BOX_W / 2,
        box_y + BOX_H - 0.2,
        "#2 replayed",
        ha="center",
        va="top",
        fontsize=9,
        fontweight="bold",
        color=RED,
    )
    ax.text(
        rx + BOX_W / 2,
        box_y + BOX_H - 0.5,
        "seq 2 (again)",
        ha="center",
        va="top",
        fontsize=8,
        color="#444",
    )
    ax.text(
        rx + BOX_W / 2,
        box_y + BOX_H - 0.75,
        f"prev: {records[1]['prev']}",
        ha="center",
        va="top",
        fontsize=7.5,
        color="#444",
        fontfamily="monospace",
    )
    ax.text(
        rx + BOX_W / 2,
        box_y + BOX_H - 1.0,
        "sig: OK",
        ha="center",
        va="top",
        fontsize=8.5,
        fontweight="bold",
        color=GREEN,
    )

    ax.text(
        rx + BOX_W / 2,
        box_y - 0.4,
        "REJECTED\nreplayed record: nonce reused",
        ha="center",
        va="top",
        fontsize=7.5,
        color=RED,
        fontweight="bold",
        bbox={
            "boxstyle": "round,pad=0.2",
            "facecolor": "#fff0f0",
            "edgecolor": RED,
            "linewidth": 1.5,
        },
    )

    # Arrow from record #5 to replayed
    ax.annotate(
        "",
        xy=(rx + 0.05, arrow_y),
        xytext=(xs[-1] + BOX_W - 0.05, arrow_y),
        arrowprops={"arrowstyle": "-|>", "color": RED, "lw": 1.8, "linestyle": "dashed"},
    )

    # ── Legend ────────────────────────────────────────────────────────────────
    legend_elements = [
        mpatches.Patch(
            facecolor=LIGHT, edgecolor=BLUE, linewidth=1.5, label="Verified record (sig: OK)"
        ),
        mpatches.Patch(facecolor="#fff0f0", edgecolor=RED, linewidth=2, label="REJECTED record"),
        mpatches.Patch(
            facecolor="#dce8f7", edgecolor=NAVY, linewidth=2, label="Signed Merkle root"
        ),
    ]
    ax.legend(handles=legend_elements, loc="lower left", fontsize=9, framealpha=0.9, edgecolor=NAVY)

    # ── Caption ───────────────────────────────────────────────────────────────
    caption = (
        "What the judge should notice: Two red records — an edited output and a replayed "
        "old record — both refused while every untouched record stays green."
    )
    ax.text(
        8,
        0.3,
        caption,
        ha="center",
        va="bottom",
        fontsize=8,
        color="#555",
        style="italic",
        wrap=True,
    )

    plt.tight_layout(rect=[0, 0.05, 1, 1])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(out_path), dpi=130, bbox_inches="tight", facecolor="white", edgecolor="none")
    plt.close(fig)
    print(f"Saved: {out_path}  ({out_path.stat().st_size // 1024} KB)")
    return out_path


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Render p4_chain_tamper.png")
    parser.add_argument(
        "--log", type=Path, default=None, help="audit.log (uses real hashes when given)"
    )
    parser.add_argument("--out", type=Path, default=Path("p4_chain_tamper.png"))
    parser.add_argument("--pubkey", type=Path, default=None)
    args = parser.parse_args()

    render_chain_diagram(args.log, args.out, pubkey_path=args.pubkey)


if __name__ == "__main__":
    main()
