#!/usr/bin/env python
"""Render p4_storyboard.png — mock-up 4C (3-frame demo storyboard).

Three equally-sized frames with numbered captions and arrows between them:
  1. Poison found    — C-07 ranked high risk, heatmap crop
  2. Trigger matched — model trigger = patch in C-07 samples
  3. Tamper rejected — edited and replayed records fail verification

Usage:
    python scripts/render_storyboard.py [--report out/report.html] [--out p4_storyboard.png]

If no real screenshots are available, renders text-only placeholder frames
styled identically to the real output so the layout is correct.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

BLUE = "#0070C0"
NAVY = "#1F3864"
RED = "#C00000"
GREEN = "#1E7B34"
LIGHT = "#EEF2F7"


def _draw_frame(
    ax,
    x,
    y,
    w,
    h,
    *,
    number: int,
    title: str,
    subtitle: str,
    content_lines: list[str],
    colour: str,
    bg: str,
) -> None:
    import matplotlib.patches as mpatches

    # Frame box
    box = mpatches.FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.04",
        linewidth=2.5,
        edgecolor=colour,
        facecolor=bg,
        zorder=2,
    )
    ax.add_patch(box)

    # Number badge
    ax.text(
        x + 0.15,
        y + h - 0.15,
        f"{number}",
        ha="left",
        va="top",
        fontsize=28,
        fontweight="black",
        color=colour,
        zorder=3,
    )

    # Title
    ax.text(
        x + w / 2,
        y + h - 0.2,
        title,
        ha="center",
        va="top",
        fontsize=12,
        fontweight="bold",
        color=colour,
        zorder=3,
    )

    # Subtitle
    ax.text(
        x + w / 2,
        y + h - 0.55,
        subtitle,
        ha="center",
        va="top",
        fontsize=8.5,
        color="#555",
        style="italic",
        zorder=3,
    )

    # Content lines
    for i, line in enumerate(content_lines):
        ax.text(
            x + w / 2,
            y + h - 0.95 - i * 0.3,
            line,
            ha="center",
            va="top",
            fontsize=8.5,
            color="#222",
            zorder=3,
        )


def render_storyboard(
    out_path: Path | None = None,
    *,
    frame_screenshots: list[Path | None] | None = None,
) -> Path:
    """Build the 3-frame storyboard PNG."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib required. pip install matplotlib")
        sys.exit(1)

    out_path = out_path or Path("p4_storyboard.png")

    fig_w, fig_h = 18, 7
    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=130)
    ax.set_xlim(0, fig_w)
    ax.set_ylim(0, fig_h)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    # Background gradient effect
    ax.set_facecolor(LIGHT)

    # Title
    ax.text(
        fig_w / 2,
        fig_h - 0.3,
        "CVAssure | C-07 Story in Three Frames",
        ha="center",
        va="top",
        fontsize=16,
        fontweight="bold",
        color=NAVY,
    )

    # Frame dimensions
    MARGIN = 0.5
    GAP = 0.8
    ARROW_W = 0.6
    FRAME_W = (fig_w - 2 * MARGIN - 2 * GAP - 2 * ARROW_W) / 3
    FRAME_H = fig_h - 1.2
    FRAME_Y = 0.1

    frames = [
        {
            "number": 1,
            "title": "Poison Found",
            "subtitle": "C-07 ranked HIGH RISK with evidence",
            "content": [
                "B1  B2  B3  B4",
                "C-02 ░░░░░░░░░░",
                "C-03 ░░░░░░░░░░",
                "C-05 ░░░░░░░░░░",
                "C-07 ██████████  ◄ HIGH RISK",
                "",
                "Source C-07 flagged",
                "severity 0.93  →  QUARANTINE",
            ],
            "colour": RED,
            "bg": "#fff5f5",
        },
        {
            "number": 2,
            "title": "Trigger Matched",
            "subtitle": "Model trigger = patch in C-07 samples",
            "content": [
                "Data finding F-012:",
                "  patch_trigger, source C-07",
                "",
                "Model finding F-019:",
                "  reconstructed trigger class 0",
                "  MAD score 3.4 (anomalous)",
                "",
                "LINK: mask ≈ C-07 sample",
                "severity escalated 0.79 → 0.88",
            ],
            "colour": BLUE,
            "bg": "#f0f6ff",
        },
        {
            "number": 3,
            "title": "Tamper Rejected",
            "subtitle": "Edited & replayed records fail instantly",
            "content": [
                "#3 (edited output)",
                "  sig: FAIL  →  REJECTED ✗",
                "",
                "#2 (replayed record)",
                "  nonce: reused  →  REJECTED ✗",
                "",
                "Records F-027: severity 1.00",
                "Chain verified: 5 entries OK",
            ],
            "colour": RED,
            "bg": "#fff5f5",
        },
    ]

    frame_positions = []
    for i, frame in enumerate(frames):
        x = MARGIN + i * (FRAME_W + ARROW_W + GAP)
        frame_positions.append((x, FRAME_Y, FRAME_W, FRAME_H))
        _draw_frame(
            ax,
            x,
            FRAME_Y,
            FRAME_W,
            FRAME_H,
            number=frame["number"],
            title=frame["title"],
            subtitle=frame["subtitle"],
            content_lines=frame["content"],
            colour=frame["colour"],
            bg=frame["bg"],
        )

        # If a real screenshot is provided, embed it
        if frame_screenshots and i < len(frame_screenshots) and frame_screenshots[i]:
            try:
                from matplotlib.image import imread

                img = imread(str(frame_screenshots[i]))
                ax.imshow(
                    img,
                    extent=[x + 0.15, x + FRAME_W - 0.15, FRAME_Y + 0.15, FRAME_Y + FRAME_H * 0.55],
                    aspect="auto",
                    zorder=2,
                    alpha=0.85,
                )
            except Exception:
                pass

    # Arrows between frames
    for i in range(len(frames) - 1):
        x_from = frame_positions[i][0] + FRAME_W
        x_to = frame_positions[i + 1][0]
        y_mid = FRAME_Y + FRAME_H / 2
        ax.annotate(
            "",
            xy=(x_to + 0.05, y_mid),
            xytext=(x_from - 0.05, y_mid),
            arrowprops={"arrowstyle": "-|>", "color": NAVY, "lw": 2.5},
            zorder=4,
        )

    # Caption
    caption = (
        "What the judge should notice: Poison found, trigger matched, tamper rejected — "
        "the whole C-07 story in three frames."
    )
    ax.text(
        fig_w / 2, 0.08, caption, ha="center", va="bottom", fontsize=9, color="#555", style="italic"
    )

    plt.tight_layout(rect=[0, 0.04, 1, 1])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(out_path), dpi=130, bbox_inches="tight", facecolor="white", edgecolor="none")
    plt.close(fig)
    print(f"Saved: {out_path}  ({out_path.stat().st_size // 1024} KB)")
    return out_path


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Render p4_storyboard.png")
    parser.add_argument("--out", type=Path, default=Path("p4_storyboard.png"))
    parser.add_argument(
        "--frame1", type=Path, default=None, help="Screenshot for frame 1 (optional)"
    )
    parser.add_argument(
        "--frame2", type=Path, default=None, help="Screenshot for frame 2 (optional)"
    )
    parser.add_argument(
        "--frame3", type=Path, default=None, help="Screenshot for frame 3 (optional)"
    )
    args = parser.parse_args()

    render_storyboard(
        args.out,
        frame_screenshots=[args.frame1, args.frame2, args.frame3],
    )


if __name__ == "__main__":
    main()
