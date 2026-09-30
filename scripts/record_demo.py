#!/usr/bin/env python
"""Demo automation script — Person 4's 2-minute demo.

Follows the C-07 story:
  1. Generate Ed25519 keys
  2. Build the seeded scenario (build_demo_scenario(seed=42))
  3. Run full signed audit — all 5 stages, LINK, DISPOSITION
  4. Show report.html path + QR content
  5. verify-log → chain verified (signed)
  6. Live tamper: edit one line → re-verify → REJECTED
  7. Live replay: duplicate a record → re-verify → nonce reused
  8. Show Merkle root from manifest (if present)

Usage:
    python scripts/record_demo.py [--out demo_out] [--seed 42]

Capture with:
    asciinema rec demo.cast -- python scripts/record_demo.py
    termtosvg demo.svg --screen-geometry 140x40 < demo.cast

Output:
    demo_out/  — full audit output
    demo_out/demo_transcript.txt  — ANSI-free text transcript of this run
"""

from __future__ import annotations

import json
import sys
import time
import warnings
from pathlib import Path

# Allow running from repo root without pip install
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))


BLUE = "\033[34m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"


def _print(msg: str, *, colour: str = "", end: str = "\n") -> None:
    print(f"{colour}{msg}{RESET}", end=end, flush=True)


def _step(n: int, total: int, label: str) -> None:
    _print(f"\n{BOLD}[{n}/{total}] {label}{RESET}", colour=BLUE)


def _ok(msg: str) -> None:
    _print(f"  [+] {msg}", colour=GREEN)


def _fail(msg: str) -> None:
    _print(f"  [!] {msg}", colour=RED)


def _info(msg: str) -> None:
    _print(f"  {msg}", colour=DIM)


def run_demo(out_dir: Path, seed: int = 42) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    transcript: list[str] = []

    def _t(msg: str) -> None:
        transcript.append(msg)

    total = 8

    # ── 1. Generate keys ──────────────────────────────────────────────────────
    _step(1, total, "Generate Ed25519 signing keys")
    _t("=== [1/8] Generate Ed25519 keys ===")
    from cvassure.provenance.keys import fingerprint, generate_keypair, load_public

    key_base = out_dir / "cvassure_demo"
    priv_path, pub_path = generate_keypair(key_base)
    vk = load_public(pub_path)
    fp = fingerprint(bytes(vk))
    _ok(f"private key: {priv_path.name}")
    _ok(f"public key:  {pub_path.name}")
    _ok(f"fingerprint: {fp}")
    _t(f"private key: {priv_path}")
    _t(f"public key:  {pub_path}")
    _t(f"fingerprint: {fp}")
    time.sleep(0.3)

    # ── 2. Build scenario ─────────────────────────────────────────────────────
    _step(2, total, f"Build seeded demo scenario (seed={seed})")
    _t(f"\n=== [2/8] Build scenario seed={seed} ===")
    try:
        from cvassure.shift.scenario import build_demo_scenario  # type: ignore[import]

        scenario = build_demo_scenario(seed=seed)
        data_path = scenario["data"]
        model_path = scenario["model"]
        records_path = scenario["records"]
        _ok(f"data: {data_path}")
        _ok(f"model: {model_path}")
        _ok(f"records: {records_path}")
        _t(f"data: {data_path}")
        _t(f"model: {model_path}")
        _t(f"records: {records_path}")
    except ImportError:
        _print("  Using synthetic scenario (shift.scenario not available)", colour=YELLOW)
        _t("Using synthetic scenario (shift.scenario not available)")
        from tests.fixtures.synthetic_scenario import build_all  # type: ignore[import]

        scenario_root = out_dir / "scenario"
        assets = build_all(scenario_root)
        data_path = assets["data"]
        model_path = assets["model"]
        records_path = assets["records"]
    time.sleep(0.3)

    # ── 3. Full signed audit ──────────────────────────────────────────────────
    _step(3, total, "Run full signed audit (cvassure audit ...)")
    _t("\n=== [3/8] Full signed audit ===")
    _print(
        f"  $ cvassure audit --data {data_path} --model {model_path} "
        f"--records {records_path} --privkey {priv_path} --pubkey {pub_path}",
        colour=DIM,
    )

    from cvassure.core.pipeline import run_audit

    t0 = time.monotonic()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = run_audit(
            data=data_path,
            model=model_path,
            records=records_path,
            out_dir=out_dir,
            privkey_path=priv_path,
            pubkey_path=pub_path,
            emit=lambda s: None,
        )
    elapsed = time.monotonic() - t0
    m, s = divmod(int(elapsed), 60)

    for stage in result.stages:
        marker = {
            "ok": "PASS",
            "clean": "PASS",
            "skipped": "SKIP",
            "error": "FAIL",
        }.get(stage.status, "?")
        colour = (
            GREEN
            if stage.status in ("ok", "clean")
            else YELLOW
            if stage.status == "skipped"
            else RED
        )
        _print(f"  [{marker}] [{stage.index}/5] {stage.label:<38} {stage.detail}", colour=colour)
        _t(f"  [{marker}] [{stage.index}/5] {stage.label:<38} {stage.detail}")

    if result.link_line:
        _print(f"\n  LINK  {result.link_line}", colour=BLUE)
        _t(f"  LINK  {result.link_line}")
    _print(f"  DISPOSITION  {result.disposition_line}", colour=BLUE)
    _t(f"  DISPOSITION  {result.disposition_line}")
    _print(
        f"\n  Report: {result.report_path}  sha256 {result.report_file_sha256[:12]}...",
        colour=GREEN,
    )
    _print(f"  Audit log: {out_dir / 'audit.log'}  Time: {m}:{s:02d}", colour=GREEN)
    _t(f"  Report: {result.report_path}")
    _t(f"  Time: {m}:{s:02d}")
    time.sleep(0.5)

    # ── 4. Show QR content ────────────────────────────────────────────────────
    _step(4, total, "Report QR code content")
    _t("\n=== [4/8] QR code ===")
    from cvassure.provenance.qr import payload_qr_content

    qr_content = payload_qr_content(result.manifest.get("payload_sha256", ""))
    _print(f"  QR encodes: {qr_content}", colour=BLUE)
    _t(f"  QR: {qr_content}")
    _info("Open out/report.html to see the interactive dashboard.")
    time.sleep(0.3)

    # ── 5. Verify log ─────────────────────────────────────────────────────────
    _step(5, total, "Verify audit log - clean chain")
    _t("\n=== [5/8] Verify clean log ===")
    _print(f"  $ cvassure verify-log {out_dir / 'audit.log'} --pubkey {pub_path}", colour=DIM)
    from cvassure.provenance.verify import verify_signed_log

    log_path = out_dir / "audit.log"
    expected_head = result.manifest.get("audit_head")
    res = verify_signed_log(log_path, pub_path, expected_head=expected_head)
    if res.ok:
        _ok(f"chain and {res.entries} signatures verified (signed)  head {res.head[:12]}...")
        _t(f"PASS: {res.reason}")
    else:
        _fail(f"Unexpected failure: {res.reason}")
        _t(f"FAIL: {res.reason}")
    time.sleep(0.3)

    # ── 6. Live tamper ────────────────────────────────────────────────────────
    _step(6, total, "Live tamper: edit one output -> REJECTED instantly")
    _t("\n=== [6/8] Live tamper ===")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    original_line = lines[2]
    entry = json.loads(lines[2])
    entry["data"]["tampered"] = True
    lines[2] = json.dumps(entry)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _print("  [edit] Modified entry #3 body field", colour=YELLOW)
    _t("  [edit] Modified entry #3 body field")

    res_tampered = verify_signed_log(log_path, pub_path)
    if not res_tampered.ok:
        _fail(f"REJECTED: {res_tampered.reason}")
        _t(f"REJECTED: {res_tampered.reason}")
    else:
        _print("  WARNING: tamper not detected (unexpected)", colour=YELLOW)
        _t("WARNING: tamper not detected")

    # Restore
    lines[2] = original_line
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _info("Log restored to clean state.")
    time.sleep(0.3)

    # ── 7. Live replay ────────────────────────────────────────────────────────
    _step(7, total, "Live replay: duplicate a record -> nonce reused -> REJECTED")
    _t("\n=== [7/8] Live replay ===")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines.append(lines[0])  # replay first entry
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    json.loads(lines[0]).get("data", {}).get("nonce", "?")
    _print("  [replay] Duplicated entry #1 at end", colour=YELLOW)
    _t("  [replay] Duplicated entry #1 at end")

    from cvassure.provenance.verify import detect_all_tampering

    evidence = detect_all_tampering(log_path, pub_path)
    replay_hits = [e for e in evidence if e.attack == "replay"]
    if replay_hits:
        _fail(f"REJECTED: {replay_hits[0].reason[:80]}")
        _t(f"REJECTED (replay): {replay_hits[0].reason}")
    else:
        _print("  WARNING: replay not detected (unexpected)", colour=YELLOW)
        _t("WARNING: replay not detected")

    # Restore
    log_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    _info("Log restored to clean state.")
    time.sleep(0.3)

    # ── 8. Merkle root ────────────────────────────────────────────────────────
    _step(8, total, "Merkle root from manifest")
    _t("\n=== [8/8] Merkle root ===")
    merkle_root = result.manifest.get("merkle_root")
    if merkle_root:
        _ok(f"Merkle root: {merkle_root[:24]}...")
        _t(f"Merkle root: {merkle_root}")
    else:
        _info("No Merkle root in manifest (built as stretch feature).")
        _t("No Merkle root in manifest.")

    # ── Summary ───────────────────────────────────────────────────────────────
    _print(f"\n{BOLD}{'-' * 60}{RESET}")
    _print(f"{BOLD}Demo complete in {m}:{s:02d}.{RESET}")
    _print(f"  Report:   {result.report_path}", colour=GREEN)
    _print(f"  Audit log: {log_path}", colour=GREEN)
    _print(f"  Public key: {pub_path}", colour=GREEN)
    _t(f"\n=== Demo complete in {m}:{s:02d} ===")

    transcript_path = out_dir / "demo_transcript.txt"
    transcript_path.write_text("\n".join(transcript) + "\n", encoding="utf-8")
    _info(f"Transcript: {transcript_path}")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="CVAssure Person 4 demo script")
    parser.add_argument("--out", default="demo_out", help="Output directory")
    parser.add_argument("--seed", type=int, default=42, help="Scenario seed")
    args = parser.parse_args()

    run_demo(Path(args.out), seed=args.seed)


if __name__ == "__main__":
    main()
