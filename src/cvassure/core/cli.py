"""CLI. Eight commands, fixed exit codes.

Numbers printed by `audit` come from that run. `--plain` turns colours off.

Exit codes are in `errors.ExitCode`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from cvassure.core.audit import verify_file
from cvassure.core.errors import BlockedOn, CvassureError, ExitCode
from cvassure.core.finding import draft_schema, final_schema
from cvassure.core.hashing import file_sha256

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Offline computer-vision integrity assurance over data, model and records.",
)

BLUE = "blue"
GREEN = "green"
RED = "red"
YELLOW = "yellow"


def _console(plain: bool) -> Console:
    """Fixed 118-column output.

    The stage lines are a fixed shape that gets diffed between runs and read off
    a projector. Wrapping them at the terminal width would break the diff, so
    the width is pinned and the layout is kept inside it. `--plain` only drops
    colour.
    """
    return Console(no_color=plain, highlight=False, width=118, soft_wrap=False)


def _rel(path: Path) -> str:
    """Path relative to the cwd when possible, so a printed line stays short."""
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return path.name


def _echo(err: typer.Exit, code: int) -> None:
    raise typer.Exit(code)


# ----------------------------------------------------------------------------- audit


@app.command()
def audit(
    data: Path | None = typer.Option(None, help="Dataset directory (COCO json or YOLO labels/)."),
    model: Path | None = typer.Option(None, help="Model file, ONNX or TorchScript."),
    records: Path | None = typer.Option(None, help="Inference records, JSON Lines."),
    policy: Path | None = typer.Option(None, help="Policy YAML. Default from config."),
    config: Path | None = typer.Option(None, help="Run config YAML."),
    out: Path = typer.Option(Path("out"), help="Output directory."),
    seed: int | None = typer.Option(None, help="Run seed."),
    access: str | None = typer.Option(
        None, help="Declared model access tier: white-box|gray-box|black-box"
    ),
    strict: bool = typer.Option(False, help="Exit 5 if any stub ran."),
    reproducible: bool = typer.Option(False, help="Freeze timestamps to the seed."),
    plain: bool = typer.Option(False, help="No colour."),
    fail_on: str | None = typer.Option(
        None, help="Exit 10 if a finding has this disposition: review|quarantine|rejected"
    ),
    stages: str = typer.Option("data,model,records,shift", help="Comma-separated stage list."),
    results: Path | None = typer.Option(None, help="Results CSV for coverage."),
    coverage_rules: Path | None = typer.Option(
        None, help="Coverage rules YAML. Default configs/coverage_rules.yaml."
    ),
    as_json: bool = typer.Option(False, "--json", help="Also print the run manifest as JSON."),
    privkey: Path | None = typer.Option(
        None, "--privkey", help="Ed25519 private key (.key) for signing the audit log."
    ),
    pubkey: Path | None = typer.Option(
        None, "--pubkey", help="Ed25519 public key (.pub) for verification."
    ),
) -> None:
    """Run the audit. Offline, CPU-only, no network."""
    from cvassure.core.pipeline import run_audit

    console = _console(plain)
    stage_list = [s.strip() for s in stages.split(",") if s.strip()]

    # Validate key paths before running
    if privkey and not privkey.is_file():
        console.print(f"[{RED}]--privkey: no such file: {privkey}[/]")
        raise typer.Exit(ExitCode.USAGE)
    if pubkey and not pubkey.is_file():
        console.print(f"[{RED}]--pubkey: no such file: {pubkey}[/]")
        raise typer.Exit(ExitCode.USAGE)

    try:
        result = run_audit(
            data=data,
            model=model,
            records=records,
            out_dir=out,
            config_path=config,
            policy_path=policy,
            coverage_rules=coverage_rules,
            results_csv=results,
            seed=seed,
            access=access,
            stages=stage_list,
            reproducible=reproducible,
            privkey_path=privkey,
            pubkey_path=pubkey,
            emit=lambda s: console.print(f"[dim]{s}[/dim]"),
        )
    except CvassureError as exc:
        console.print(f"[{RED}]{exc}[/]")
        _echo(exc, exc.exit_code)
    except (ValueError, OSError) as exc:
        # Config and policy errors are ValueError subclasses. Exit 2.
        console.print(f"[{RED}]{type(exc).__name__}: {exc}[/]")
        _echo(None, ExitCode.USAGE)

    status_style = {"ok": GREEN, "clean": GREEN, "skipped": YELLOW, "error": RED}
    for line in result.stages:
        style = status_style.get(line.status, GREEN)
        marker = {"ok": "ok", "clean": "clean", "skipped": "skipped", "error": "ERROR"}[line.status]
        console.print(
            f"[{BLUE}][{line.index}/5] {line.label:<42}[/] [{style}]{marker:<9}[/] {line.detail}"
        )

    if result.link_line:
        console.print(f"[{BLUE}]LINK  {result.link_line}[/]")
    console.print(f"[{BLUE}]DISPOSITION  {result.disposition_line}[/]")

    if result.stub_ran:
        console.print(f"[{YELLOW}]STUB  one or more detectors are built-in stubs[/]")

    chain_txt = "chain verified" if result.chain_ok else "CHAIN BROKEN"
    chain_style = GREEN if result.chain_ok else RED
    # Real elapsed time, not the manifest value: under --reproducible the
    # manifest duration is frozen to zero so the payload hash is stable, and a
    # human still wants to know how long the run took.
    total = result.manifest.get("timings", {}).get("total_s") or 0.0
    if result.manifest.get("reproducible"):
        total = result.wall_clock_s
    m, s = divmod(int(total), 60)
    # Short relative paths: the full path makes the line wrap and the wrap
    # breaks the diff between two runs.
    log_path = _rel(result.out_dir / "audit.log")
    report_path = _rel(result.report_path)
    console.print(
        f"Report: {report_path} (sha256 {result.report_file_sha256[:12]})  "
        f"Audit log: {log_path} ([{chain_style}]{chain_txt}[/])  Time: {m}:{s:02d}"
    )
    if result.coverage_warning:
        console.print(f"[{YELLOW}]warning: {result.coverage_warning}[/]")

    if as_json:
        console.print_json(json.dumps(result.manifest, default=str))

    if strict and result.stub_ran:
        _echo(None, ExitCode.STUB)
    if fail_on and any(f.disposition == fail_on for f in result.findings):
        console.print(f"[{RED}]--fail-on {fail_on} tripped[/]")
        _echo(None, ExitCode.FAIL_ON)
    if not result.chain_ok:
        _echo(None, ExitCode.VERIFY)
    if result.detector_errors:
        for e in result.detector_errors:
            console.print(f"[{RED}]detector: {e}[/]", highlight=False)
        _echo(None, ExitCode.DETECTOR)


# ----------------------------------------------------------------------- verify-log


@app.command("verify-log")
def verify_log(
    log: Path = typer.Argument(..., help="Path to audit.log."),
    pubkey: Path | None = typer.Option(None, help="Ed25519 public key for a signed audit log."),
    manifest: Path | None = typer.Option(
        None, help="run_manifest.json, to check the chain head and catch truncation."
    ),
) -> None:
    """Recompute the chain. Catches edit, delete, reorder and truncation."""
    console = _console(False)
    expected = None
    if manifest and manifest.is_file():
        expected = json.loads(manifest.read_text(encoding="utf-8")).get("audit_head")

    if pubkey and pubkey.is_file():
        # Signed log: use the provenance verifier
        try:
            from cvassure.provenance.verify import verify_signed_log

            res = verify_signed_log(log, pubkey, expected_head=expected)
        except ImportError:
            console.print(
                f"[{YELLOW}]provenance package not available; falling back to hash-chain verify[/]"
            )
            res_core = verify_file(log, expected_head=expected)
            if res_core.ok:
                console.print(
                    f"[{GREEN}]chain verified[/]  "
                    f"{res_core.entries} entries, head {res_core.head[:12]}"
                )
                raise typer.Exit(ExitCode.OK) from None
            console.print(f"[{RED}]chain verification FAILED[/]  {res_core.reason}")
            raise typer.Exit(ExitCode.VERIFY) from None
        if res.ok:
            signed_txt = " (signed)" if res.signed else ""
            merkle_txt = f", merkle {res.merkle_root[:12]}" if res.merkle_root else ""
            fp_txt = f", signer {res.pubkey_fp}" if res.pubkey_fp else ""
            console.print(
                f"[{GREEN}]chain verified{signed_txt}[/]  "
                f"{res.entries} entries, head {res.head[:12]}{merkle_txt}{fp_txt}"
            )
            raise typer.Exit(ExitCode.OK)
        console.print(f"[{RED}]chain verification FAILED[/]  {res.reason}")
        raise typer.Exit(ExitCode.VERIFY)

    # No pubkey: hash-chain only
    res_core = verify_file(log, expected_head=expected, allow_signatures=True)
    if res_core.ok:
        console.print(
            f"[{GREEN}]chain verified[/]  {res_core.entries} entries, head {res_core.head[:12]}"
        )
        raise typer.Exit(ExitCode.OK)
    console.print(f"[{RED}]chain verification FAILED[/]  {res_core.reason}")
    raise typer.Exit(ExitCode.VERIFY)


# -------------------------------------------------------------------- verify-report


@app.command("verify-report")
def verify_report(
    report: Path = typer.Argument(..., help="Path to report.html."),
    out: Path | None = typer.Option(None, help="out/ directory, to recompute payload_sha256."),
) -> None:
    """Recompute both hashes: payload_sha256 from out/, file_sha256 from the bytes."""
    console = _console(False)
    if not report.is_file():
        console.print(f"[{RED}]no such report: {report}[/]")
        raise typer.Exit(ExitCode.USAGE)
    file_hash = file_sha256(report)
    console.print(f"file_sha256   {file_hash}")

    if out and out.is_dir():
        from cvassure.core.pipeline import _payload_sha256

        manifest = json.loads((out / "run_manifest.json").read_text(encoding="utf-8"))
        findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        coverage = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
        # Recompute with the same function the pipeline used, from the same
        # three files. If these two ever disagreed, verification would be a
        # second implementation of the rule and could pass a corrupted report.
        from cvassure.core.coverage import Coverage, CoverageRow
        from cvassure.core.finding import Finding

        cov = Coverage(
            rows=[CoverageRow(**r) for r in coverage["rows"]],
            assumptions=coverage.get("assumptions", []),
            thresholds=coverage.get("thresholds", {}),
            warning=coverage.get("warning"),
            declared=coverage.get("declared_unsupported", []),
        )
        payload = _payload_sha256([Finding.model_validate(f) for f in findings], cov, manifest)
        console.print(f"payload_sha256 {payload}")
        if payload != manifest.get("payload_sha256"):
            console.print("[red]payload_sha256 does not match run_manifest.json[/]")
            raise typer.Exit(ExitCode.VERIFY)
        if manifest.get("report_file_sha256") and manifest["report_file_sha256"] != file_hash:
            console.print("[red]file_sha256 does not match run_manifest.json[/]")
            raise typer.Exit(ExitCode.VERIFY)
        console.print("[green]both hashes verified[/]")
        raise typer.Exit(ExitCode.OK)
    console.print("[yellow]no --out given: only the file hash was recomputed[/]")
    raise typer.Exit(ExitCode.OK)


# ------------------------------------------------------------------ list-detectors


@app.command("list-detectors")
def list_detectors(
    config: Path | None = typer.Option(None, help="Run config YAML."),
) -> None:
    """Every registered detector, with owner, version and whether it is a stub."""
    from cvassure.core.config import load_config
    from cvassure.core.registry import build_registry, order_registry

    console = _console(False)
    cfg = load_config(config)
    loaded = order_registry(build_registry(cfg.detector_modules), cfg.detector_order)
    table = Table(title="registered detectors", show_lines=False)
    for col, style in (
        ("id", BLUE),
        ("asset", ""),
        ("owner", ""),
        ("version", ""),
        ("module", "dim"),
        ("stub", ""),
    ):
        table.add_column(col, style=style)
    for item in loaded:
        table.add_row(
            item.id,
            item.asset,
            item.detector.owner,
            item.detector.version,
            item.module,
            "STUB" if item.is_stub else "real",
        )
    console.print(table)


# ---------------------------------------------------------------------------- schema


@app.command()
def schema(
    which: str = typer.Argument("final", help="final | draft"),
    out: Path | None = typer.Option(None, help="Write to this file instead of stdout."),
) -> None:
    """Print the Finding JSON Schema 2020-12 document."""
    if which not in ("final", "draft"):
        console = _console(False)
        console.print(f"[red]which must be 'final' or 'draft', got {which!r}[/]")
        raise typer.Exit(ExitCode.USAGE)
    doc = final_schema() if which == "final" else draft_schema()
    text = json.dumps(doc, indent=2, sort_keys=True)
    if out:
        out.write_text(text + "\n", encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")


# ------------------------------------------------------------------------- coverage


@app.command()
def coverage(
    results: Path | None = typer.Option(None, help="Results CSV for the coverage statement."),
    rules: Path = typer.Option(Path("configs/coverage_rules.yaml"), help="Coverage rules YAML."),
    as_json: bool = typer.Option(False, "--json", help="Print JSON instead of a table."),
) -> None:
    """Derive the coverage statement. No row means Untested, never Supported."""
    from cvassure.core.coverage import build_coverage

    console = _console(False)
    cov = build_coverage(results, rules)
    if as_json:
        console.print_json(json.dumps(cov.to_json(), default=str))
        raise typer.Exit(ExitCode.OK)
    table = Table(title="coverage statement")
    for col in ("attack class", "status", "measured", "n seeds", "why"):
        table.add_column(col)
    for r in cov.rows:
        table.add_row(
            r.attack_class, r.status, r.measured or "-", str(r.n_seeds or "-"), r.reason or "-"
        )
    console.print(table)
    if cov.warning:
        console.print(f"[yellow]warning: {cov.warning}[/]")
    console.print(f"[dim]thresholds: {cov.thresholds}[/]")


# ---------------------------------------------------------------------------- doctor


@app.command()
def doctor() -> None:
    """Environment check. Offline-safe and read-only."""
    import platform
    import shutil
    import sys as _sys

    console = _console(False)
    from cvassure import __version__

    console.print(f"cvassure        {__version__}")
    console.print(f"python          {_sys.version.split()[0]} ({platform.python_implementation()})")
    console.print(f"platform        {platform.system()} {platform.release()} {platform.machine()}")
    for mod in ("pydantic", "yaml", "jsonschema", "typer", "rich", "numpy"):
        try:
            m = __import__(mod)
        except ImportError:
            console.print(f"[red]  {mod:<12} MISSING[/]")
            raise typer.Exit(ExitCode.USAGE) from None
        # importlib.metadata, not `mod.__version__`: jsonschema deprecated the
        # attribute and the warning lands in the middle of the demo output.
        try:
            from importlib.metadata import version

            shown = version(m.__name__.split(".")[0])
        except Exception:
            shown = "installed"
        console.print(f"  {mod:<12} {shown}")
    console.print(f"cpu cores       {__import__('os').cpu_count()}")
    console.print(f"ram             {_ram_gb():.1f} GB")
    console.print("network         not required. The audit path opens no socket.")
    console.print("gpu             not used. CPU-only by design.")
    console.print(f"disk free       {shutil.disk_usage('.').free / 1e9:.1f} GB")
    raise typer.Exit(ExitCode.OK)


def _ram_gb() -> float:
    try:
        import ctypes

        class _MemStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        st = _MemStatus()
        st.dwLength = ctypes.sizeof(_MemStatus)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))  # type: ignore[attr-defined]
        return st.ullTotalPhys / 1024**3
    except Exception:
        try:
            return os_sysinfo_totalram() / 1024**3
        except Exception:
            return 0.0


def os_sysinfo_totalram() -> int:
    import os

    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")


# ------------------------------------------------------------------------------ demo


@app.command("generate-keys")
def generate_keys(
    path: Path = typer.Argument(
        Path("cvassure_key"), help="Base path for key files (no extension)."
    ),
    overwrite: bool = typer.Option(False, help="Overwrite existing key files."),
) -> None:
    """Generate an Ed25519 keypair for signing audit logs and records."""
    console = _console(False)
    try:
        from cvassure.provenance.keys import generate_keypair
    except ImportError:
        console.print(f"[{RED}]PyNaCl is not installed. Run: pip install 'PyNaCl>=1.5,<2'[/]")
        raise typer.Exit(ExitCode.USAGE) from None

    base = path.with_suffix("")
    priv = base.with_suffix(".key")
    pub = base.with_suffix(".pub")

    if not overwrite:
        for p in (priv, pub):
            if p.exists():
                console.print(f"[{RED}]{p} already exists. Use --overwrite to replace.[/]")
                raise typer.Exit(ExitCode.USAGE)

    priv_path, pub_path = generate_keypair(base)
    console.print(f"[{GREEN}]Generated Ed25519 keypair[/]")
    console.print(f"  private key: {priv_path}")
    console.print(f"  public key:  {pub_path}")
    console.print(
        f"[{YELLOW}]Keep the private key secret. Share only the public key for verification.[/]"
    )
    raise typer.Exit(ExitCode.OK)


@app.command()
def demo(seed: int = typer.Option(42, help="Scenario seed.")) -> None:
    """Build the seeded demo scenario when cvassure.shift.scenario is installed."""
    import importlib

    try:
        mod = importlib.import_module("cvassure.shift.scenario")
    except Exception as exc:
        raise BlockedOn(
            "scenario", f"build_demo_scenario is not importable ({type(exc).__name__})"
        ) from exc
    builder = getattr(mod, "build_demo_scenario", None)
    if builder is None:
        raise BlockedOn("scenario", "cvassure.shift.scenario has no build_demo_scenario")
    scenario = builder(seed=seed)
    console = _console(False)
    console.print(f"scenario seed {seed}")
    for attr in ("data_dir", "model_path", "records_path", "manifest_path"):
        value = getattr(scenario, attr, None)
        if value is not None:
            console.print(f"  {attr:<14} {value}")
    raise typer.Exit(ExitCode.OK)


def main() -> None:  # pragma: no cover - entry point
    try:
        app()
    except CvassureError as exc:
        _console(False).print(f"[{RED}]{exc}[/]")
        raise SystemExit(exc.exit_code) from exc


if __name__ == "__main__":  # pragma: no cover
    main()
