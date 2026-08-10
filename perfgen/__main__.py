"""Minimal entrypoint so M1 runs end to end.

The real CLI, config loading and run summary are M5. This is deliberately thin — enough to turn an
IR file into a script and say what happened.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

from perfgen.emit import emit
from perfgen.emit.naming import slug
from perfgen.ir.gaps import blocking, detect_gaps, format_gaps
from perfgen.ir.io import dump_ir, load_ir
from perfgen.parse import parse_workbook
from perfgen.validate import validate_file


def _use_utf8_console() -> None:
    """Stop a non-ASCII spec from crashing the run on a legacy Windows console.

    The default Windows console encoding is cp1252, which cannot represent most of what a user
    might legitimately type into the spreadsheet - an application named 'Cafe' with an accent, a
    non-Latin flow name. Printing it would raise UnicodeEncodeError and lose the whole report
    rather than the one character.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            # A detached or already-closed stream is not worth failing the run over.
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _use_utf8_console()
    parser = argparse.ArgumentParser(prog="perfgen", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    parse_cmd = sub.add_parser("parse", help="specification workbook -> IR YAML")
    parse_cmd.add_argument("workbook", type=Path, help="path to a filled-in .xlsx specification")
    parse_cmd.add_argument(
        "--out",
        type=Path,
        default=Path("data/ir"),
        help="directory for the generated IR YAML (default: data/ir)",
    )

    emit_cmd = sub.add_parser("emit", help="IR YAML -> .jmx")
    emit_cmd.add_argument("ir", type=Path, help="path to a Test Plan IR YAML file")
    emit_cmd.add_argument(
        "--out", type=Path, default=Path("outputs"), help="output root (default: outputs)"
    )
    emit_cmd.add_argument("--jmeter-version", default="5.6.3")

    args = parser.parse_args(argv)
    if args.command == "parse":
        return _parse(args.workbook, args.out)
    if args.command == "emit":
        return _emit(args.ir, args.out, args.jmeter_version)
    return 2  # pragma: no cover - argparse enforces the choices


def _parse(workbook_path: Path, out_dir: Path) -> int:
    result = parse_workbook(workbook_path)

    # parse_workbook already folds the structural checks in, so everything wrong with the
    # spreadsheet arrives in one list rather than one problem per run.
    gaps = result.gaps

    if gaps:
        print(f"Gaps found in {workbook_path}:", file=sys.stderr)
        print(format_gaps(gaps), file=sys.stderr)

    for note in result.notes:
        print(f"  [note]     {note}", file=sys.stderr)

    if result.ir is None or blocking(gaps):
        count = len(blocking(gaps))
        print(
            f"\n{count} blocking gap(s). No test plan was written - fill in the values named "
            f"above and run again.",
            file=sys.stderr,
        )
        return 1

    target = dump_ir(result.ir, Path(out_dir) / f"{slug(result.ir.application.name)}.yaml")
    print(f"Wrote {target}")
    print(
        f"  {len(result.ir.flows)} flow(s), "
        f"{sum(len(f.steps) for f in result.ir.flows)} step(s), "
        f"{len(result.ir.enabled_profiles)} enabled load profile(s), "
        f"{len(result.ir.sla)} SLA target(s)"
    )
    print(
        "\nCorrelations are not filled in yet - the probe (M3) and correlation engine (M4) "
        "supply them.\nNext:\n  perfgen emit " + str(target)
    )
    return 0


def _emit(ir_path: Path, out_root: Path, jmeter_version: str) -> int:
    ir = load_ir(ir_path)

    gaps = detect_gaps(ir)
    if gaps:
        print(f"Gaps found in {ir_path}:", file=sys.stderr)
        print(format_gaps(gaps), file=sys.stderr)
    if blocking(gaps):
        print(
            f"\n{len(blocking(gaps))} blocking gap(s). Nothing was generated - fill in the "
            f"missing values and run again.",
            file=sys.stderr,
        )
        return 1

    result = emit(ir, out_root, jmeter_version)
    report = validate_file(result.jmx_path)

    print(f"Wrote {result.jmx_path}")
    for path in result.property_files:
        print(f"      {path}")
    if result.sla_path:
        print(f"      {result.sla_path}")

    if result.warnings:
        print("\nWarnings:")
        for warning in result.warnings:
            print(f"  ! {warning}")

    print(f"\n{report}")
    if not report.ok:
        return 1

    first_profile = result.property_files[0].name if result.property_files else None
    if first_profile:
        print(
            f"\nRun it:\n  jmeter -n -q {result.property_files[0]} "
            f"-t {result.jmx_path} -l results.jtl"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
