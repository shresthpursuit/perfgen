"""Minimal entrypoint so M1 runs end to end.

The real CLI, config loading and run summary are M5. This is deliberately thin — enough to turn an
IR file into a script and say what happened.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from perfgen.emit import emit
from perfgen.ir.gaps import blocking, detect_gaps, format_gaps
from perfgen.ir.io import load_ir
from perfgen.validate import validate_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="perfgen", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    emit_cmd = sub.add_parser("emit", help="IR YAML -> .jmx")
    emit_cmd.add_argument("ir", type=Path, help="path to a Test Plan IR YAML file")
    emit_cmd.add_argument(
        "--out", type=Path, default=Path("outputs"), help="output root (default: outputs)"
    )
    emit_cmd.add_argument("--jmeter-version", default="5.6.3")

    args = parser.parse_args(argv)
    if args.command == "emit":
        return _emit(args.ir, args.out, args.jmeter_version)
    return 2  # pragma: no cover - argparse enforces the choices


def _emit(ir_path: Path, out_root: Path, jmeter_version: str) -> int:
    ir = load_ir(ir_path)

    gaps = detect_gaps(ir)
    if gaps:
        print(f"Gaps found in {ir_path}:", file=sys.stderr)
        print(format_gaps(gaps), file=sys.stderr)
    if blocking(gaps):
        print(
            f"\n{len(blocking(gaps))} blocking gap(s). Nothing was generated — fill in the "
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
