"""The perfgen command line.

Five commands. `run` is the one the target user needs - spreadsheet in, script out - and the four
stage commands exist because every stage writes its artifact to disk and is independently
re-runnable from the previous stage's output. Re-probing a spec without re-parsing it, or
re-emitting after hand-editing the IR, are both ordinary things to want.

Every command finishes with a run summary. Its most important job is not saying what worked: it is
making the parts that were guessed impossible to skim past. See `perfgen.summary`.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

from perfgen import secrets
from perfgen.config import Config, load_config
from perfgen.correlate import ClaudeAdjudicator, correlate
from perfgen.emit import emit
from perfgen.emit.naming import slug
from perfgen.ir.gaps import blocking, detect_gaps
from perfgen.ir.io import dump_ir, load_ir
from perfgen.ir.models import TestPlanIR
from perfgen.parse import parse_workbook
from perfgen.probe import apply_outcome, dump_record, load_record, run_probe
from perfgen.summary import RunSummary, exit_code_for, summarise
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="perfgen",
        description="Read a filled-in API specification workbook and emit a JMeter test plan.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="path to config.yaml (default: found by searching upwards from the working directory)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_cmd = sub.add_parser("run", help="workbook -> .jmx, all stages")
    run_cmd.add_argument("workbook", type=Path, help="path to a filled-in .xlsx specification")
    run_cmd.add_argument(
        "--no-probe", action="store_true", help="skip the probe; correlations become inferred"
    )
    run_cmd.add_argument(
        "--no-llm", action="store_true", help="skip adjudication; run the scan only"
    )

    parse_cmd = sub.add_parser("parse", help="specification workbook -> IR YAML")
    parse_cmd.add_argument("workbook", type=Path, help="path to a filled-in .xlsx specification")
    parse_cmd.add_argument("--out", type=Path, default=None, help="directory for the IR YAML")

    probe_cmd = sub.add_parser("probe", help="run the spec once and record the traffic")
    probe_cmd.add_argument("ir", type=Path, help="path to a Test Plan IR YAML file")
    probe_cmd.add_argument("--out", type=Path, default=None, help="directory for the record")
    probe_cmd.add_argument("--timeout", type=int, default=None, help="per-request timeout, seconds")

    correlate_cmd = sub.add_parser(
        "correlate", help="traffic record + IR -> extractors wired into the IR"
    )
    correlate_cmd.add_argument("ir", type=Path, help="path to a Test Plan IR YAML file")
    correlate_cmd.add_argument("--record", type=Path, default=None, help="traffic record")
    correlate_cmd.add_argument(
        "--no-llm", action="store_true", help="run the scan and report it without adjudicating"
    )

    emit_cmd = sub.add_parser("emit", help="IR YAML -> .jmx")
    emit_cmd.add_argument("ir", type=Path, help="path to a Test Plan IR YAML file")
    emit_cmd.add_argument("--out", type=Path, default=None, help="output root")
    emit_cmd.add_argument("--jmeter-version", default=None, help="overrides config.yaml")
    return parser


def main(argv: list[str] | None = None) -> int:
    _use_utf8_console()
    args = build_parser().parse_args(argv)

    try:
        config = load_config(args.config)
    except (ValueError, OSError) as exc:
        print(f"Could not read configuration: {exc}", file=sys.stderr)
        return 2

    if args.command == "run":
        return _run(args, config)
    if args.command == "parse":
        return _parse(args, config)
    if args.command == "probe":
        return _probe(args, config)
    if args.command == "correlate":
        return _correlate(args, config)
    if args.command == "emit":
        return _emit(args, config)
    return 2  # pragma: no cover - argparse enforces the choices


def _report(summary: RunSummary) -> int:
    print(summary.render())
    return exit_code_for(summary)


def _ir_path_for(ir: TestPlanIR, config: Config, override: Path | None = None) -> Path:
    directory = override or config.paths.ir
    return Path(directory) / f"{slug(ir.application.name)}.yaml"


def _probe_stage(ir: TestPlanIR, outcome) -> str:
    """One line describing how the probe went, placed in the stage list in run order."""
    detail = "DEGRADED - no traffic captured" if outcome.degraded else ir.application.base_url
    skipped = outcome.record.skipped_flow_ids
    if skipped:
        detail += f"; skipped {', '.join(skipped)} (marked unsafe)"
    return f"probe: {detail}"


# --------------------------------------------------------------------------------------------
# Stages
# --------------------------------------------------------------------------------------------


def _parse(args, config: Config) -> int:
    result = parse_workbook(args.workbook)

    if result.ir is None or blocking(result.gaps):
        summary = RunSummary(
            application=str(args.workbook),
            stages=[f"parse: {args.workbook}"],
            gaps=result.gaps,
            notes=result.notes,
            config_warnings=config.warnings(),
        )
        print(summary.render())
        print(
            f"\n{len(blocking(result.gaps))} blocking gap(s). Nothing was written - fill in the "
            f"values named above and run again."
        )
        return 1

    target = dump_ir(result.ir, _ir_path_for(result.ir, config, args.out))
    summary = summarise(
        result.ir,
        stages=[f"parse: {args.workbook}"],
        artifacts=[target],
        gaps=result.gaps,
        notes=result.notes,
        config_warnings=config.warnings(),
        next_command=f"perfgen probe {target}",
    )
    return _report(summary)


def _probe(args, config: Config) -> int:
    secrets.load_dotenv()
    ir = load_ir(args.ir)

    outcome = run_probe(ir, timeout_s=args.timeout or config.probe.timeout_s)
    record_dir = args.out or config.paths.probe_records
    record_path = dump_record(
        outcome.record, Path(record_dir) / f"{slug(ir.application.name)}.json"
    )
    apply_outcome(ir, outcome)
    dump_ir(ir, args.ir)  # the IR accumulates through the stages, so it is updated in place

    summary = summarise(
        ir,
        stages=[_probe_stage(ir, outcome)],
        artifacts=[record_path, Path(args.ir)],
        warnings=outcome.warnings,
        config_warnings=config.warnings(),
        notes=[
            "The traffic record holds real response bodies and is written to a gitignored "
            "directory. Credentials and the auth token are redacted; response bodies are not."
        ],
        next_command=f"perfgen correlate {args.ir}",
    )
    return _report(summary)


def _correlate(args, config: Config) -> int:
    ir = load_ir(args.ir)

    source = args.record or Path(config.paths.probe_records) / f"{slug(ir.application.name)}.json"
    record = load_record(source) if Path(source).is_file() else None

    adjudicator = None if args.no_llm else ClaudeAdjudicator.from_config(config)
    outcome = correlate(ir, record, adjudicator)
    dump_ir(ir, args.ir)

    stages = [f"correlate: {outcome.scan.summary}"]
    notes = [
        f"filtered out {rejection.value!r} - {rejection.reason}"
        for rejection in outcome.scan.rejected[:10]
    ]
    if len(outcome.scan.rejected) > 10:
        notes.append(f"...and {len(outcome.scan.rejected) - 10} more filtered values")
    if record is None:
        notes.insert(0, f"No traffic record at {source}; correlations are inferred from names.")

    summary = summarise(
        ir,
        stages=stages,
        artifacts=[Path(args.ir)],
        warnings=outcome.warnings,
        notes=notes,
        config_warnings=config.warnings(),
        llm_called=outcome.llm_called,
        llm_skip_reason=outcome.skip_reason,
        next_command=f"perfgen emit {args.ir}",
    )
    return _report(summary)


def _emit(args, config: Config) -> int:
    ir = load_ir(args.ir)
    gaps = detect_gaps(ir)

    if blocking(gaps):
        summary = summarise(
            ir, stages=["emit"], gaps=gaps, config_warnings=config.warnings()
        )
        print(summary.render())
        print(
            f"\n{len(blocking(gaps))} blocking gap(s). Nothing was generated - fill in the "
            f"missing values and run again."
        )
        return 1

    version = args.jmeter_version or config.jmeter.version
    result = emit(ir, args.out or config.paths.outputs, version)
    report = validate_file(result.jmx_path)

    artifacts = [result.jmx_path, *result.property_files]
    if result.sla_path:
        artifacts.append(result.sla_path)

    warnings = list(result.warnings)
    if not report.ok:
        warnings.extend(report.errors)

    run_hint = (
        f"jmeter -n -q {result.property_files[0]} -t {result.jmx_path} -l results.jtl"
        if result.property_files
        else f"jmeter -n -t {result.jmx_path} -l results.jtl"
    )

    summary = summarise(
        ir,
        stages=[f"emit: JMeter {version}", f"validate: {report}"],
        artifacts=artifacts,
        gaps=gaps,
        warnings=warnings,
        config_warnings=config.warnings(),
        next_command=run_hint,
    )
    code = _report(summary)
    return 1 if not report.ok else code


# --------------------------------------------------------------------------------------------
# End to end
# --------------------------------------------------------------------------------------------


def _run(args, config: Config) -> int:
    """Spreadsheet in, script out. Every stage still writes its artifact on the way through."""
    secrets.load_dotenv()
    stages: list[str] = []
    artifacts: list[Path] = []
    warnings: list[str] = []
    notes: list[str] = []

    parsed = parse_workbook(args.workbook)
    stages.append(f"parse: {args.workbook}")
    notes.extend(parsed.notes)

    if parsed.ir is None or blocking(parsed.gaps):
        summary = RunSummary(
            application=str(args.workbook),
            stages=stages,
            gaps=parsed.gaps,
            notes=notes,
            config_warnings=config.warnings(),
        )
        print(summary.render())
        print(
            f"\n{len(blocking(parsed.gaps))} blocking gap(s). Nothing was generated - fill in "
            f"the values named above and run again."
        )
        return 1

    ir = parsed.ir
    ir_path = dump_ir(ir, _ir_path_for(ir, config))
    artifacts.append(ir_path)

    record = None
    if config.probe.enabled and not args.no_probe:
        outcome = run_probe(ir, timeout_s=config.probe.timeout_s)
        record = outcome.record
        record_path = dump_record(
            record, Path(config.paths.probe_records) / f"{slug(ir.application.name)}.json"
        )
        artifacts.append(record_path)
        apply_outcome(ir, outcome)
        warnings.extend(outcome.warnings)
        stages.append(_probe_stage(ir, outcome))
    else:
        reason = "--no-probe" if args.no_probe else "probe.enabled is false in config"
        stages.append(f"probe: skipped ({reason})")
        notes.append(
            f"The probe was skipped ({reason}), so nothing was verified against the real "
            f"service and every correlation below is inferred."
        )

    adjudicator = None if args.no_llm else ClaudeAdjudicator.from_config(config)
    correlation = correlate(ir, record, adjudicator)
    stages.append(f"correlate: {correlation.scan.summary}")
    if correlation.llm_called:
        stages.append("correlate: one adjudication call")
    elif correlation.skip_reason:
        stages.append(f"correlate: no model call - {correlation.skip_reason.split('.')[0]}")
    warnings.extend(correlation.warnings)

    dump_ir(ir, ir_path)

    gaps = detect_gaps(ir)
    if blocking(gaps):
        summary = summarise(
            ir, stages=stages, artifacts=artifacts, gaps=gaps, warnings=warnings, notes=notes,
            config_warnings=config.warnings(), llm_called=correlation.llm_called,
            llm_skip_reason=correlation.skip_reason,
        )
        print(summary.render())
        return 1

    result = emit(ir, config.paths.outputs, config.jmeter.version)
    report = validate_file(result.jmx_path)
    artifacts.extend([result.jmx_path, *result.property_files])
    if result.sla_path:
        artifacts.append(result.sla_path)
    warnings.extend(result.warnings)
    if not report.ok:
        warnings.extend(report.errors)
    stages.append(f"emit: JMeter {config.jmeter.version}")
    stages.append(f"validate: {report}")

    run_hint = (
        f"jmeter -n -q {result.property_files[0]} -t {result.jmx_path} -l results.jtl"
        if result.property_files
        else f"jmeter -n -t {result.jmx_path} -l results.jtl"
    )

    summary = summarise(
        ir,
        stages=stages,
        artifacts=artifacts,
        gaps=gaps,
        warnings=warnings,
        notes=notes,
        config_warnings=config.warnings(),
        llm_called=correlation.llm_called,
        llm_skip_reason=correlation.skip_reason,
        next_command=run_hint,
    )
    code = _report(summary)
    return 1 if not report.ok else code


if __name__ == "__main__":
    raise SystemExit(main())
