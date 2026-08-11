"""The `perfgen emit` entrypoint, end to end.

The exit code is the contract: blocking gaps must stop the run and generate nothing.
"""

from __future__ import annotations

import yaml

from perfgen.__main__ import main
from perfgen.ir.io import dump_ir, load_ir
from perfgen.validate import validate_file
from tests.fixtures.workbooks import WorkbookSpec, set_application_value, write_workbook


def test_emit_writes_jmx_properties_and_sla(tmp_path, auth_shared_token):
    ir_path = tmp_path / "ir.yaml"
    dump_ir(auth_shared_token, ir_path)

    exit_code = main(["emit", str(ir_path), "--out", str(tmp_path / "out")])
    assert exit_code == 0

    out_dir = tmp_path / "out" / "order_management"
    assert (out_dir / "order_management.jmx").exists()
    assert (out_dir / "baseline.properties").exists()
    assert (out_dir / "peak.properties").exists()
    assert (out_dir / "sla_criteria.yaml").exists()
    assert validate_file(out_dir / "order_management.jmx").ok


def test_only_enabled_profiles_get_property_files(tmp_path, auth_shared_token):
    ir_path = tmp_path / "ir.yaml"
    dump_ir(auth_shared_token, ir_path)
    main(["emit", str(ir_path), "--out", str(tmp_path / "out")])

    out_dir = tmp_path / "out" / "order_management"
    assert not (out_dir / "capacity.properties").exists()
    assert not (out_dir / "endurance.properties").exists()


def test_property_file_thread_counts_sum_to_the_profile_total(tmp_path, auth_shared_token):
    ir_path = tmp_path / "ir.yaml"
    dump_ir(auth_shared_token, ir_path)
    main(["emit", str(ir_path), "--out", str(tmp_path / "out")])

    text = (tmp_path / "out" / "order_management" / "peak.properties").read_text()
    values = dict(
        line.split("=", 1)
        for line in text.splitlines()
        if line and not line.startswith("#")
    )
    assert int(values["users_F01"]) + int(values["users_F02"]) == 80
    assert values["rampup_s"] == "180"
    assert values["duration_s"] == "1800"


def test_blocking_gap_exits_non_zero_and_writes_nothing(tmp_path, simple_flow, capsys):
    """D3: throughput set, users absent, on an enabled profile."""
    from perfgen.ir.models import Throughput, ThroughputUnit

    simple_flow.load_profiles[0].users = None
    simple_flow.load_profiles[0].throughput = Throughput(value=1200, unit=ThroughputUnit.TPH)

    ir_path = tmp_path / "ir.yaml"
    dump_ir(simple_flow, ir_path)
    out_root = tmp_path / "out"

    exit_code = main(["emit", str(ir_path), "--out", str(out_root)])

    assert exit_code == 1
    assert not out_root.exists(), "nothing should be generated when a blocking gap is present"

    report = capsys.readouterr().out
    assert "BLOCKING" in report
    assert "Load profiles, row 2 (Baseline)" in report
    assert "Concurrent users" in report


def test_warning_gap_does_not_block(tmp_path, simple_flow):
    simple_flow.load_profiles[0].ramp_up_s = None
    ir_path = tmp_path / "ir.yaml"
    dump_ir(simple_flow, ir_path)
    assert main(["emit", str(ir_path), "--out", str(tmp_path / "out")]) == 0


def test_sla_criteria_written_outside_the_script(tmp_path, auth_shared_token):
    """SLAs never become per-sample assertions inside the JMX."""
    ir_path = tmp_path / "ir.yaml"
    dump_ir(auth_shared_token, ir_path)
    main(["emit", str(ir_path), "--out", str(tmp_path / "out")])

    out_dir = tmp_path / "out" / "order_management"
    criteria = yaml.safe_load((out_dir / "sla_criteria.yaml").read_text())
    assert criteria["application"] == "Order management"
    assert {"scope": "all", "metric": "response_time_p95", "target": 800.0, "unit": "ms"} in (
        criteria["criteria"]
    )

    jmx = (out_dir / "order_management.jmx").read_text(encoding="utf-8")
    assert "DurationAssertion" not in jmx


def test_output_is_namespaced_per_application(tmp_path, simple_flow, auth_shared_token):
    out_root = tmp_path / "out"
    for ir in (simple_flow, auth_shared_token):
        path = tmp_path / f"{ir.application.name}.yaml"
        dump_ir(ir, path)
        main(["emit", str(path), "--out", str(out_root)])

    assert (out_root / "catalogue_browse").is_dir()
    assert (out_root / "order_management").is_dir()


# --------------------------------------------------------------------------------------------
# perfgen parse - workbooks are always generated, never the shipped data/specs/*.xlsx
# --------------------------------------------------------------------------------------------


def test_parse_writes_an_ir_file(tmp_path):
    workbook = write_workbook(tmp_path / "spec.xlsx")
    exit_code = main(["parse", str(workbook), "--out", str(tmp_path / "ir")])

    assert exit_code == 0
    target = tmp_path / "ir" / "claims_intake_service.yaml"
    assert target.exists()

    ir = load_ir(target)
    assert ir.application.name == "Claims intake service"
    assert len(ir.flows) == 2


def test_parse_output_is_valid_ir_that_round_trips(tmp_path):
    workbook = write_workbook(tmp_path / "spec.xlsx")
    main(["parse", str(workbook), "--out", str(tmp_path / "ir")])
    ir = load_ir(tmp_path / "ir" / "claims_intake_service.yaml")
    assert ir.provenance.source_workbook == "spec.xlsx"


def test_parse_exits_non_zero_on_a_blocking_gap_and_writes_nothing(tmp_path, capsys):
    spec = set_application_value(WorkbookSpec(), "Base URL", None)
    workbook = write_workbook(tmp_path / "spec.xlsx", spec)
    out_dir = tmp_path / "ir"

    exit_code = main(["parse", str(workbook), "--out", str(out_dir)])

    assert exit_code == 1
    assert not out_dir.exists(), "no IR should be written when a blocking gap is present"
    report = capsys.readouterr().out
    assert "BLOCKING" in report
    assert "Base URL" in report


def test_parse_reports_warnings_but_still_succeeds(tmp_path, capsys):
    spec = set_application_value(WorkbookSpec(), "Auth header value format", "Bearer")
    workbook = write_workbook(tmp_path / "spec.xlsx", spec)
    assert main(["parse", str(workbook), "--out", str(tmp_path / "ir")]) == 0
    assert "warning" in capsys.readouterr().out


def test_parse_surfaces_structural_gaps_not_just_parse_gaps(tmp_path, capsys):
    """D3 lives in detect_gaps; parse must report it so the sheet is fixed in one pass."""
    spec = WorkbookSpec()
    baseline = next(row for row in spec.profiles if row[0] == "Baseline")
    baseline[2] = None  # users blank, throughput still set

    workbook = write_workbook(tmp_path / "spec.xlsx", spec)
    exit_code = main(["parse", str(workbook), "--out", str(tmp_path / "ir")])

    assert exit_code == 1
    report = capsys.readouterr().out
    assert "load_profiles.baseline.users" in report
    assert "Concurrent users" in report


def test_missing_token_expression_does_not_block_parsing(tmp_path, capsys):
    """The probe supplies it next; blocking here would make every OAuth spec unparseable."""
    workbook = write_workbook(tmp_path / "spec.xlsx")
    assert main(["parse", str(workbook), "--out", str(tmp_path / "ir")]) == 0
    assert "auth.token_extract.expr" in capsys.readouterr().out


def test_parsed_ir_is_not_yet_emittable_without_a_probe(tmp_path):
    """Parse succeeds, but emit blocks on the same field - the stages disagree on purpose."""
    workbook = write_workbook(tmp_path / "spec.xlsx")
    main(["parse", str(workbook), "--out", str(tmp_path / "ir")])

    ir_path = tmp_path / "ir" / "claims_intake_service.yaml"
    assert main(["emit", str(ir_path), "--out", str(tmp_path / "out")]) == 1
