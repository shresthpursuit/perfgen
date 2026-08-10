"""The `perfgen emit` entrypoint, end to end.

The exit code is the contract: blocking gaps must stop the run and generate nothing.
"""

from __future__ import annotations

import yaml

from perfgen.__main__ import main
from perfgen.ir.io import dump_ir
from perfgen.validate import validate_file


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

    stderr = capsys.readouterr().err
    assert "BLOCKING" in stderr
    assert "Load profiles, row 2 (Baseline)" in stderr
    assert "Concurrent users" in stderr


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
