"""`perfgen run` - spreadsheet in, script out.

Uses a generated workbook and a stub HTTP server on a loopback port. The tool is never run against
`data/specs/*.xlsx` here or anywhere else in the suite; that is the user's call, not a test step
(see CLAUDE.md).
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from perfgen.__main__ import main
from perfgen.ir.io import load_ir
from perfgen.validate import validate_file
from tests.fixtures.workbooks import WorkbookSpec, set_application_value, write_workbook

TOKEN = "tok-run-e2e-9f2c"
ITEM_ID = "ITEM-run-e2e-abcdef"


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if self.path.endswith("/token"):
            self._send(200, {"access_token": TOKEN, "expires_in": 3600})
        else:
            self._send(201, {"requestRef": "REQ-run-e2e-7d3e"})

    def do_GET(self):
        if "/catalogue/search" in self.path:
            self._send(200, {"results": [{"id": ITEM_ID, "name": "Widget"}]})
        elif "/catalogue/items/" in self.path:
            self._send(200, {"id": self.path.rsplit("/", 1)[-1], "stock": 7})
        else:
            self._send(200, {"state": "pending"})

    def log_message(self, *args):
        pass


@pytest.fixture
def stub_api():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def credentials(monkeypatch):
    monkeypatch.setenv("CLAIMS_PERF_ID", "id-value")
    monkeypatch.setenv("CLAIMS_PERF_SECRET", "secret-value")
    monkeypatch.setenv("GRANT_TYPE", "client_credentials")


def spec_for(base_url: str) -> WorkbookSpec:
    spec = WorkbookSpec()
    set_application_value(spec, "Base URL", base_url)
    set_application_value(spec, "Base path", "/v1")
    set_application_value(spec, "Token endpoint URL", f"{base_url}/oauth2/token")
    # Both flows are safe here so the probe walks them; F02 is unsafe by default.
    spec.flows[1][4] = "Yes"
    return spec


def config_at(tmp_path) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(
        "probe:\n  enabled: true\n  timeout_s: 10\n"
        "jmeter:\n  version: '5.6.3'\n"
        f"paths:\n  ir: {(tmp_path / 'ir').as_posix()}\n"
        f"  probe_records: {(tmp_path / 'probe').as_posix()}\n"
        f"  outputs: {(tmp_path / 'out').as_posix()}\n",
        encoding="utf-8",
    )
    return str(path)


def test_workbook_to_jmx_in_one_command(tmp_path, stub_api, credentials, capsys):
    workbook = write_workbook(tmp_path / "spec.xlsx", spec_for(stub_api))

    code = main(["--config", config_at(tmp_path), "run", str(workbook), "--no-llm"])
    report = capsys.readouterr().out

    assert code == 0, report
    jmx = tmp_path / "out" / "claims_intake_service" / "claims_intake_service.jmx"
    assert jmx.exists()
    assert validate_file(jmx).ok


def test_every_stage_leaves_its_artifact(tmp_path, stub_api, credentials):
    workbook = write_workbook(tmp_path / "spec.xlsx", spec_for(stub_api))
    main(["--config", config_at(tmp_path), "run", str(workbook), "--no-llm"])

    assert (tmp_path / "ir" / "claims_intake_service.yaml").exists()
    assert (tmp_path / "probe" / "claims_intake_service.json").exists()
    assert (tmp_path / "out" / "claims_intake_service" / "baseline.properties").exists()
    assert (tmp_path / "out" / "claims_intake_service" / "sla_criteria.yaml").exists()


def test_the_probe_fills_in_the_token_expression(tmp_path, stub_api, credentials):
    workbook = write_workbook(tmp_path / "spec.xlsx", spec_for(stub_api))
    main(["--config", config_at(tmp_path), "run", str(workbook), "--no-llm"])

    ir = load_ir(tmp_path / "ir" / "claims_intake_service.yaml")
    assert ir.auth.token_extract.expr == "$.access_token"
    assert ir.provenance.probe.performed is True


def test_no_secret_reaches_any_artifact(tmp_path, stub_api, credentials):
    workbook = write_workbook(tmp_path / "spec.xlsx", spec_for(stub_api))
    main(["--config", config_at(tmp_path), "run", str(workbook), "--no-llm"])

    for path in tmp_path.rglob("*"):
        if path.is_file() and path.suffix in {".json", ".yaml", ".jmx", ".properties"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            assert "secret-value" not in text, path
            assert TOKEN not in text, path


def test_summary_names_the_config_it_used(tmp_path, stub_api, credentials, capsys):
    workbook = write_workbook(tmp_path / "spec.xlsx", spec_for(stub_api))
    main(["--config", config_at(tmp_path), "run", str(workbook), "--no-llm"])
    report = capsys.readouterr().out
    assert "JMeter 5.6.3" in report


def test_no_probe_on_an_oauth_spec_cannot_produce_a_working_script(
    tmp_path, stub_api, credentials, capsys
):
    """Without the probe the token expression is unknown, so the script could not authenticate.

    Blocking is the honest outcome: a script that cannot log in would 401 on every sample and
    report a tidy 100% error rate, which looks like an API problem rather than a missing step.
    """
    workbook = write_workbook(tmp_path / "spec.xlsx", spec_for(stub_api))
    code = main(
        ["--config", config_at(tmp_path), "run", str(workbook), "--no-probe", "--no-llm"]
    )
    report = capsys.readouterr().out

    assert code == 1
    assert "ARE GUESSES" in report
    assert "probe: skipped" in report
    assert "auth.token_extract.expr" in report
    assert "Run the probe first" in report


def test_no_probe_still_generates_when_there_is_no_auth_to_resolve(
    tmp_path, stub_api, capsys
):
    """The block above is about the missing token, not about skipping the probe as such."""
    spec = spec_for(stub_api)
    set_application_value(spec, "Auth type", "None")
    set_application_value(spec, "Token endpoint URL", None)
    workbook = write_workbook(tmp_path / "spec.xlsx", spec)

    code = main(
        ["--config", config_at(tmp_path), "run", str(workbook), "--no-probe", "--no-llm"]
    )
    report = capsys.readouterr().out

    assert code == 0, report
    assert "ARE GUESSES" in report, "every correlation here is a guess and must say so"
    assert (tmp_path / "out" / "claims_intake_service" / "claims_intake_service.jmx").exists()


def test_inferred_placeholders_leave_no_dangling_reference(tmp_path, stub_api, capsys):
    """A bare `{placeholder}` would be emitted as literal text and sent to the server.

    `${itemId}` is the correct JMeter reference and must survive; `{itemId}` on its own must not.
    """
    spec = spec_for(stub_api)
    set_application_value(spec, "Auth type", "None")
    set_application_value(spec, "Token endpoint URL", None)
    workbook = write_workbook(tmp_path / "spec.xlsx", spec)

    main(["--config", config_at(tmp_path), "run", str(workbook), "--no-probe", "--no-llm"])

    jmx = tmp_path / "out" / "claims_intake_service" / "claims_intake_service.jmx"
    text = jmx.read_text(encoding="utf-8")

    assert validate_file(jmx).ok
    assert "${itemId}" in text, "the guess still has to be wired into the path"
    assert not re.search(r"(?<!\$)\{itemId\}", text), "no bare placeholder may reach the script"


def test_probe_disabled_in_config_is_honoured(tmp_path, stub_api, credentials, capsys):
    path = tmp_path / "config.yaml"
    path.write_text(
        "probe:\n  enabled: false\n"
        f"paths:\n  ir: {(tmp_path / 'ir').as_posix()}\n"
        f"  probe_records: {(tmp_path / 'probe').as_posix()}\n"
        f"  outputs: {(tmp_path / 'out').as_posix()}\n",
        encoding="utf-8",
    )
    workbook = write_workbook(tmp_path / "spec.xlsx", spec_for(stub_api))
    main(["--config", str(path), "run", str(workbook), "--no-llm"])

    report = capsys.readouterr().out
    assert "probe.enabled is false" in report
    assert not (tmp_path / "probe").exists()


def test_blocking_gap_stops_before_anything_is_generated(tmp_path, capsys):
    spec = set_application_value(WorkbookSpec(), "Base URL", None)
    workbook = write_workbook(tmp_path / "spec.xlsx", spec)

    code = main(["--config", config_at(tmp_path), "run", str(workbook), "--no-llm"])
    report = capsys.readouterr().out

    assert code == 1
    assert "BLOCKING" in report
    assert not (tmp_path / "out").exists()


def test_jmeter_version_comes_from_config(tmp_path, stub_api, credentials):
    path = tmp_path / "config.yaml"
    path.write_text(
        "jmeter:\n  version: '5.5'\n"
        f"paths:\n  ir: {(tmp_path / 'ir').as_posix()}\n"
        f"  probe_records: {(tmp_path / 'probe').as_posix()}\n"
        f"  outputs: {(tmp_path / 'out').as_posix()}\n",
        encoding="utf-8",
    )
    workbook = write_workbook(tmp_path / "spec.xlsx", spec_for(stub_api))
    main(["--config", str(path), "run", str(workbook), "--no-llm"])

    jmx = (tmp_path / "out" / "claims_intake_service" / "claims_intake_service.jmx").read_text(
        encoding="utf-8"
    )
    assert 'jmeter="5.5"' in jmx


def test_temperature_warning_surfaces_in_a_real_run(tmp_path, stub_api, credentials, capsys):
    path = tmp_path / "config.yaml"
    path.write_text(
        "llm:\n  temperature: 0.9\n"
        f"paths:\n  ir: {(tmp_path / 'ir').as_posix()}\n"
        f"  probe_records: {(tmp_path / 'probe').as_posix()}\n"
        f"  outputs: {(tmp_path / 'out').as_posix()}\n",
        encoding="utf-8",
    )
    workbook = write_workbook(tmp_path / "spec.xlsx", spec_for(stub_api))
    main(["--config", str(path), "run", str(workbook), "--no-llm"])

    report = capsys.readouterr().out
    assert "llm.temperature" in report
    assert "no effect" in report
