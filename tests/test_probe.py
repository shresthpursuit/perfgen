"""The probe runner.

Tests drive a stub API through httpx's MockTransport, so nothing here touches a real environment
or a real spreadsheet. The transport records every outbound request, which is how the
"never called an unsafe flow" claims are checked - by asserting on what was actually sent, not on
what the runner reported doing.
"""

from __future__ import annotations

import json

import httpx
import pytest

from perfgen.ir.models import (
    Application,
    Auth,
    AuthType,
    Confidence,
    Extract,
    ExtractorType,
    Flow,
    Method,
    ProbeProvenance,
    Provenance,
    Scope,
    Source,
    Step,
    TestPlanIR,
    TokenConfidence,
    TokenRequest,
)
from perfgen.probe import apply_outcome, run_probe
from perfgen.probe.records import dump_record, load_record
from perfgen.probe.redact import REDACTED

TOKEN = "tok-abc123-xyz-9f2"
ITEM_ID = "ITEM-42-abcdef"
CLIENT_SECRET = "s3cret-value-9f2"


@pytest.fixture(autouse=True)
def credentials(monkeypatch):
    monkeypatch.setenv("CLAIMS_PERF_ID", "client-id-7c1")
    monkeypatch.setenv("CLAIMS_PERF_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("GRANT_TYPE", "client_credentials")


class StubApi:
    """A minimal API plus a log of everything that was actually requested of it."""

    def __init__(self, *, token_status=200, token_payload=None, item_status=200):
        self.requests: list[httpx.Request] = []
        self.token_status = token_status
        default_payload = {"access_token": TOKEN, "expires_in": 3600}
        self.token_payload = default_payload if token_payload is None else token_payload
        self.item_status = item_status

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path

        if path.endswith("/token"):
            return httpx.Response(self.token_status, json=self.token_payload)
        if "/catalogue/search" in path:
            return httpx.Response(
                200,
                json={"results": [{"id": ITEM_ID, "name": "Widget"}], "total": 1},
                headers={"Set-Cookie": "session=super-secret-session"},
            )
        if "/catalogue/items/" in path:
            return httpx.Response(self.item_status, json={"id": path.rsplit("/", 1)[-1]})
        if "/requests" in path:
            return httpx.Response(201, json={"requestRef": "REQ-999"})
        return httpx.Response(404, json={"error": "not found"})

    @property
    def paths(self) -> list[str]:
        return [r.url.path for r in self.requests]

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def build_ir(*, auth: bool = True, f02_safe: bool = False) -> TestPlanIR:
    return TestPlanIR(
        application=Application(
            name="Claims intake service", base_url="https://api.example.internal", base_path="/v1"
        ),
        auth=Auth(
            type=AuthType.OAUTH2_CLIENT_CREDENTIALS if auth else AuthType.NONE,
            token_request=TokenRequest(
                method="POST",
                url="https://sso.example.internal/connect/token",
                content_type="application/x-www-form-urlencoded",
                param_names=["grant_type", "client_id", "client_secret"],
                credential_refs=["claims-perf-id", "claims-perf-secret"],
            )
            if auth
            else None,
            token_extract={"var": "authToken"} if auth else None,
            header_name="Authorization" if auth else None,
            value_format="Bearer {token}" if auth else None,
            lifetime_seconds=3600,
        ),
        flows=[
            Flow(
                id="F01",
                name="Search and view record",
                share_pct=60,
                think_time_ms=1000,
                probe_safe=True,
                steps=[
                    Step(
                        index=1,
                        name="Search catalogue",
                        method=Method.GET,
                        path="/catalogue/search?q=widget",
                        expected_status=200,
                    ),
                    Step(
                        index=2,
                        name="Open record detail",
                        method=Method.GET,
                        path="/catalogue/items/{itemId}",
                        expected_status=200,
                    ),
                ],
            ),
            Flow(
                id="F02",
                name="Submit new request",
                share_pct=40,
                think_time_ms=1000,
                probe_safe=f02_safe,
                steps=[
                    Step(
                        index=1,
                        name="Create request",
                        method=Method.POST,
                        path="/requests",
                        body='{"type":"standard"}',
                        content_type="application/json",
                        expected_status=201,
                    )
                ],
            ),
        ],
        load_profiles=[],
        provenance=Provenance(
            source_workbook="fixture", generated_at="2026-08-10T00:00:00Z", probe=ProbeProvenance()
        ),
    )


def run(api: StubApi, ir: TestPlanIR | None = None):
    ir = ir or build_ir()
    with api.client() as client:
        return ir, run_probe(ir, client=client)


# --------------------------------------------------------------------------------------------
# The happy path
# --------------------------------------------------------------------------------------------


def test_auth_then_each_safe_flow_in_step_order():
    api = StubApi()
    _, outcome = run(api)

    assert api.paths == [
        "/connect/token",
        "/v1/catalogue/search",
        "/v1/catalogue/items/" + ITEM_ID,
    ]
    assert not outcome.degraded


def test_token_expression_is_discovered_from_the_response():
    _, outcome = run(StubApi())
    assert outcome.token_expr == "$.access_token"
    assert outcome.token_confidence is TokenConfidence.VERIFIED


def test_token_found_in_a_nested_payload():
    api = StubApi(token_payload={"data": {"access_token": TOKEN}})
    _, outcome = run(api)
    assert outcome.token_expr == "$.data.access_token"


def test_token_is_sent_on_subsequent_requests():
    api = StubApi()
    run(api)
    catalogue = [r for r in api.requests if "catalogue" in r.url.path]
    assert all(r.headers.get("Authorization") == f"Bearer {TOKEN}" for r in catalogue)


def test_placeholder_is_filled_from_an_earlier_response():
    """Without this the second step 404s and the run yields nothing for the correlator to read."""
    api = StubApi()
    _, outcome = run(api)

    detail = next(c for c in outcome.record.calls if c.step_index == 2)
    assert detail.request.url.endswith(f"/catalogue/items/{ITEM_ID}")
    assert detail.placeholder_bindings == {"itemId": "$.results[0].id"}


def test_every_call_is_recorded_with_its_response():
    _, outcome = run(StubApi())
    for call in outcome.record.calls:
        assert call.succeeded
        assert call.response is not None
        assert call.response.status == 200
    assert outcome.record.steps_observed == 2


def test_response_bodies_are_kept_verbatim_for_the_correlator():
    _, outcome = run(StubApi())
    search = next(c for c in outcome.record.calls if c.step_index == 1)
    assert ITEM_ID in search.response.body


# --------------------------------------------------------------------------------------------
# probe_safe
# --------------------------------------------------------------------------------------------


def test_unsafe_flow_is_never_called():
    """The strongest assertion available: nothing for F02 was ever sent."""
    api = StubApi()
    _, outcome = run(api)

    assert not any("/requests" in path for path in api.paths)
    assert "F02" in outcome.record.skipped_flow_ids


def test_unsafe_flow_skip_records_a_reason():
    _, outcome = run(StubApi())
    skip = next(s for s in outcome.record.skipped_flows if s.flow_id == "F02")
    assert "not safe" in skip.reason
    assert any("F02" in w for w in outcome.warnings)


def test_a_flow_marked_safe_is_called():
    api = StubApi()
    run(api, build_ir(f02_safe=True))
    assert any("/requests" in path for path in api.paths)


def test_skipped_flow_correlations_are_downgraded_to_inferred():
    ir = build_ir()
    ir.flows[1].steps[0].extracts.append(
        Extract(
            var="requestRef",
            source=Source.RESPONSE_BODY,
            extractor=ExtractorType.JSON_PATH,
            expr="$.requestRef",
            scope=Scope.ITERATION,
            confidence=Confidence.VERIFIED,
            evidence="hand-written",
        )
    )
    with StubApi().client() as client:
        outcome = run_probe(ir, client=client)
    apply_outcome(ir, outcome)

    assert ir.flows[1].steps[0].extracts[0].confidence is Confidence.INFERRED, (
        "a flow that was never called cannot have verified correlations"
    )


# --------------------------------------------------------------------------------------------
# Secrets never reach the record
# --------------------------------------------------------------------------------------------


def test_resolved_credentials_are_not_in_the_record(tmp_path):
    _, outcome = run(StubApi())
    written = dump_record(outcome.record, tmp_path / "record.json").read_text(encoding="utf-8")

    assert CLIENT_SECRET not in written
    assert "client-id-7c1" not in written


def test_the_token_is_not_in_the_record(tmp_path):
    _, outcome = run(StubApi())
    written = dump_record(outcome.record, tmp_path / "record.json").read_text(encoding="utf-8")
    assert TOKEN not in written


def test_the_token_request_body_is_redacted():
    _, outcome = run(StubApi())
    token_call = outcome.record.calls[0]
    assert CLIENT_SECRET not in token_call.request.body
    assert "grant_type=client_credentials" in token_call.request.body


def test_credentials_actually_reach_the_token_request():
    """Found by running it: `claims-perf-id` did not match `client_id`, so an empty client_id
    was sent and the failure looked like a broken IdP rather than a naming mismatch."""
    api = StubApi()
    run(api)

    sent = api.requests[0].content.decode()
    assert "client_id=client-id-7c1" in sent
    assert f"client_secret={CLIENT_SECRET}" in sent
    assert "client_id=&" not in sent and not sent.endswith("client_id=")


def test_a_token_parameter_with_no_value_anywhere_degrades(monkeypatch):
    """Never an empty string: an empty credential fails auth in a way that misdirects the reader."""
    monkeypatch.delenv("GRANT_TYPE", raising=False)
    api = StubApi()
    _, outcome = run(api)

    assert outcome.degraded
    assert "GRANT_TYPE" in outcome.record.degraded_reason
    assert api.requests == [], "nothing is sent when a parameter has no value"


def test_the_authorization_header_is_redacted_on_every_call():
    _, outcome = run(StubApi())
    for call in outcome.record.calls:
        for name, value in call.request.headers.items():
            if name.lower() == "authorization":
                assert value == REDACTED


def test_set_cookie_is_redacted_in_responses():
    _, outcome = run(StubApi())
    search = next(c for c in outcome.record.calls if c.step_index == 1)
    for name, value in search.response.headers.items():
        if name.lower() == "set-cookie":
            assert value == REDACTED
    assert "super-secret-session" not in json.dumps(search.model_dump(mode="json"))


def test_record_round_trips_through_disk(tmp_path):
    _, outcome = run(StubApi())
    path = dump_record(outcome.record, tmp_path / "record.json")
    assert load_record(path) == outcome.record


# --------------------------------------------------------------------------------------------
# Degraded mode
# --------------------------------------------------------------------------------------------


def test_missing_credential_degrades_rather_than_raising(monkeypatch):
    monkeypatch.delenv("CLAIMS_PERF_SECRET", raising=False)
    api = StubApi()
    _, outcome = run(api)

    assert outcome.degraded
    assert "CLAIMS_PERF_SECRET" in outcome.record.degraded_reason
    assert api.requests == [], "nothing should be called without credentials"


def test_unreachable_environment_degrades():
    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("name or service not known", request=request)

    ir = build_ir()
    with httpx.Client(transport=httpx.MockTransport(explode)) as client:
        outcome = run_probe(ir, client=client)

    assert outcome.degraded
    assert "could not be reached" in outcome.record.degraded_reason


def test_degraded_run_skips_every_flow():
    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    ir = build_ir()
    with httpx.Client(transport=httpx.MockTransport(explode)) as client:
        outcome = run_probe(ir, client=client)

    assert set(outcome.record.skipped_flow_ids) == {"F01", "F02"}


def test_failed_auth_degrades_rather_than_hammering_the_environment():
    api = StubApi(token_status=401, token_payload={"error": "invalid_client"})
    _, outcome = run(api)

    assert outcome.degraded
    assert api.paths == ["/connect/token"], "flows must not run once auth has failed"


def test_degraded_run_marks_the_token_confidence_unknown():
    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    ir = build_ir()
    with httpx.Client(transport=httpx.MockTransport(explode)) as client:
        outcome = run_probe(ir, client=client)
    apply_outcome(ir, outcome)

    assert ir.auth.token_extract.confidence is TokenConfidence.UNKNOWN
    assert ir.provenance.probe.degraded is True
    assert ir.provenance.probe.performed is False


def test_unexpected_status_warns_but_keeps_going():
    api = StubApi(item_status=500)
    _, outcome = run(api)

    assert not outcome.degraded
    assert any("returned 500" in w for w in outcome.warnings)
    assert len(outcome.record.calls) == 3


def test_no_auth_spec_probes_flows_directly():
    api = StubApi()
    ir = build_ir(auth=False)
    with api.client() as client:
        outcome = run_probe(ir, client=client)

    assert not outcome.degraded
    assert not any("token" in path for path in api.paths)
    assert outcome.record.steps_observed == 2


# --------------------------------------------------------------------------------------------
# Applying results to the IR
# --------------------------------------------------------------------------------------------


def test_apply_fills_the_token_expression_and_provenance():
    ir = build_ir()
    with StubApi().client() as client:
        outcome = run_probe(ir, client=client)
    apply_outcome(ir, outcome)

    assert ir.auth.token_extract.expr == "$.access_token"
    assert ir.auth.token_extract.confidence is TokenConfidence.VERIFIED
    assert ir.provenance.probe.performed is True
    assert ir.provenance.probe.steps_observed == 2
    assert ir.provenance.probe.skipped_flows == ["F02"]


def test_probed_ir_becomes_emittable():
    """The token expression is what unblocked emit; this is the M2->M3->M4 seam."""
    from perfgen.ir.gaps import blocking, detect_gaps

    ir = build_ir()
    assert any(g.field == "auth.token_extract.expr" for g in blocking(detect_gaps(ir)))

    with StubApi().client() as client:
        apply_outcome(ir, run_probe(ir, client=client))

    assert not any(g.field == "auth.token_extract.expr" for g in blocking(detect_gaps(ir)))
