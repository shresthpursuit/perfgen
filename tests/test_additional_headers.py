"""Literal headers sent on every request, alongside the auth header.

Twitch's Helix API is the motivating case: `Authorization` and `Client-Id` are both required on
every call, and one auth-header field cannot express that.

These are literal values only. They are written into the script as-is and resolved from nowhere -
credential-sourced headers are a separate piece of work, deliberately not started.
"""

from __future__ import annotations

from lxml import etree

from perfgen.emit.emitter import build_tree
from perfgen.ir.models import (
    Application,
    Auth,
    AuthStrategy,
    AuthType,
    Flow,
    LoadProfile,
    Method,
    ProfileId,
    Provenance,
    Severity,
    Step,
    TestPlanIR,
    TokenExtract,
    TokenRequest,
)
from perfgen.parse import parse_workbook
from tests.fixtures.workbooks import WorkbookSpec, set_application_value, write_workbook

HEADERS_LABEL = "Additional required headers"


def parse(tmp_path, value: str | None):
    spec = set_application_value(WorkbookSpec(), HEADERS_LABEL, value)
    return parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))


def gap_for(result, fragment: str):
    return next((g for g in result.gaps if fragment in g.message), None)


def build_ir(
    headers: dict[str, str],
    *,
    auth_type: AuthType = AuthType.BEARER_STATIC,
    strategy: AuthStrategy = AuthStrategy.SHARED_SETUP,
) -> TestPlanIR:
    if auth_type is AuthType.NONE:
        auth = Auth(type=AuthType.NONE)
    elif auth_type.needs_token_request:
        auth = Auth(
            type=auth_type,
            strategy=strategy,
            token_request=TokenRequest(
                method="POST",
                url="https://sso.example.internal/token",
                content_type="application/x-www-form-urlencoded",
                param_names=["grant_type"],
                credential_refs=[],
            ),
            token_extract=TokenExtract(var="authToken", expr="$.access_token"),
            header_name="Authorization",
            value_format="Bearer {token}",
        )
    else:
        auth = Auth(
            type=auth_type,
            static_credential_refs=["perf-api-token"],
            header_name="Authorization",
            value_format="Bearer {token}",
        )

    return TestPlanIR(
        application=Application(
            name="Helix", base_url="https://api.example.internal", additional_headers=headers
        ),
        auth=auth,
        flows=[
            Flow(
                id="F01",
                name="Read",
                share_pct=100,
                think_time_ms=0,
                probe_safe=True,
                steps=[
                    Step(
                        index=1,
                        name="List",
                        method=Method.POST,
                        path="/items",
                        body='{"a":1}',
                        content_type="application/json",
                        expected_status=200,
                    )
                ],
            )
        ],
        load_profiles=[
            LoadProfile(id=ProfileId.BASELINE, enabled=True, users=1, ramp_up_s=1, duration_s=60)
        ],
        provenance=Provenance(source_workbook="fixture", generated_at="2026-08-11T00:00:00Z"),
    )


def headers_in(ir: TestPlanIR) -> dict[str, str]:
    """Every header the emitted script sets anywhere."""
    xml, _ = build_tree(ir, "5.6.3")
    found: dict[str, str] = {}
    for manager in etree.fromstring(xml).iter("HeaderManager"):
        for element in manager.iter("elementProp"):
            name = element.find("stringProp[@name='Header.name']")
            value = element.find("stringProp[@name='Header.value']")
            if name is not None and name.text:
                found[name.text] = value.text if value is not None else ""
    return found


# --------------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------------


def test_headers_are_read_from_the_workbook(tmp_path):
    ir = parse(tmp_path, "Client-Id: abc123\nX-Trace: perf-run").ir
    assert ir.application.additional_headers == {"Client-Id": "abc123", "X-Trace": "perf-run"}


def test_the_default_fixture_carries_headers(tmp_path):
    """The generated workbook ships the field populated, so the happy path is covered."""
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx"))
    assert result.ir.application.additional_headers["Client-Id"] == "claims-portal-9f2c"


def test_a_value_containing_a_colon_survives(tmp_path):
    """Split on the first colon only - URLs and timestamps have their own."""
    ir = parse(tmp_path, "X-Origin: https://portal.example.internal:8443/app").ir
    assert ir.application.additional_headers["X-Origin"] == (
        "https://portal.example.internal:8443/app"
    )


def test_an_empty_field_yields_no_headers(tmp_path):
    assert parse(tmp_path, None).ir.application.additional_headers == {}


def test_surrounding_whitespace_is_trimmed(tmp_path):
    ir = parse(tmp_path, "  Client-Id  :   abc123   ").ir
    assert ir.application.additional_headers == {"Client-Id": "abc123"}


def test_a_line_with_no_colon_is_a_warning_and_is_skipped(tmp_path):
    result = parse(tmp_path, "Client-Id abc123\nX-Trace: ok")

    gap = gap_for(result, "is not a header")
    assert gap is not None and gap.severity is Severity.WARNING
    assert "Client-Id abc123" in gap.message
    assert result.ir.application.additional_headers == {"X-Trace": "ok"}


def test_a_duplicate_header_warns_and_keeps_the_first(tmp_path):
    result = parse(tmp_path, "Client-Id: first\nClient-Id: second")

    assert gap_for(result, "listed more than once") is not None
    assert result.ir.application.additional_headers == {"Client-Id": "first"}


def test_a_collision_with_the_auth_header_warns_and_auth_wins(tmp_path):
    """Two mechanisms cannot both own one header."""
    result = parse(tmp_path, "Authorization: Bearer hand-rolled")

    gap = gap_for(result, "Auth header name")
    assert gap is not None and gap.severity is Severity.WARNING
    assert "Authorization" not in result.ir.application.additional_headers


def test_a_credential_looking_header_warns_but_is_still_used(tmp_path):
    """The user may genuinely need it; they are told it lands in the script in clear text."""
    result = parse(tmp_path, "X-Api-Key: literal-value-here")

    gap = gap_for(result, "clear text")
    assert gap is not None and gap.severity is Severity.WARNING
    assert result.ir.application.additional_headers["X-Api-Key"] == "literal-value-here"


def test_malformed_headers_never_block_the_run(tmp_path):
    result = parse(tmp_path, "nonsense\nAuthorization: x\nDup: 1\nDup: 2")
    assert not [g for g in result.blocking if "additional_headers" in g.field]


# --------------------------------------------------------------------------------------------
# Emission
# --------------------------------------------------------------------------------------------


def test_both_headers_are_emitted_alongside_auth():
    """The Twitch shape: Authorization and Client-Id on the same request."""
    headers = headers_in(build_ir({"Client-Id": "abc123", "X-Trace": "perf-run"}))

    assert headers["Client-Id"] == "abc123"
    assert headers["X-Trace"] == "perf-run"
    assert "Authorization" in headers


def test_headers_are_emitted_with_no_auth_at_all():
    """A header can be required without authentication - the reason this is not under auth."""
    headers = headers_in(build_ir({"Client-Id": "abc123"}, auth_type=AuthType.NONE))

    assert headers["Client-Id"] == "abc123"
    assert "Authorization" not in headers


def test_a_step_content_type_overrides_a_same_named_additional_header():
    """The narrower derived value wins over the global literal."""
    headers = headers_in(build_ir({"Content-Type": "text/plain"}))
    assert headers["Content-Type"] == "application/json"


def test_the_auth_header_overrides_a_same_named_additional_header():
    ir = build_ir({"Authorization": "Bearer hand-rolled"})
    assert "hand-rolled" not in headers_in(ir)["Authorization"]


def test_no_additional_headers_emits_what_it_did_before():
    assert "Client-Id" not in headers_in(build_ir({}))


def test_additional_headers_do_not_reach_the_token_request_under_per_thread_auth():
    """They ride with the auth header, which is deliberately kept off the token call."""
    ir = build_ir(
        {"Client-Id": "abc123"},
        auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
        strategy=AuthStrategy.PER_THREAD,
    )
    root = etree.fromstring(build_tree(ir, "5.6.3")[0])

    token_sampler = next(
        s for s in root.iter("HTTPSamplerProxy") if s.get("testname") == "Acquire token"
    )
    manager = token_sampler.getnext().find("HeaderManager")
    names = (
        [p.text for p in manager.iter("stringProp") if p.get("name") == "Header.name"]
        if manager is not None
        else []
    )
    assert "Client-Id" not in names


def test_no_secret_looking_value_is_invented_in_the_script():
    """Values are literal and come only from the spec - nothing is resolved."""
    xml, _ = build_tree(build_ir({"Client-Id": "abc123"}), "5.6.3")
    text = xml.decode()
    assert "abc123" in text, "a literal is meant to be written as-is"
    assert "System.getenv('CLIENT_ID')" not in text, "no credential resolution was built"
