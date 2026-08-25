"""The two probe gaps that would have failed the PKCE gate.

Half B was scoped to the correlation scan alone. That is necessary but not sufficient: correlation
runs on a traffic record, and without these two the probe never produces one worth correlating.

* `_resolve_path` filled placeholders in the *path* only, so `content=step.body` went out verbatim
  and a login step posted `{"originalRequest":"{sCtx}"}` as literal text.
* `_index_response` could only index JSON, so an HTML login page taught it nothing and `{sCtx}`
  had no value to be filled from in the first place.

Both are exercised here against a local stub, never a real identity provider.
"""

from __future__ import annotations

import httpx
import pytest

from perfgen.ir.models import (
    Application,
    Auth,
    AuthType,
    Flow,
    LoadProfile,
    Method,
    ProfileId,
    Provenance,
    Step,
    TestPlanIR,
)
from perfgen.probe.runner import run_probe
from tests.fixtures.html_login import CANARY, S_CTX, S_FT, login_page


def plan(steps: list[Step], base_url: str = "https://idp.test") -> TestPlanIR:
    return TestPlanIR(
        application=Application(name="PKCE probe", base_url=base_url),
        auth=Auth(type=AuthType.NONE),
        flows=[
            Flow(
                id="F01",
                name="Login",
                share_pct=100,
                think_time_ms=0,
                probe_safe=True,
                steps=steps,
            )
        ],
        load_profiles=[
            LoadProfile(id=ProfileId.BASELINE, enabled=True, users=1, ramp_up_s=1, duration_s=10)
        ],
        provenance=Provenance(source_workbook="x.xlsx", generated_at="2026-08-25T00:00:00Z"),
    )


@pytest.fixture
def sent() -> list[httpx.Request]:
    return []


@pytest.fixture
def stub_idp(sent, monkeypatch):
    """An identity provider that answers with the HTML login page, then echoes."""

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        if request.url.path == "/authorize":
            return httpx.Response(
                200, headers={"Content-Type": "text/html; charset=utf-8"}, text=login_page()
            )
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    original = httpx.Client

    def patched(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr("perfgen.probe.runner.httpx.Client", patched)
    return sent


def body_of(request: httpx.Request) -> str:
    return request.content.decode()


# ------------------------------------------------------------------------------------------


def test_a_placeholder_in_a_request_body_is_filled_from_an_html_response(stub_idp):
    """The whole PKCE login turns on this: the body carries sCtx, and the page holds it."""
    ir = plan(
        [
            Step(index=1, name="Authorize", method=Method.GET, path="/authorize",
                 expected_status=200),
            Step(
                index=2,
                name="Get credential type",
                method=Method.POST,
                path="/GetCredentialType",
                body='{"originalRequest":"{sCtx}","flowToken":"{sFT}"}',
                content_type="application/json",
                expected_status=200,
            ),
        ]
    )

    run_probe(ir, timeout_s=5)

    login_request = next(r for r in stub_idp if r.url.path == "/GetCredentialType")
    body = body_of(login_request)
    assert S_CTX in body
    assert S_FT in body
    assert "{sCtx}" not in body, "the placeholder went out as literal text"


def test_a_placeholder_in_a_request_header_is_filled_too(stub_idp):
    """The reference sends canary, hpgid and client-request-id as correlated headers."""
    ir = plan(
        [
            Step(index=1, name="Authorize", method=Method.GET, path="/authorize",
                 expected_status=200),
            Step(
                index=2,
                name="Get credential type",
                method=Method.POST,
                path="/GetCredentialType",
                body="{}",
                content_type="application/json",
                expected_status=200,
                headers={"canary": "{canary}"},
            ),
        ]
    )

    run_probe(ir, timeout_s=5)

    login_request = next(r for r in stub_idp if r.url.path == "/GetCredentialType")
    assert login_request.headers["canary"] == CANARY


def test_the_recorded_request_shows_the_resolved_body_not_the_template(stub_idp):
    """The record is what correlation reads; a template in it correlates against nothing."""
    ir = plan(
        [
            Step(index=1, name="Authorize", method=Method.GET, path="/authorize",
                 expected_status=200),
            Step(
                index=2,
                name="Sign in",
                method=Method.POST,
                path="/login",
                body="ctx={sCtx}",
                content_type="application/x-www-form-urlencoded",
                expected_status=200,
            ),
        ]
    )

    outcome = run_probe(ir, timeout_s=5)

    recorded = next(c for c in outcome.record.calls if c.name == "Sign in")
    assert recorded.request.body == f"ctx={S_CTX}"
    assert "sCtx" in recorded.placeholder_bindings


def test_a_placeholder_nothing_supplies_is_reported_rather_than_sent_silently(stub_idp):
    ir = plan(
        [
            Step(index=1, name="Authorize", method=Method.GET, path="/authorize",
                 expected_status=200),
            Step(
                index=2,
                name="Sign in",
                method=Method.POST,
                path="/login",
                body="ctx={notInThatPage}",
                content_type="application/x-www-form-urlencoded",
                expected_status=200,
            ),
        ]
    )

    outcome = run_probe(ir, timeout_s=5)

    assert any("notInThatPage" in w for w in outcome.warnings)


def test_text_scanning_only_runs_when_no_parser_could_read_the_body(stub_idp):
    """A fallback, not a replacement. A JSON response is indexed structurally as it always was,
    and the wider probe suite covers that path; this pins that the fallback stays out of its way.
    """
    ir = plan(
        [
            Step(index=1, name="Structured", method=Method.GET, path="/plain",
                 expected_status=200),
        ]
    )

    outcome = run_probe(ir, timeout_s=5)

    recorded = outcome.record.calls[0]
    assert recorded.response is not None
    assert recorded.response.body == '{"ok":true}'
    assert not outcome.warnings
