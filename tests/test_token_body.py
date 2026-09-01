"""The token request body follows the declared Content-Type, on both paths.

Both builders used to form-encode unconditionally while sending whatever Content-Type the workbook
declared. A spec saying `application/json` therefore posted `username=...&password=...` under a
JSON header, and DummyJSON answered:

    {"message":"Unexpected token 'u', \\"username=e\\"... is not valid JSON"}

The emitter needs the same rule as the probe, not just the probe. That split has failed a gate
twice on this project, and this is exactly its shape: if the probe sends JSON and the emitted
script sends form text, the probe passes and the generated script fails - the one disagreement
worse than both failing.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs

import pytest

from perfgen.emit.emitter import build_tree
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
    TokenExtract,
    TokenRequest,
)
from perfgen.probe.redact import Redactor
from perfgen.probe.runner import _token_body

PARAMS = ["username", "password"]
RESOLVED = {"demo-username": "emilys", "demo-password": "emilyspass"}


def request_spec(content_type: str) -> TokenRequest:
    return TokenRequest(
        method="POST",
        url="https://dummyjson.com/auth/login",
        content_type=content_type,
        param_names=PARAMS,
        credential_refs=list(RESOLVED),
    )


# ------------------------------------------------------------------------------------------
# The decision itself


@pytest.mark.parametrize(
    "content_type,expected",
    [
        ("application/json", True),
        ("application/json; charset=UTF-8", True),
        ("application/vnd.api+json", True),
        ("application/x-www-form-urlencoded", False),
        ("", False),
        ("text/plain", False),
    ],
)
def test_the_declared_content_type_decides_the_encoding(content_type, expected):
    """Anything unrecognised stays form-encoded - what OAuth specifies."""
    assert request_spec(content_type).sends_json is expected


# ------------------------------------------------------------------------------------------
# The probe


def test_the_probe_sends_json_when_the_spec_says_json():
    body = _token_body(PARAMS, RESOLVED, sends_json=True)

    assert json.loads(body) == {"username": "emilys", "password": "emilyspass"}


def test_the_probe_still_form_encodes_by_default():
    body = _token_body(PARAMS, RESOLVED, sends_json=False)

    assert parse_qs(body) == {"username": ["emilys"], "password": ["emilyspass"]}


def test_a_json_token_body_is_redacted_exactly_like_a_form_one():
    """The new path must not route around redaction - a JSON body reaches disk the same way."""
    redactor = Redactor(list(RESOLVED.values()))

    as_json = redactor.body(_token_body(PARAMS, RESOLVED, True), "application/json")
    as_form = redactor.body(
        _token_body(PARAMS, RESOLVED, False), "application/x-www-form-urlencoded"
    )

    for value in RESOLVED.values():
        assert value not in as_json, "a credential survived in the JSON body"
        assert value not in as_form
    assert json.loads(as_json) == {"username": "[redacted]", "password": "[redacted]"}


# ------------------------------------------------------------------------------------------
# The emitter


def plan_with(content_type: str) -> TestPlanIR:
    return TestPlanIR(
        application=Application(name="dummyjson", base_url="https://dummyjson.com"),
        auth=Auth(
            type=AuthType.OAUTH2_PASSWORD,
            header_name="Authorization",
            value_format="Bearer {token}",
            token_request=request_spec(content_type),
            token_extract=TokenExtract(var="authToken", expr="$.accessToken"),
        ),
        flows=[
            Flow(
                id="F01",
                name="Products",
                share_pct=100,
                think_time_ms=0,
                probe_safe=True,
                steps=[
                    Step(index=1, name="List", method=Method.GET, path="/products",
                         expected_status=200)
                ],
            )
        ],
        load_profiles=[
            LoadProfile(id=ProfileId.BASELINE, enabled=True, users=1, ramp_up_s=1, duration_s=10)
        ],
        provenance=Provenance(source_workbook="x.xlsx", generated_at="2026-09-01T00:00:00Z"),
    )


def token_body_from_jmx(content_type: str) -> str:
    xml = build_tree(plan_with(content_type), "5.6.3")[0].decode()
    sampler = xml.split('testname="Acquire token"', 1)[1].split("</HTTPSamplerProxy>", 1)[0]
    return re.search(r'<stringProp name="Argument.value">([^<]*)</stringProp>', sampler).group(1)


def test_the_emitter_sends_json_when_the_spec_says_json():
    body = token_body_from_jmx("application/json")
    payload = json.loads(body)

    assert set(payload) == {"username", "password"}
    assert payload["username"] == "${__groovy(System.getenv('DEMO_USERNAME'))}"
    assert payload["password"] == "${__groovy(System.getenv('DEMO_PASSWORD'))}"


def test_the_emitter_still_form_encodes_by_default():
    body = token_body_from_jmx("application/x-www-form-urlencoded")

    assert body.startswith("username=${__groovy(")
    assert "&amp;password=${__groovy(" in body or "&password=${__groovy(" in body


def test_a_json_token_body_leaves_jmeter_references_intact():
    """json.dumps must not escape the function into something JMeter stops recognising."""
    body = token_body_from_jmx("application/json")

    assert "System.getenv(" in body
    assert r"\u" not in body, "a reference was unicode-escaped"
    assert "%28" not in body, "a reference was percent-encoded"


# ------------------------------------------------------------------------------------------
# The two paths agree


@pytest.mark.parametrize("content_type", ["application/json", "application/x-www-form-urlencoded"])
def test_probe_and_emitter_carry_the_same_parameters(content_type):
    """The failure this guards is silent: one side JSON, the other form, only the probe passing."""
    spec = request_spec(content_type)
    probe_body = _token_body(PARAMS, RESOLVED, sends_json=spec.sends_json)
    emitted = token_body_from_jmx(content_type)

    if spec.sends_json:
        assert set(json.loads(probe_body)) == set(json.loads(emitted))
    else:
        assert set(parse_qs(probe_body)) == set(parse_qs(emitted.replace("&amp;", "&")))


# ------------------------------------------------------------------------------------------
# Every credential in the token response, not only the one the script uses


def token_response(payload: dict) -> object:
    import httpx

    return httpx.Response(200, json=payload)


def test_a_refresh_token_is_registered_alongside_the_access_token():
    """DummyJSON returns both. Only the access token used to be registered, so the refresh token -
    the longer-lived credential of the two - was written to the probe record verbatim."""
    from perfgen.probe.runner import _register_response_credentials

    redactor = Redactor()
    response = token_response(
        {"accessToken": "access-value-abcdef123456", "refreshToken": "refresh-value-9876543210",
         "username": "emilys", "id": 1}
    )

    _register_response_credentials(response, redactor)
    scrubbed = redactor.scrub(response.text)

    assert "access-value-abcdef123456" not in scrubbed
    assert "refresh-value-9876543210" not in scrubbed, "the refresh token reached the record"
    # Everything else stays intact - correlation reads these bodies.
    assert "emilys" in scrubbed


@pytest.mark.parametrize(
    "key", ["refresh_token", "refreshToken", "access_token", "accessToken", "id_token", "jwt"]
)
def test_every_credential_shaped_response_field_is_registered(key):
    from perfgen.probe.runner import _register_response_credentials

    redactor = Redactor()
    response = token_response({key: "the-credential-value-0123456789"})

    _register_response_credentials(response, redactor)

    assert "the-credential-value-0123456789" not in redactor.scrub(response.text)


def test_an_ordinary_field_is_left_alone():
    """Redacting more than credentials would blind correlation, which reads these bodies."""
    from perfgen.probe.runner import _register_response_credentials

    redactor = Redactor()
    response = token_response({"sessionId": "correlate-me-0123456789", "accessToken": "tok-abc123"})

    _register_response_credentials(response, redactor)
    scrubbed = redactor.scrub(response.text)

    assert "correlate-me-0123456789" in scrubbed
    assert "tok-abc123" not in scrubbed
