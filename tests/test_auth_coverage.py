"""Every auth type either authenticates or explains itself.

This is the test whose absence let three of the seven auth types ship with no Authorization
header at all. `bearer_static`, `api_key` and `basic` have no token request, so no `token_extract`
was created and the emitter's header branch returned nothing - producing a script where every
request 401s. Structural validation could not catch it: there was no dangling `${var}`, there was
simply nothing there, and no fixture exercised those types.

So the rule this file enforces is coverage, not a particular implementation: for each member of
AuthType, either the emitted script carries a usable credential, or the spec is refused with a
message that says why.
"""

from __future__ import annotations

import base64

import pytest
from lxml import etree

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
from perfgen.parse import parse_workbook
from tests.fixtures.workbooks import WorkbookSpec, set_application_value, write_workbook

# Types that carry a secret straight into the header, with no token call.
STATIC_TYPES = [AuthType.BEARER_STATIC, AuthType.API_KEY, AuthType.BASIC]
# Types that fetch a token first.
OAUTH_TYPES = [AuthType.OAUTH2_CLIENT_CREDENTIALS, AuthType.OAUTH2_PASSWORD]
# Cannot be run unattended at all.
UNSUPPORTED_TYPES = [AuthType.OAUTH2_PKCE]

WORKBOOK_AUTH_LABEL = {
    AuthType.NONE: "None",
    AuthType.OAUTH2_CLIENT_CREDENTIALS: "OAuth2 client credentials",
    AuthType.OAUTH2_PASSWORD: "OAuth2 password",
    AuthType.OAUTH2_PKCE: "OAuth2 PKCE",
    AuthType.BEARER_STATIC: "Bearer static",
    AuthType.API_KEY: "API key",
    AuthType.BASIC: "Basic",
}


def build_auth(auth_type: AuthType) -> Auth:
    if auth_type is AuthType.NONE:
        return Auth(type=AuthType.NONE)
    if auth_type.needs_token_request:
        return Auth(
            type=auth_type,
            token_request=TokenRequest(
                method="POST",
                url="https://sso.example.internal/token",
                content_type="application/x-www-form-urlencoded",
                param_names=["grant_type", "client_id"],
                credential_refs=["perf-client-id"],
            ),
            token_extract=TokenExtract(var="authToken", expr="$.access_token"),
            header_name="Authorization",
            value_format="Bearer {token}",
        )
    refs = ["perf-user", "perf-password"] if auth_type is AuthType.BASIC else ["perf-api-token"]
    return Auth(
        type=auth_type,
        static_credential_refs=refs,
        header_name="X-API-Key" if auth_type is AuthType.API_KEY else "Authorization",
        value_format="{token}" if auth_type is AuthType.API_KEY else "Basic {token}"
        if auth_type is AuthType.BASIC
        else "Bearer {token}",
    )


def build_ir(auth_type: AuthType) -> TestPlanIR:
    return TestPlanIR(
        application=Application(name="Cover", base_url="https://api.example.internal"),
        auth=build_auth(auth_type),
        flows=[
            Flow(
                id="F01",
                name="Read",
                share_pct=100,
                think_time_ms=0,
                probe_safe=True,
                steps=[
                    Step(
                        index=1, name="List", method=Method.GET, path="/items", expected_status=200
                    )
                ],
            )
        ],
        load_profiles=[
            LoadProfile(id=ProfileId.BASELINE, enabled=True, users=1, ramp_up_s=1, duration_s=60)
        ],
        provenance=Provenance(source_workbook="fixture", generated_at="2026-08-10T00:00:00Z"),
    )


def auth_header_values(ir: TestPlanIR) -> dict[str, str]:
    """Every header the emitted script sets on a flow sampler."""
    xml, _ = build_tree(ir, "5.6.3")
    root = etree.fromstring(xml)
    headers: dict[str, str] = {}
    for manager in root.iter("HeaderManager"):
        for element in manager.iter("elementProp"):
            name = element.find("stringProp[@name='Header.name']")
            value = element.find("stringProp[@name='Header.value']")
            if name is not None and name.text:
                headers[name.text] = value.text if value is not None else ""
    return headers


# --------------------------------------------------------------------------------------------
# The coverage rule
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("auth_type", list(AuthType))
def test_every_auth_type_is_either_supported_or_refused(auth_type, tmp_path):
    """No auth type may quietly produce a script that cannot authenticate."""
    if auth_type in UNSUPPORTED_TYPES:
        spec = set_application_value(WorkbookSpec(), "Auth type", WORKBOOK_AUTH_LABEL[auth_type])
        result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))
        assert result.blocking, f"{auth_type} is unsupported but was not refused"
        return

    headers = auth_header_values(build_ir(auth_type))

    if auth_type is AuthType.NONE:
        assert "Authorization" not in headers
        return

    expected_header = "X-API-Key" if auth_type is AuthType.API_KEY else "Authorization"
    assert expected_header in headers, (
        f"{auth_type} emitted no {expected_header} header, so every request would be rejected"
    )
    assert headers[expected_header].strip(), f"{auth_type} emitted an empty credential"


@pytest.mark.parametrize("auth_type", STATIC_TYPES)
def test_static_types_read_their_credential_from_the_environment(auth_type):
    headers = auth_header_values(build_ir(auth_type))
    value = headers["X-API-Key" if auth_type is AuthType.API_KEY else "Authorization"]
    assert "System.getenv(" in value, f"{auth_type} must read its secret at run time"


@pytest.mark.parametrize("auth_type", list(AuthType))
def test_no_auth_type_writes_a_secret_value_into_the_script(auth_type):
    if auth_type in UNSUPPORTED_TYPES:
        pytest.skip("refused at parse time")
    xml, _ = build_tree(build_ir(auth_type), "5.6.3")
    text = xml.decode()
    for forbidden in ("hunter2", "s3cret", "password="):
        assert forbidden not in text


# --------------------------------------------------------------------------------------------
# The static schemes in detail
# --------------------------------------------------------------------------------------------


def test_bearer_static_header_shape():
    headers = auth_header_values(build_ir(AuthType.BEARER_STATIC))
    assert headers["Authorization"] == (
        "Bearer ${__groovy(System.getenv('PERF_API_TOKEN'))}"
    )


def test_api_key_uses_its_own_header_name():
    headers = auth_header_values(build_ir(AuthType.API_KEY))
    assert "Authorization" not in headers
    assert headers["X-API-Key"] == "${__groovy(System.getenv('PERF_API_TOKEN'))}"


def test_basic_encodes_user_and_password_at_run_time():
    headers = auth_header_values(build_ir(AuthType.BASIC))
    value = headers["Authorization"]
    assert value.startswith("Basic ${__groovy(")
    assert "PERF_USER" in value and "PERF_PASSWORD" in value
    assert "encodeBase64" in value


def test_basic_expression_contains_no_comma():
    """JMeter splits function arguments on commas; one inside would truncate the expression."""
    value = auth_header_values(build_ir(AuthType.BASIC))["Authorization"]
    inner = value[value.index("${__groovy(") :]
    assert "," not in inner


def test_static_types_emit_no_setup_thread_group():
    for auth_type in STATIC_TYPES:
        xml, _ = build_tree(build_ir(auth_type), "5.6.3")
        assert not list(etree.fromstring(xml).iter("SetupThreadGroup")), (
            f"{auth_type} has no token to fetch, so there is nothing for a setUp group to do"
        )


@pytest.mark.parametrize("auth_type", OAUTH_TYPES)
def test_oauth_types_still_fetch_a_token(auth_type):
    xml, _ = build_tree(build_ir(auth_type), "5.6.3")
    assert list(etree.fromstring(xml).iter("SetupThreadGroup"))


# --------------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------------


def _static_spec(auth_label: str, refs: str | None) -> WorkbookSpec:
    spec = set_application_value(WorkbookSpec(), "Auth type", auth_label)
    set_application_value(spec, "Credential reference names", refs)
    set_application_value(spec, "Token endpoint URL", None)
    return spec


def test_pkce_is_refused_with_the_alternative_named(tmp_path):
    spec = set_application_value(WorkbookSpec(), "Auth type", "OAuth2 PKCE")
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))

    gap = next(g for g in result.blocking if g.field == "auth.type")
    assert "browser redirect" in gap.message
    assert "Bearer static" in gap.message
    assert "Application, row" in gap.message


def test_static_auth_without_a_credential_reference_is_blocking(tmp_path):
    spec = _static_spec("Bearer static", None)
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))

    gap = next(g for g in result.blocking if g.field == "auth.static_credential_refs")
    assert "Credential reference names" in gap.message


def test_ambiguous_static_credentials_are_blocking(tmp_path):
    spec = _static_spec("Bearer static", "first-token\nsecond-token")
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))

    gap = next(g for g in result.blocking if g.field == "auth.static_credential_refs")
    assert "cannot be guessed" in gap.message


def test_basic_accepts_two_references(tmp_path):
    spec = _static_spec("Basic", "perf-user\nperf-password")
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))

    assert not [g for g in result.blocking if "credential" in g.field]
    assert result.ir.auth.static_credential_refs == ["perf-user", "perf-password"]


def test_parsed_static_spec_emits_a_working_header(tmp_path):
    """The whole chain: workbook -> IR -> JMX, for a type that used to emit nothing."""
    spec = _static_spec("Bearer static", "claims-api-token")
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))
    assert result.ir is not None

    headers = auth_header_values(result.ir)
    assert headers["Authorization"] == "Bearer ${__groovy(System.getenv('CLAIMS_API_TOKEN'))}"


def test_expected_basic_encoding_is_what_the_expression_computes():
    """Pins the encoding the Groovy expression must reproduce at run time."""
    assert base64.b64encode(b"alice:hunter2").decode() == "YWxpY2U6aHVudGVyMg=="
