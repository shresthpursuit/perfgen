"""PKCE: the crypto, the parsed spec, and the shape of the emitted tree.

`docs/reference/pkce_entra_reference.jmx` is a hand-built script confirmed to obtain a real token
against a live Entra tenant. It is the reference for what has to work - and, in three places, for
what must not be reproduced. Those three have tests of their own here, because each was a live
defect in a script that nonetheless worked:

* its `/login` sampler has no `follow_redirects` property at all, so the 302 survives by omission
  rather than by intent - point the same flow at an `https://` redirect URI and it silently breaks;
* its verifier and challenge round-trip through JVM-global properties, which races the moment more
  than one thread runs;
* nearly every one of its extractors leaves `match_number` empty, which JMeter reads as 0, meaning
  *random match*.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from perfgen.emit.emitter import CHALLENGE_VAR, CODE_VAR, VERIFIER_VAR, build_tree
from perfgen.ir.models import (
    Application,
    Auth,
    AuthStrategy,
    AuthType,
    Confidence,
    Extract,
    ExtractorType,
    Flow,
    LoadProfile,
    Method,
    ProfileId,
    Provenance,
    Scope,
    SeedCookie,
    Source,
    Step,
    TestPlanIR,
    TokenExtract,
    TokenRequest,
)
from perfgen.parse.workbook import parse_workbook
from perfgen.validate import validate_xml
from tests.fixtures.workbooks import (
    DEFAULT_AUTH_STEPS,
    WorkbookSpec,
    set_application_value,
    write_workbook,
)

# RFC 7636 Appendix B. Pinned against the RFC rather than against a value this code produced,
# because a self-generated vector only proves the implementation agrees with itself.
RFC_7636_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


# ------------------------------------------------------------------------------------------
# The transformation


def derive_challenge(verifier: str) -> str:
    """The S256 transformation, spelled out exactly as the emitted Groovy spells it."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def test_the_s256_transformation_matches_the_rfc_test_vector():
    assert derive_challenge(RFC_7636_VERIFIER) == RFC_7636_CHALLENGE


def test_the_emitted_groovy_performs_that_same_transformation(pkce_ir):
    """The Groovy cannot be executed here, so this pins the primitives it names.

    A Python reimplementation agreeing with the RFC proves the algorithm; this proves the script
    asks for that algorithm and not a neighbouring one - SHA-256 rather than SHA-1, URL-safe
    base64 rather than standard, padding stripped, 32 bytes of randomness.
    """
    script = build_tree(pkce_ir, "5.6.3")[0].decode()

    assert "SHA-256" in script
    assert "getUrlEncoder" in script
    assert "withoutPadding" in script
    assert "new byte[32]" in script
    assert "SecureRandom" in script
    assert "US-ASCII" in script


# ------------------------------------------------------------------------------------------
# Fixtures


def boundary(var: str, left: str, right: str) -> Extract:
    return Extract(
        var=var,
        source=Source.RESPONSE_BODY,
        extractor=ExtractorType.BOUNDARY,
        expr=f"{left}||{right}",
        scope=Scope.THREAD,
        confidence=Confidence.VERIFIED,
        evidence="observed in the authorize response and sent by the login step",
    )


def build_pkce_ir(strategy: AuthStrategy = AuthStrategy.PER_THREAD) -> TestPlanIR:
    return TestPlanIR(
        application=Application(name="Booking", base_url="https://api.example.internal"),
        auth=Auth(
            type=AuthType.OAUTH2_PKCE,
            strategy=strategy,
            header_name="Authorization",
            value_format="Bearer {token}",
            token_request=TokenRequest(
                method="POST",
                url="https://login.example.internal/tenant/oauth2/v2.0/token",
                content_type="application/x-www-form-urlencoded",
                param_names=["client_id"],
                credential_refs=["pkce-client-id"],
            ),
            token_extract=TokenExtract(var="accessToken", expr="$.access_token"),
            authorize_url="https://login.example.internal/tenant/oauth2/v2.0/authorize",
            redirect_uri="msal-abc123://auth",
            scope="api://booking/Booking-Execute",
            seed_cookies=[
                SeedCookie(
                    name="AADSSO", value="NA|NoExtension", domain="login.example.internal"
                )
            ],
            authorize_extracts=[
                boundary("sCtx", '"sCtx":"', '"'),
                boundary("sFT", '"sFT":"', '"'),
                boundary("canary", '"canary":"', '"'),
            ],
            flow_steps=[
                Step(
                    index=1,
                    name="Get credential type",
                    method=Method.POST,
                    path="/common/GetCredentialType",
                    body='{"originalRequest":"{sCtx}","flowToken":"{sFT}"}',
                    content_type="application/json",
                    expected_status=200,
                    headers={"canary": "{canary}"},
                ),
                Step(
                    index=2,
                    name="Sign in",
                    method=Method.POST,
                    path="/tenant/login",
                    body="canary={canary}&ctx={sCtx}&flowToken={sFT}",
                    content_type="application/x-www-form-urlencoded",
                    expected_status=302,
                ),
            ],
        ),
        flows=[
            Flow(
                id="F01",
                name="Book",
                share_pct=100,
                think_time_ms=500,
                probe_safe=True,
                steps=[
                    Step(
                        index=1,
                        name="List bookings",
                        method=Method.GET,
                        path="/bookings",
                        expected_status=200,
                    )
                ],
            )
        ],
        load_profiles=[
            LoadProfile(
                id=ProfileId.BASELINE, enabled=True, users=5, ramp_up_s=5, duration_s=60
            )
        ],
        provenance=Provenance(source_workbook="pkce.xlsx", generated_at="2026-08-25T00:00:00Z"),
    )


@pytest.fixture
def pkce_ir() -> TestPlanIR:
    return build_pkce_ir()


@pytest.fixture
def pkce_xml(pkce_ir) -> str:
    return build_tree(pkce_ir, "5.6.3")[0].decode()


# ------------------------------------------------------------------------------------------
# The three defects in the reference that must not be reproduced


def test_the_code_producing_step_never_follows_redirects(pkce_ir):
    """The reference gets this right only by omission, which breaks on an https redirect URI."""
    xml = build_tree(pkce_ir, "5.6.3")[0].decode()

    code_step = pkce_ir.auth.code_step
    assert code_step is not None and code_step.name == "Sign in"

    block = xml.split(f'testname="{code_step.name}"', 1)[1]
    sampler = block.split("</HTTPSamplerProxy>", 1)[0]
    assert '<boolProp name="HTTPSampler.follow_redirects">false</boolProp>' in sampler
    assert '<boolProp name="HTTPSampler.auto_redirects">false</boolProp>' in sampler


def test_only_the_code_producing_step_stops_following_redirects(pkce_xml):
    """A blanket false would change every other request's behaviour for no reason."""
    assert pkce_xml.count('name="HTTPSampler.follow_redirects">false') == 1


def test_the_verifier_and_challenge_are_thread_variables_not_properties(pkce_xml):
    """Properties are JVM-global: promoting these races every thread against every other."""
    assert f"vars.put('{VERIFIER_VAR}'" in pkce_xml
    assert f"vars.put('{CHALLENGE_VAR}'" in pkce_xml
    assert f'props.put("{VERIFIER_VAR}"' not in pkce_xml
    assert f'props.put("{CHALLENGE_VAR}"' not in pkce_xml
    assert "__setProperty" not in pkce_xml


def test_every_extractor_pins_its_match_number(pkce_xml):
    """An empty match number is read by JMeter as 0, which means *random match*."""
    for prop in ("RegexExtractor.match_number", "BoundaryExtractor.match_number"):
        for fragment in pkce_xml.split(f'name="{prop}">')[1:]:
            assert fragment.startswith("1<"), f"{prop} is not pinned to 1"


def test_no_beanshell_anywhere_in_pkce_output(pkce_xml):
    """The reference uses BeanShell assertions as property setters. Legacy, and unnecessary."""
    assert "BeanShell" not in pkce_xml


# ------------------------------------------------------------------------------------------
# Tree shape


def test_per_thread_wraps_the_exchange_in_a_once_only_controller():
    """Otherwise a soak test re-authenticates every iteration and measures the IdP."""
    xml = build_tree(build_pkce_ir(AuthStrategy.PER_THREAD), "5.6.3")[0].decode()

    assert "OnceOnlyController" in xml
    assert "SetupThreadGroup" not in xml
    once = xml.split("OnceOnlyController", 1)[1]
    assert "Generate code_verifier" in once
    assert "Exchange code for token" in once


def test_per_thread_keeps_the_token_out_of_a_jvm_property():
    """One property, N threads, last writer wins - which defeats per-thread auth entirely."""
    xml = build_tree(build_pkce_ir(AuthStrategy.PER_THREAD), "5.6.3")[0].decode()
    assert "props.put" not in xml


def test_shared_setup_puts_the_exchange_in_a_setup_group_and_promotes_the_token():
    """One login handed to separate flow groups is the case a property is actually for."""
    xml = build_tree(build_pkce_ir(AuthStrategy.SHARED_SETUP), "5.6.3")[0].decode()

    assert "SetupThreadGroup" in xml
    assert "OnceOnlyController" not in xml
    assert 'props.put("accessToken"' in xml


def test_the_authorize_request_carries_the_rfc_parameters(pkce_xml, pkce_ir):
    assert "response_type=code" in pkce_xml
    assert "code_challenge_method=S256" in pkce_xml
    assert f"code_challenge=%24%7B{CHALLENGE_VAR}%7D" in pkce_xml or (
        f"code_challenge=${{{CHALLENGE_VAR}}}" in pkce_xml
    )
    assert pkce_ir.auth.redirect_uri is not None


def test_the_token_exchange_sends_the_verifier_and_the_code(pkce_xml):
    exchange = pkce_xml.split('testname="Exchange code for token"', 1)[1]
    body = exchange.split("</elementProp>", 1)[0]
    assert "grant_type=authorization_code" in body
    assert f"${{{CODE_VAR}}}" in body
    assert f"${{{VERIFIER_VAR}}}" in body


def test_seed_cookies_are_emitted_and_survive_the_iteration_boundary(pkce_xml):
    assert 'testname="AADSSO"' in pkce_xml
    assert "login.example.internal" in pkce_xml
    assert '<boolProp name="CookieManager.clearEachIteration">false</boolProp>' in pkce_xml


def test_a_spec_with_no_seed_cookies_emits_no_cookie_entries():
    ir = build_pkce_ir()
    ir.auth.seed_cookies = []
    xml = build_tree(ir, "5.6.3")[0].decode()
    assert 'elementType="Cookie"' not in xml


def test_correlated_headers_on_an_auth_step_are_rewritten(pkce_xml):
    """`canary: {canary}` has to become `${canary}` - the reference sends a header that never
    resolves because its extractor writes a differently-spelled variable."""
    assert "<stringProp name=\"Header.value\">${canary}</stringProp>" in pkce_xml
    assert "{canary}<" not in pkce_xml.replace("${canary}<", "")


def test_the_whole_pkce_plan_passes_structural_validation(pkce_ir):
    xml, warnings = build_tree(pkce_ir, "5.6.3")
    report = validate_xml(xml)
    assert report.ok, str(report)
    assert not warnings


def test_no_credential_value_is_written_into_the_script(pkce_xml):
    """Only environment lookups by name, never a value - the same rule as every other auth type."""
    assert "System.getenv('PKCE_CLIENT_ID')" in pkce_xml


# ------------------------------------------------------------------------------------------
# Parsing


def pkce_spec(**overrides) -> WorkbookSpec:
    spec = set_application_value(WorkbookSpec(), "Auth type", "OAuth2 PKCE")
    set_application_value(spec, "Authorize endpoint URL", "https://login.x/tenant/authorize")
    set_application_value(spec, "Redirect URI", "msal-abc://auth")
    set_application_value(spec, "Scope", "api://booking/Execute")
    spec.auth_steps = [list(row) for row in DEFAULT_AUTH_STEPS]
    for label, value in overrides.items():
        set_application_value(spec, label.replace("_", " "), value)
    return spec


def test_a_complete_pkce_spec_parses(tmp_path):
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", pkce_spec()))

    assert not result.blocking, [g.message for g in result.blocking]
    assert result.ir is not None
    assert result.ir.auth.type is AuthType.OAUTH2_PKCE
    assert result.ir.auth.authorize_url == "https://login.x/tenant/authorize"
    assert result.ir.auth.redirect_uri == "msal-abc://auth"


def test_pkce_falls_back_to_per_thread_when_the_account_model_is_unusable(tmp_path):
    """A blank 'Account model' stays a blocking gap - this is only which way it leans meanwhile.

    PKCE leans per_thread because that is the shape the reference actually ran against a live
    tenant; every other auth type leans shared_setup, as before.
    """
    spec = pkce_spec()
    set_application_value(spec, "Account model", None)
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))

    assert any(g.field == "auth.strategy" for g in result.blocking)
    assert result.ir is not None
    assert result.ir.auth.strategy is AuthStrategy.PER_THREAD


def test_pkce_honours_an_explicit_single_shared_account_model(tmp_path):
    spec = pkce_spec()
    set_application_value(spec, "Account model", "Single shared")
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))

    assert result.ir is not None
    assert result.ir.auth.strategy is AuthStrategy.SHARED_SETUP


def test_auth_flow_steps_are_ordered_and_keep_their_placeholders(tmp_path):
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", pkce_spec()))

    steps = result.ir.auth.flow_steps
    assert [s.index for s in steps] == [1, 2]
    assert [s.name for s in steps] == ["Get credential type", "Sign in"]
    assert "{sCtx}" in steps[0].body
    assert steps[0].headers["canary"] == "{canary}"
    assert steps[1].expected_status == 302


def test_the_last_auth_step_produces_the_code_by_default(tmp_path):
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", pkce_spec()))
    assert result.ir.auth.code_step.name == "Sign in"


def test_auth_flow_steps_with_a_repeated_number_are_blocking(tmp_path):
    spec = pkce_spec()
    spec.auth_steps[1][0] = 1
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))

    gap = next(g for g in result.blocking if g.field == "auth.flow_steps.index")
    assert "repeats" in gap.message


def test_request_headers_reach_flow_steps_too(tmp_path):
    """The column is on both sheets: a flow step needing a correlated header was previously
    inexpressible, quite apart from PKCE."""
    spec = WorkbookSpec()
    spec.steps[0][6] = "X-Trace-Id: {traceId}"
    result = parse_workbook(write_workbook(tmp_path / "spec.xlsx", spec))

    step = result.ir.flows[0].steps[0]
    assert step.headers == {"X-Trace-Id": "{traceId}"}
