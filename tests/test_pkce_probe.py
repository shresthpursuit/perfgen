"""The probe walking a PKCE exchange, and the credential references the login step needs.

Against a stub identity provider, never a real one. The stub answers `/authorize` with the same
HTML shape the reference script scrapes, checks the login credentials it is sent, and issues a 302
carrying an authorization code.

The load-bearing test here is `test_add_secret_runs_before_anything_is_recorded`. Everything else
checks an outcome; that one checks an *ordering*, because the guarantee that a password never
reaches the probe record is the order of two calls and nothing else. An order-dependent guarantee
that is only tested by its outcome passes just as happily when the outcome is right by luck.
"""

from __future__ import annotations

import httpx
import pytest

from perfgen import secrets
from perfgen.ir.models import (
    Application,
    Auth,
    AuthType,
    Flow,
    LoadProfile,
    Method,
    ProfileId,
    Provenance,
    SeedCookie,
    Step,
    TestPlanIR,
    TokenExtract,
    TokenRequest,
)
from perfgen.probe.runner import run_probe
from tests.fixtures.html_login import CANARY, S_CTX, S_FT, login_page

PASSWORD = "correct-horse-battery-staple-9f2c"
USERNAME = "perf.tester@example.internal"
CLIENT_ID = "11112222-3333-4444-5555-666677778888"
ISSUED_CODE = "0.AXkAauthorizationcodevalue123456789"
ISSUED_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.stubtokenpayload.stubsignature"


@pytest.fixture
def credentials(monkeypatch):
    monkeypatch.setenv("PKCE_LOGIN_USER", USERNAME)
    monkeypatch.setenv("PKCE_LOGIN_PASSWORD", PASSWORD)
    monkeypatch.setenv("PKCE_CLIENT_ID", CLIENT_ID)


def pkce_ir() -> TestPlanIR:
    return TestPlanIR(
        application=Application(name="PKCE probe", base_url="https://api.example.internal"),
        auth=Auth(
            type=AuthType.OAUTH2_PKCE,
            header_name="Authorization",
            value_format="Bearer {token}",
            token_request=TokenRequest(
                method="POST",
                url="https://idp.test/tenant/oauth2/v2.0/token",
                content_type="application/x-www-form-urlencoded",
                param_names=["client_id"],
                credential_refs=["pkce-client-id"],
            ),
            token_extract=TokenExtract(var="accessToken"),
            authorize_url="https://idp.test/tenant/oauth2/v2.0/authorize",
            redirect_uri="msal-abc://auth",
            scope="api://booking/Execute",
            seed_cookies=[SeedCookie(name="AADSSO", value="NA|NoExtension", domain="idp.test")],
            flow_steps=[
                Step(
                    index=1,
                    name="Get credential type",
                    method=Method.POST,
                    path="/common/GetCredentialType",
                    body='{"username":"{secret:pkce-login-user}","originalRequest":"{sCtx}"}',
                    content_type="application/json",
                    expected_status=200,
                    headers={"canary": "{canary}"},
                ),
                Step(
                    index=2,
                    name="Sign in",
                    method=Method.POST,
                    path="/tenant/login",
                    body=(
                        "login={secret:pkce-login-user}&passwd={secret:pkce-login-password}"
                        "&ctx={sCtx}&flowToken={sFT}"
                    ),
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
                think_time_ms=0,
                probe_safe=True,
                steps=[
                    Step(
                        index=1,
                        name="List",
                        method=Method.GET,
                        path="/bookings",
                        expected_status=200,
                    )
                ],
            )
        ],
        load_profiles=[
            LoadProfile(id=ProfileId.BASELINE, enabled=True, users=1, ramp_up_s=1, duration_s=10)
        ],
        provenance=Provenance(source_workbook="pkce.xlsx", generated_at="2026-08-25T00:00:00Z"),
    )


@pytest.fixture
def idp(monkeypatch):
    """A stub Entra. Records what it was sent, and only issues a code for the right password."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path

        if path.endswith("/authorize"):
            return httpx.Response(
                200, headers={"Content-Type": "text/html; charset=utf-8"}, text=login_page()
            )
        if path.endswith("/GetCredentialType"):
            return httpx.Response(200, json={"IfExistsResult": 0})
        if path.endswith("/login"):
            body = request.content.decode()
            if f"passwd={PASSWORD}" not in body:
                return httpx.Response(200, text="<html>Your password is incorrect</html>")
            return httpx.Response(
                302, headers={"Location": f"msal-abc://auth?code={ISSUED_CODE}&state=x"}
            )
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": ISSUED_TOKEN, "expires_in": 3599})
        return httpx.Response(200, json={"ok": "listed"})

    transport = httpx.MockTransport(handler)
    original = httpx.Client

    def patched(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr("perfgen.probe.runner.httpx.Client", patched)
    return seen


def sent_to(seen: list[httpx.Request], suffix: str) -> httpx.Request:
    return next(r for r in seen if r.url.path.endswith(suffix))


# ------------------------------------------------------------------------------------------
# The exchange


def test_the_probe_walks_authorize_login_and_token(idp, credentials):
    outcome = run_probe(pkce_ir(), timeout_s=5)

    assert not outcome.degraded, outcome.record.degraded_reason
    names = [c.name for c in outcome.record.calls]
    assert names[:4] == [
        "Authorize",
        "Get credential type",
        "Sign in",
        "Exchange code for token",
    ]


def test_the_token_call_carries_the_code_and_the_matching_verifier(idp, credentials):
    """PKCE's whole point: the verifier sent here must hash to the challenge sent to /authorize."""
    import base64
    import hashlib
    from urllib.parse import parse_qs

    run_probe(pkce_ir(), timeout_s=5)

    challenge = parse_qs(sent_to(idp, "/authorize").url.query.decode())["code_challenge"][0]
    token_body = parse_qs(sent_to(idp, "/token").content.decode())

    assert token_body["grant_type"] == ["authorization_code"]
    assert token_body["code"] == [ISSUED_CODE]

    verifier = token_body["code_verifier"][0]
    derived = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    assert derived == challenge


def test_the_code_step_does_not_follow_its_redirect(idp, credentials):
    """A followed redirect consumes the Location header before the code can be read."""
    outcome = run_probe(pkce_ir(), timeout_s=5)

    sign_in = next(c for c in outcome.record.calls if c.name == "Sign in")
    assert sign_in.response is not None
    assert sign_in.response.status == 302, "the redirect was followed, so the code was lost"


def test_correlated_values_come_from_the_html_login_page(idp, credentials):
    """sCtx and canary are scraped from an unparseable body, not guessed from their names."""
    run_probe(pkce_ir(), timeout_s=5)

    credential_type = sent_to(idp, "/GetCredentialType")
    assert S_CTX in credential_type.content.decode()
    assert credential_type.headers["canary"] == CANARY
    assert S_FT in sent_to(idp, "/login").content.decode()


def test_seed_cookies_are_sent(idp, credentials):
    run_probe(pkce_ir(), timeout_s=5)
    assert "AADSSO" in sent_to(idp, "/authorize").headers.get("cookie", "")


# ------------------------------------------------------------------------------------------
# Credentials


def test_the_real_password_is_sent_on_the_wire(idp, credentials):
    run_probe(pkce_ir(), timeout_s=5)
    assert f"passwd={PASSWORD}" in sent_to(idp, "/login").content.decode()


def test_the_real_password_never_reaches_the_probe_record(idp, credentials):
    """The hard constraint. The value goes out on the wire and nowhere near disk."""
    outcome = run_probe(pkce_ir(), timeout_s=5)

    dumped = outcome.record.model_dump_json()
    assert PASSWORD not in dumped
    assert USERNAME not in dumped
    assert ISSUED_TOKEN not in dumped

    # Form bodies are re-encoded on the way out, so the marker arrives percent-escaped. Both the
    # password *and* the username are redacted - the username used to survive as `%40`, hidden
    # from a literal value match by its own encoding.
    from urllib.parse import unquote

    sign_in = next(c for c in outcome.record.calls if c.name == "Sign in")
    body = unquote(sign_in.request.body or "")
    assert "login=[redacted]" in body
    assert "passwd=[redacted]" in body


def test_add_secret_runs_before_anything_is_recorded(idp, credentials, monkeypatch):
    """Pins the ordering itself, not the outcome it happens to produce.

    Registration and recording are two calls on the same redactor, and only their order stops the
    password reaching disk. Asserting the record is clean would still pass if a later refactor
    inverted them and something else happened to scrub the value; this fails the moment a request
    is recorded before the credential it carries has been registered.
    """
    from perfgen.probe import runner

    events: list[str] = []
    real_add = runner.Redactor.add_secret

    def traced_add(self, value):
        if value in (PASSWORD, USERNAME):
            events.append("register")
        return real_add(self, value)

    real_record = runner._record_auth_call

    def traced_record(*args, **kwargs):
        events.append("record")
        return real_record(*args, **kwargs)

    monkeypatch.setattr(runner.Redactor, "add_secret", traced_add)
    monkeypatch.setattr(runner, "_record_auth_call", traced_record)

    run_probe(pkce_ir(), timeout_s=5)

    assert "register" in events, "no credential was ever registered"
    assert "record" in events
    assert events.index("register") < events.index("record"), (
        f"a call was recorded before its credential was registered: {events}"
    )
    # Both credentials, not just the first one to be needed.
    assert events.count("register") == 2
    assert events[:2] == ["register", "register"]


def test_a_missing_credential_names_the_variable_and_degrades(idp, monkeypatch):
    monkeypatch.setenv("PKCE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("PKCE_LOGIN_USER", USERNAME)
    monkeypatch.delenv("PKCE_LOGIN_PASSWORD", raising=False)

    outcome = run_probe(pkce_ir(), timeout_s=5)

    assert outcome.degraded
    assert "PKCE_LOGIN_PASSWORD" in (outcome.record.degraded_reason or "")


def test_a_wrong_password_degrades_rather_than_half_running(idp, monkeypatch):
    monkeypatch.setenv("PKCE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("PKCE_LOGIN_USER", USERNAME)
    monkeypatch.setenv("PKCE_LOGIN_PASSWORD", "not-the-right-one")

    outcome = run_probe(pkce_ir(), timeout_s=5)

    assert outcome.degraded
    assert "authorization code" in (outcome.record.degraded_reason or "")


# ------------------------------------------------------------------------------------------
# The syntax itself


def test_credential_references_are_found_in_step_text():
    ir = pkce_ir()
    assert ir.auth.step_credential_refs == ["pkce-login-user", "pkce-login-password"]


def test_the_two_syntaxes_cannot_be_confused():
    """A correlated placeholder and a credential reference must never match the same text."""
    from perfgen.emit.emitter import rewrite_placeholders

    text = "ctx={sCtx}&user={secret:pkce-login-user}&nested={{userId}}"

    # The credential pattern sees only the credential.
    assert secrets.references_in(text) == ["pkce-login-user"]

    # The placeholder rewrite leaves the credential alone.
    rewritten = rewrite_placeholders(text, {})
    assert "{secret:pkce-login-user}" in rewritten


def test_env_var_mapping_is_the_shared_one():
    assert secrets.env_var_name("pkce-login-user") == "PKCE_LOGIN_USER"
