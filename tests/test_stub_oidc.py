"""Run A: proving the stub can fail.

Until this passes, nothing the stub says about perfgen is evidence. A provider that accepts any
`code_verifier` would turn the M7 gate green while proving nothing - worse than no gate, because it
would look like proof. So these tests are mostly about the rejections, and the happy path is here
only to show the rejections are not simply "everything fails".

No perfgen code is involved. This is the stub examined on its own terms.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from tests.stubs.oidc_provider import StubProvider, base64url_sha256

# RFC 7636 Appendix B, so the transformation is pinned against the RFC rather than against
# whatever this code happens to compute.
RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

REDIRECT = "https://example.internal/callback"
USER = "stub.tester@example.internal"
PASSWORD = "stub-password-9f2c"


@pytest.fixture
def stub(monkeypatch):
    monkeypatch.setenv("STUB_LOGIN_USER", USER)
    monkeypatch.setenv("STUB_LOGIN_PASSWORD", PASSWORD)
    provider = StubProvider()
    provider.start()
    yield provider
    provider.stop()


@pytest.fixture
def client(stub):
    with httpx.Client(base_url=stub.base_url, timeout=10, follow_redirects=False) as c:
        yield c


def authorize(client, challenge=RFC_CHALLENGE, method="S256", redirect=REDIRECT):
    return client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "perfgen-test",
            "scope": "openid",
            "redirect_uri": redirect,
            "state": "xyz-state",
            "code_challenge": challenge,
            "code_challenge_method": method,
        },
    )


def login(client, page_html, user=USER, password=PASSWORD):
    token = re.search(r'name="loginToken" value="([^"]+)"', page_html).group(1)
    nonce = re.search(r'"sessionNonce":"([^"]+)"', page_html).group(1)
    return client.post(
        "/login",
        content=(
            f"loginToken={token}&sessionNonce={nonce}&username={user}&password={password}"
        ),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def code_from(response):

    return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]


def token(client, code, verifier, redirect=REDIRECT):
    return client.post(
        "/token",
        content=(
            "grant_type=authorization_code"
            f"&code={code}&redirect_uri={redirect}&code_verifier={verifier}"
            "&client_id=perfgen-test"
        ),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


# ------------------------------------------------------------------------------------------
# The transformation itself


def test_the_stub_computes_the_rfc_test_vector():
    assert base64url_sha256(RFC_VERIFIER) == RFC_CHALLENGE


# ------------------------------------------------------------------------------------------
# The happy path, so the rejections below mean something


def test_the_correct_verifier_yields_a_token(client):
    page = authorize(client)
    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]

    redirected = login(client, page.text)
    assert redirected.status_code == 302

    granted = token(client, code_from(redirected), RFC_VERIFIER)
    assert granted.status_code == 200
    payload = granted.json()
    assert payload["token_type"] == "Bearer"
    assert payload["access_token"].startswith("stub.")


# ------------------------------------------------------------------------------------------
# The rejections - the reason this stub is worth anything


def test_a_wrong_verifier_is_rejected(client):
    """The check the whole exercise turns on."""
    page = authorize(client)
    redirected = login(client, page.text)

    granted = token(client, code_from(redirected), "not-the-verifier-that-was-hashed-000")

    assert granted.status_code == 400
    assert granted.json()["error"] == "invalid_grant"
    assert "code_verifier does not match" in granted.json()["error_description"]


def test_a_missing_verifier_is_rejected(client):
    page = authorize(client)
    redirected = login(client, page.text)
    code = code_from(redirected)

    granted = client.post(
        "/token",
        content=f"grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert granted.status_code == 400
    assert granted.json()["error"] == "invalid_grant"


def test_a_reused_code_is_rejected(client):
    """Single use. A replayed code is how a script mishandling state still looks like it works."""
    page = authorize(client)
    redirected = login(client, page.text)
    code = code_from(redirected)

    assert token(client, code, RFC_VERIFIER).status_code == 200
    second = token(client, code, RFC_VERIFIER)

    assert second.status_code == 400
    assert "already been redeemed" in second.json()["error_description"]


def test_a_mismatched_redirect_uri_is_rejected(client):
    """RFC 6749 4.1.3 requires it to match the one the code was issued for."""
    page = authorize(client)
    redirected = login(client, page.text)

    granted = token(
        client, code_from(redirected), RFC_VERIFIER, redirect="https://elsewhere.internal/cb"
    )

    assert granted.status_code == 400
    assert granted.json()["error"] == "invalid_grant"


def test_the_plain_challenge_method_is_refused(client):
    """Accepting `plain` would let an implementation that never hashes anything pass."""
    page = authorize(client, challenge=RFC_VERIFIER, method="plain")

    assert page.status_code == 400
    assert "S256" in page.json()["error_description"]


def test_an_absent_challenge_is_refused(client):
    page = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "perfgen-test",
            "redirect_uri": REDIRECT,
        },
    )
    assert page.status_code == 400
    assert page.json()["error"] == "invalid_request"


# ------------------------------------------------------------------------------------------
# The login form is load-bearing


def test_a_wrong_login_token_is_rejected(client):
    """If perfgen fails to correlate this, the login must fail rather than pass unnoticed."""
    page = authorize(client)
    nonce = re.search(r'"sessionNonce":"([^"]+)"', page.text).group(1)

    answered = client.post(
        "/login",
        content=f"loginToken=wrong&sessionNonce={nonce}&username={USER}&password={PASSWORD}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert answered.status_code == 400
    assert "loginToken" in answered.json()["error_description"]


def test_a_wrong_session_nonce_is_rejected(client):
    """The nonce lives in a script blob: the raw-text extraction path, made load-bearing."""
    page = authorize(client)
    login_token = re.search(r'name="loginToken" value="([^"]+)"', page.text).group(1)

    answered = client.post(
        "/login",
        content=f"loginToken={login_token}&sessionNonce=wrong&username={USER}&password={PASSWORD}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert answered.status_code == 400
    assert "sessionNonce" in answered.json()["error_description"]


def test_wrong_credentials_are_rejected(client):
    page = authorize(client)
    answered = login(client, page.text, password="not-the-password")

    assert answered.status_code == 401
    assert answered.json()["error"] == "access_denied"


# ------------------------------------------------------------------------------------------
# The page carries both extraction shapes


def test_the_login_page_carries_one_value_in_each_shape(client):
    """One hidden input, one JSON blob inside a script - so a passing gate exercises both paths."""
    page = authorize(client).text

    assert 'name="loginToken" value="' in page
    assert '"sessionNonce":"' in page
    assert "<form method=\"POST\" action=\"/login\"" in page
