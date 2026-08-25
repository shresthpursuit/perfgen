"""Raw-text scanning: finding values in a body no parser can read, and extracting them again.

Structured parsing hands you a location for free - `$.data[0].id` is both the answer and the
extractor. Raw text hands you a byte offset, which JMeter cannot read back, so an expression has to
be synthesised from context. That synthesis is the part that can go quietly wrong, and these tests
are mostly about the ways it is stopped from doing so.

The shapes come from `docs/reference/pkce_entra_reference.jmx`, whose `/authorize` response is an
HTML page carrying the whole login sequence's inputs inside a JavaScript blob.
"""

from __future__ import annotations

import pytest

from perfgen.correlate.scan import TEXT_FORMAT, find_candidates
from perfgen.correlate.text import find_by_key, find_value, index_text, verify
from perfgen.probe.records import (
    ProbeRecord,
    RecordedCall,
    RecordedRequest,
    RecordedResponse,
)
from tests.fixtures.html_login import (
    CANARY,
    CLIENT_REQUEST_ID,
    HPGID,
    INSTRUMENTATION_KEY,
    NONCE_FIRST,
    S_CTX,
    S_FT,
    SESSION_ID,
    login_page,
)


@pytest.fixture
def html() -> str:
    return login_page()


# ------------------------------------------------------------------------------------------
# Synthesis


@pytest.mark.parametrize(
    "value,key,left,right",
    [
        (S_CTX, "sCtx", '"sCtx":"', '"'),
        (S_FT, "sFT", '"sFT":"', '"'),
        (CANARY, "canary", '"canary":"', '"'),
        (SESSION_ID, "sessionId", '"sessionId":"', '"'),
        # Unquoted and numeric, so a comma terminates it rather than a quote.
        (HPGID, "hpgid", '"hpgid":', ","),
        (INSTRUMENTATION_KEY, "instrumentationKey", '"instrumentationKey":"', '"'),
        # Inside a URL inside a JavaScript string, so the ampersand arrives JSON-escaped. As a
        # regex the terminator needs \\\\u0026; as a boundary it needs no escaping at all.
        (CLIENT_REQUEST_ID, "client-request-id", "client-request-id=", "\\u0026"),
    ],
)
def test_the_reference_shapes_all_synthesise_a_verified_boundary(html, value, key, left, right):
    match = find_value(html, value)

    assert match is not None, f"no extractor synthesised for {key}"
    assert match.key == key
    assert match.left == left
    assert match.right == right
    assert match.unique
    assert verify(html, match)


def test_the_escaped_ampersand_is_six_characters_not_one(html):
    """If this collapses to `&`, the extractor stops at the wrong place - or never matches."""
    match = find_value(html, CLIENT_REQUEST_ID)
    assert match.right == "\\u0026"
    assert len(match.right) == 6


# ------------------------------------------------------------------------------------------
# The guards


def test_a_value_with_no_key_before_it_yields_no_extractor():
    """An arbitrary character window would produce context that changes between runs."""
    body = "<html><body>a1b2c3d4e5f6g7h8 sits here with nothing naming it</body></html>"
    assert find_value(body, "a1b2c3d4e5f6g7h8") is None


def test_a_key_appearing_twice_yields_no_extractor(html):
    """Two values under one key: picking either is a guess, and guessing is the whole problem."""
    match = find_value(html, NONCE_FIRST)

    assert match is not None
    assert match.occurrences == 2
    assert not match.unique
    assert not verify(html, match)
    assert "nonce" not in index_text(html, [NONCE_FIRST])


def test_a_value_that_is_absent_yields_nothing(html):
    assert find_value(html, "this-string-is-not-in-the-page") is None


def test_a_value_with_no_closing_boundary_yields_nothing():
    body = '{"token":"abcdefghijklmnop'
    assert find_value(body, "abcdefghijklmnop") is None


def test_verification_rejects_an_extractor_that_does_not_reproduce_the_value(html):
    """The guard that matters: the expression is executed, not merely inspected."""
    match = find_value(html, S_CTX)
    assert verify(html, match)

    tampered = match.__class__(**{**match.__dict__, "value": S_CTX + "TAMPERED"})
    assert not verify(html, tampered)


# ------------------------------------------------------------------------------------------
# The probe's direction: name to value


def test_find_by_key_resolves_a_declared_placeholder(html):
    """`{sCtx}` in a login body has to become a value before the request can be sent at all."""
    match = find_by_key(html, "sCtx")

    assert match is not None
    assert match.value == S_CTX
    assert verify(html, match)


def test_find_by_key_handles_an_unquoted_numeric_value(html):
    match = find_by_key(html, "hpgid")
    assert match is not None
    assert match.value == HPGID


def test_find_by_key_is_case_insensitive(html):
    assert find_by_key(html, "SCTX").value == S_CTX


def test_find_by_key_returns_nothing_for_an_absent_key(html):
    assert find_by_key(html, "noSuchKeyAnywhere") is None


# ------------------------------------------------------------------------------------------
# Through the scan


def call(name: str, *, body: str = "", request_body: str = "", index: int = 1) -> RecordedCall:
    return RecordedCall(
        flow_id="AUTH",
        step_index=index,
        name=name,
        request=RecordedRequest(
            method="POST", url="https://login.example/step", headers={}, body=request_body
        ),
        response=RecordedResponse(
            status=200, headers={"Content-Type": "text/html"}, cookies={}, body=body
        ),
    )


def test_an_html_response_now_yields_candidates_instead_of_only_a_complaint(html):
    """Before this, the login page reported as UnreadableBody and contributed nothing."""
    record = ProbeRecord(
        application="pkce",
        performed_at="2026-08-25T00:00:00Z",
        calls=[
            call("Authorize", body=html, index=1),
            call("Get credential type", request_body=f'{{"ctx":"{S_CTX}"}}', index=2),
        ],
    )

    result = find_candidates(record)
    found = {c.value: c for c in result.candidates}

    assert S_CTX in found
    candidate = found[S_CTX]
    assert candidate.body_format == TEXT_FORMAT
    assert candidate.source_location == '"sCtx":"||"'
    assert not result.unreadable, "a body that yielded candidates is not an unreadable body"


def test_a_body_that_yields_nothing_is_still_reported_as_unreadable(html):
    """Text scanning must not turn a dead end into silence.

    The same login page, but the later request carries nothing that came from it. Nothing is
    found, so the body is still reported as one no parser could read - under-reporting is the bug
    that reporting replaced.
    """
    record = ProbeRecord(
        application="pkce",
        performed_at="2026-08-25T00:00:00Z",
        calls=[
            call("Authorize", body=html, index=1),
            call("Next", request_body='{"unrelated":"nothing-from-that-page-at-all"}', index=2),
        ],
    )

    result = find_candidates(record)

    assert not result.candidates
    assert result.unreadable, "under-reporting is the bug this replaced"
