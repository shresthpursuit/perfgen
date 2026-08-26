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
    INTERSTITIAL_CANARY,
    INTERSTITIAL_FLOW_TOKEN,
    INTERSTITIAL_REQUEST,
    NONCE_FIRST,
    S_CTX,
    S_FT,
    SESSION_ID,
    interstitial_page,
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


# ------------------------------------------------------------------------------------------
# Separators
#
# The structured path already matches names separator-insensitively - `normalise_field` strips
# them from both sides, so `{userId}` finds `user_id`. The text path matched literally, so
# `{client_request_id}` failed to find `client-request-id=` in a page that plainly contained it.
# One placeholder style working in one context and not the other, with nothing to explain why, is
# the defect; the fix is symmetry rather than a rule for the reader to remember.


@pytest.mark.parametrize(
    "written",
    ["client_request_id", "client-request-id", "clientRequestId", "CLIENT_REQUEST_ID"],
)
def test_a_key_resolves_however_the_placeholder_spells_it(html, written):
    match = find_by_key(html, written)

    assert match is not None, f"{written} did not find client-request-id="
    assert match.value == CLIENT_REQUEST_ID


@pytest.mark.parametrize("written", ["sessionId", "session_id", "session-id"])
def test_camel_case_and_snake_case_find_each_other(html, written):
    assert find_by_key(html, written).value == SESSION_ID


def test_a_key_that_is_genuinely_absent_still_finds_nothing(html):
    """Loosening separators must not loosen it into matching anything."""
    assert find_by_key(html, "noSuchKey") is None
    assert find_by_key(html, "s_c_t_x_extra") is None


def test_a_single_word_key_is_matched_exactly(html):
    assert find_by_key(html, "hpgid").value == HPGID


def test_an_earlier_near_miss_does_not_hide_the_real_key():
    """Found on a live Entra page, not in a fixture.

    `sCtx` loosened to `s[^A-Za-z0-9]*Ctx` also matches `s?ctx=` inside a `/reprocess?ctx=` URL,
    and that decoy sat 3KB *before* the real `"sCtx":"`. Taking the first anchor hit and giving up
    discarded the genuine key. Exact spelling is tried first, and every hit is considered rather
    than only the first, so a near-miss that cannot be verified is passed over.
    """
    body = (
        '<a href="https://login.example.com/common/reprocess?ctx=DECOYVALUEdecoyvalue123">x</a>'
        '<script>$Config={"name":"code","sCtx":"REALVALUEreal9876543210","sFT":"tok"};</script>'
    )

    match = find_by_key(body, "sCtx")

    assert match is not None
    assert match.left == '"sCtx":"'
    assert match.value == "REALVALUEreal9876543210"
    assert verify(body, match)


def test_the_loose_pattern_is_still_used_when_the_exact_one_is_absent(html):
    """Exact-first must not disable the separator handling it was added for."""
    assert find_by_key(html, "client_request_id").value == CLIENT_REQUEST_ID


def test_a_key_name_occurring_inside_a_value_is_not_an_anchor():
    """Found on a live Entra login page, and the nastiest shape yet.

    Entra's canary value contains the literal text `CANARY:` within itself. The anchor matched
    there - inside the very value it was looking for - and returned the tail: 44 characters where
    the real value is 99. It passed verification, because that context did occur exactly once.

    A plausible, verifiable, silently wrong value is precisely what this module exists to avoid, so
    a key only anchors where a key can sit: after a delimiter, never mid-token. Asserted as the
    whole value coming back rather than as nothing coming back - the tail is what a mid-token
    anchor produces, and "not the tail" is the property that matters.
    """
    whole = "ZNGuujd3Dykk=7:1:CANARY:tailonlyABCDEF0123456789"
    body = '{"other":"x","canary":"' + whole + '"}'

    match = find_by_key(body, "canary")

    assert match is not None
    assert match.value == whole
    assert match.left == '"canary":"'


def test_a_key_after_an_ordinary_delimiter_still_anchors():
    """The guard must reject mid-token matches without rejecting real ones."""
    for body, expected in [
        ('{"canary":"realvalue0123456789"}', "realvalue0123456789"),
        ('x,"canary":"realvalue0123456789"', "realvalue0123456789"),
        ("https://x/y?canary=realvalue0123456789&z=1", "realvalue0123456789"),
    ]:
        match = find_by_key(body, "canary")
        assert match is not None, body
        assert match.value == expected


# ------------------------------------------------------------------------------------------
# Hidden form inputs
#
# An auto-submitted interstitial carries its state in `<input name="k" value="v">`, where the name
# and the value are separate attributes with arbitrary text between them - invisible to anchoring
# that expects `key: value`. Generic HTML rather than an Entra quirk: SAML's POST binding is the
# same shape. A live PKCE run stalled here, because the login step's 200 was one of these pages.


@pytest.fixture
def interstitial() -> str:
    return interstitial_page()


@pytest.mark.parametrize(
    "name,expected",
    [
        ("request", INTERSTITIAL_REQUEST),
        ("flowToken", INTERSTITIAL_FLOW_TOKEN),
        ("canary", INTERSTITIAL_CANARY),
    ],
)
def test_a_hidden_input_resolves_by_name(interstitial, name, expected):
    """The probe's direction: a declared `{request}` needs a value before the step can be sent."""
    match = find_by_key(interstitial, name)

    assert match is not None, f"{name} not found in the interstitial"
    assert match.value == expected
    assert match.left == f'name="{name}" value="'
    assert verify(interstitial, match)


@pytest.mark.parametrize(
    "name,expected",
    [
        ("request", INTERSTITIAL_REQUEST),
        ("flowToken", INTERSTITIAL_FLOW_TOKEN),
        ("canary", INTERSTITIAL_CANARY),
    ],
)
def test_a_hidden_input_yields_a_boundary_naming_its_own_field(interstitial, name, expected):
    """The scan's direction, and the extractor the emitted script will carry.

    Anchoring on the bare `value="` would be ambiguous - every input on the page has one - so it
    would be rejected and no extractor offered at all. The field's own name disambiguates it.
    """
    match = find_value(interstitial, expected)

    assert match is not None
    assert match.key == name
    assert match.left == f'name="{name}" value="'
    assert match.right == '"'
    assert match.unique
    assert verify(interstitial, match)


def test_a_value_containing_its_own_key_name_still_extracts_whole(interstitial):
    """The permanent regression for the canary self-match.

    A live tenant returned a canary whose value contains the literal text `CANARY:`. Anchoring
    matched *inside the value it was looking for* and returned only the tail - and it verified,
    because that context genuinely occurred once. Verification cannot catch this class on its own:
    the expression really does reproduce what it extracted. Only refusing to anchor mid-token does.
    """
    assert "CANARY:" in INTERSTITIAL_CANARY, "the fixture must keep the self-referencing shape"

    match = find_by_key(interstitial, "canary")

    assert match is not None
    assert match.value == INTERSTITIAL_CANARY, "extracted only the tail after the embedded key"
    assert match.value.startswith("ZNGuujd3")


def test_an_input_whose_name_is_absent_yields_nothing(interstitial):
    assert find_by_key(interstitial, "noSuchField") is None
