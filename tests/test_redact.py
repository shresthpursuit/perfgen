"""Redaction of the probe record.

Two passes, because either alone leaks: by value (every secret the probe resolved, wherever it
ended up) and by name (anything that looks like a credential, including values we never held).
"""

from __future__ import annotations

import json
from urllib.parse import quote, unquote

import pytest

from perfgen.probe.redact import REDACTED, Redactor, is_sensitive_key


@pytest.fixture
def redactor():
    return Redactor(["s3cret-value-9f2", "client-id-7c1"])


# --------------------------------------------------------------------------------------------
# By value
# --------------------------------------------------------------------------------------------


def test_known_secret_is_removed_wherever_it_appears(redactor):
    text = "prefix s3cret-value-9f2 suffix"
    assert "s3cret-value-9f2" not in redactor.scrub(text)
    assert REDACTED in redactor.scrub(text)


def test_secret_discovered_mid_run_is_redacted_retrospectively(redactor):
    redactor.add_secret("tok-abc123-xyz")
    assert redactor.scrub("Bearer tok-abc123-xyz") == f"Bearer {REDACTED}"


def test_overlapping_secrets_are_replaced_whole(redactor):
    """Longest first, so a secret containing another does not leave a fragment behind."""
    redactor.add_secret("abc")
    redactor.add_secret("abc-extended-value")
    assert "abc" not in redactor.scrub("abc-extended-value")


def test_short_values_are_not_redacted():
    """Blanking a two-character value would corrupt the record without protecting anything."""
    assert Redactor(["ab"]).scrub("a table of ab") == "a table of ab"


def test_scrub_passes_through_none(redactor):
    assert redactor.scrub(None) is None


# --------------------------------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    ["Authorization", "authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-API-Key"],
)
def test_sensitive_headers_are_redacted_by_name(redactor, header):
    assert redactor.headers({header: "anything at all"})[header] == REDACTED


def test_ordinary_headers_are_kept(redactor):
    headers = redactor.headers({"Content-Type": "application/json"})
    assert headers["Content-Type"] == "application/json"


def test_a_secret_in_an_ordinary_header_is_still_removed(redactor):
    headers = redactor.headers({"X-Trace": "run for client-id-7c1"})
    assert "client-id-7c1" not in headers["X-Trace"]


def test_cookies_keep_names_and_lose_values(redactor):
    assert redactor.cookies({"session": "abc123", "csrf": "xyz"}) == {
        "session": REDACTED,
        "csrf": REDACTED,
    }


# --------------------------------------------------------------------------------------------
# Request bodies
# --------------------------------------------------------------------------------------------


def test_form_encoded_credentials_are_redacted_by_key(redactor):
    body = "grant_type=client_credentials&client_id=abc&client_secret=shhh"
    cleaned = redactor.body(body, "application/x-www-form-urlencoded")

    assert "shhh" not in cleaned
    assert "grant_type=client_credentials" in cleaned, "non-secret parameters stay readable"


def test_json_body_credentials_are_redacted_by_key(redactor):
    body = json.dumps({"username": "alice", "password": "hunter2", "nested": {"apiKey": "k"}})
    cleaned = json.loads(redactor.body(body, "application/json"))

    assert cleaned["password"] == REDACTED
    assert cleaned["nested"]["apiKey"] == REDACTED
    assert cleaned["username"] == "alice", "non-secret fields stay reviewable"


def test_redacted_json_body_is_still_valid_json(redactor):
    body = json.dumps({"token": "abc", "keep": [1, 2, {"secret": "x"}]})
    parsed = json.loads(redactor.body(body, "application/json"))
    assert parsed["keep"][2]["secret"] == REDACTED


def test_a_secret_typed_into_a_free_text_body_is_caught_by_name(redactor):
    """The user's Request body column is free text; a mistyped password is not in our value list."""
    body = json.dumps({"type": "standard", "password": "never-seen-before"})
    assert "never-seen-before" not in redactor.body(body, "application/json")


def test_a_resolved_secret_in_an_unrecognised_body_is_caught_by_value(redactor):
    """No key name to match, so the value pass is what saves it."""
    body = "<xml><cred>s3cret-value-9f2</cred></xml>"
    assert "s3cret-value-9f2" not in redactor.body(body, "application/xml")


def test_body_type_is_inferred_when_no_content_type_is_given(redactor):
    cleaned = redactor.body('{"password":"hunter2"}', None)
    assert json.loads(cleaned)["password"] == REDACTED


def test_malformed_json_falls_back_to_value_scrubbing(redactor):
    body = "{not valid json s3cret-value-9f2"
    cleaned = redactor.body(body, "application/json")
    assert "s3cret-value-9f2" not in cleaned


def test_body_passes_through_none(redactor):
    assert redactor.body(None) is None


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "client_secret",
        "clientSecret",
        "api_key",
        "apiKey",
        "access_token",
        # Header spellings. Found when reusing this for header names: the hyphen used to defeat
        # both `api_key` and `apikey`, so a header plainly naming a credential slipped through.
        "X-Api-Key",
        "X-Auth-Token",
        "Proxy-Authorization",
    ],
)
def test_sensitive_key_detection(key):
    assert is_sensitive_key(key)


@pytest.mark.parametrize("key", ["username", "type", "subject", "quantity"])
def test_ordinary_keys_are_not_sensitive(key):
    assert not is_sensitive_key(key)


# ------------------------------------------------------------------------------------------
# Encoding must not hide a value from the value pass
#
# Found while wiring credentials into PKCE login steps. Redaction ran structurally first and
# scrubbed by value afterwards, on the re-encoded text - so a secret containing any character the
# encoding touches was invisible to the value match. Redaction by key name masked it: `passwd` was
# caught by its name while the same secret under `login` went straight through.


def test_a_secret_survives_no_encoding_in_a_form_body():
    secret = "p@ssw0rd+with/special=chars"
    redactor = Redactor([secret])

    encoded = f"custom={quote(secret, safe='')}&ctx=abc"
    assert secret not in unquote(redactor.body(encoded, "application/x-www-form-urlencoded"))


def test_a_secret_substituted_verbatim_into_a_form_body_is_still_caught():
    """What the probe actually sends: the raw value dropped into the spec's own template."""
    secret = "p@ssw0rd+with/special=chars"
    redactor = Redactor([secret])

    raw = f"custom={secret}&ctx=abc"
    assert secret not in unquote(redactor.body(raw, "application/x-www-form-urlencoded"))


def test_a_secret_under_an_innocuous_form_key_is_caught_by_value():
    """`passwd` is caught by name; `login` is not, and used to leak."""
    secret = "perf.tester@example.internal"
    redactor = Redactor([secret])

    body = f"login={secret}&ctx=abc"
    assert secret not in unquote(redactor.body(body, "application/x-www-form-urlencoded"))


def test_json_escaping_does_not_hide_a_secret():
    secret = 'quote"and\backslash-value-1234'
    redactor = Redactor([secret])

    body = json.dumps({"note": secret, "ctx": "abc"})
    assert secret not in json.loads(redactor.body(body, "application/json"))["note"]


def test_a_non_ascii_secret_is_caught_in_json():
    secret = "pässwörd-with-ümlauts-9f2c"
    redactor = Redactor([secret])

    body = json.dumps({"note": secret})
    assert secret not in json.loads(redactor.body(body, "application/json"))["note"]
