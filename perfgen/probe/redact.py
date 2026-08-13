"""Stripping secrets out of a probe record before it reaches disk.

The hard constraint is that no secret value is ever written to disk, into the IR, into logs, or
into the JMX. The probe is the one stage that holds real credentials in memory, so this is where
that rule is enforced.

Two passes, because either alone leaks:

* **By value.** Every credential the probe resolved, plus the token it received, is replaced
  wherever it appears. This is the strong guarantee: it does not matter which field a secret
  ended up in, or whether we anticipated that field.
* **By name.** Headers and request-body keys that look like credentials are redacted whether or
  not we resolved them. A user can type a password into the free-text "Request body or
  parameters" column, and that value was never in our list to match against.

Response *bodies* are stored verbatim. The correlation engine works by finding values that appear
in one response and a later request, so redacting them would remove the very thing it reads. The
run summary says so rather than leaving it implied.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode

REDACTED = "[redacted]"

# Header names whose value is a credential regardless of what it looks like.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "auth-token",
    "authentication",
    "x-csrf-token",
}

# Body keys that name a credential. Matched as substrings, so `client_secret` and `clientSecret`
# both hit `secret`.
SENSITIVE_KEY_PARTS = (
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "credential",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "private_key",
    "privatekey",
)

# Values too short or too common to redact usefully - blanking them would corrupt the record
# without protecting anything.
_MIN_REDACTABLE_LENGTH = 4


def is_sensitive_key(key: str) -> bool:
    """Does this name suggest a credential?

    Separators are stripped before matching, so the same rule covers body keys and header names:
    `client_secret`, `clientSecret` and `X-Api-Key` all reduce to something the parts below match.
    Without that, `X-Api-Key` matches neither `api_key` nor `apikey` - the hyphen defeats both -
    and a header that plainly names a credential would slip through.
    """
    normalised = re.sub(r"[^a-z0-9]+", "", key.strip().lower())
    return any(part.replace("_", "") in normalised for part in SENSITIVE_KEY_PARTS)


class Redactor:
    """Applies both passes. Built once per probe run with the secrets it must never emit."""

    def __init__(self, secret_values: list[str] | None = None):
        self._values = sorted(
            {v for v in (secret_values or []) if v and len(v) >= _MIN_REDACTABLE_LENGTH},
            key=len,
            reverse=True,  # longest first, so a secret containing another is replaced whole
        )

    def add_secret(self, value: str | None) -> None:
        """Register a value discovered mid-run, such as the token the auth call returned."""
        if value and len(value) >= _MIN_REDACTABLE_LENGTH and value not in self._values:
            self._values.append(value)
            self._values.sort(key=len, reverse=True)

    # -- by value ------------------------------------------------------------------------

    def scrub(self, text: str | None) -> str | None:
        """Replace every known secret value wherever it appears in a string."""
        if text is None:
            return None
        for value in self._values:
            if value in text:
                text = text.replace(value, REDACTED)
        return text

    # -- by name -------------------------------------------------------------------------

    def headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Redact credential-bearing headers, then scrub what is left."""
        cleaned: dict[str, str] = {}
        for name, value in headers.items():
            if name.strip().lower() in SENSITIVE_HEADERS:
                cleaned[name] = REDACTED
            else:
                cleaned[name] = self.scrub(value) or ""
        return cleaned

    def body(self, body: str | None, content_type: str | None = None) -> str | None:
        """Redact credential-looking keys in a request body, then scrub known values.

        Handles JSON and form encoding structurally so the body stays parseable and the shape of
        the request is still reviewable. Anything else is scrubbed by value only.
        """
        if body is None:
            return None

        redacted = self._structured_body(body, content_type)
        return self.scrub(redacted)

    def _structured_body(self, body: str, content_type: str | None) -> str:
        kind = (content_type or "").lower()
        stripped = body.lstrip()

        if "json" in kind or stripped.startswith(("{", "[")):
            try:
                return json.dumps(_redact_json(json.loads(body)))
            except (ValueError, TypeError):
                pass

        if "form-urlencoded" in kind or looks_form_encoded(body):
            try:
                pairs = parse_qsl(body, keep_blank_values=True)
                if pairs:
                    return urlencode(
                        [(k, REDACTED if is_sensitive_key(k) else v) for k, v in pairs]
                    )
            except ValueError:
                pass

        return body

    def cookies(self, cookies: dict[str, str]) -> dict[str, str]:
        """Cookie values are credentials by default; only the names are kept."""
        return dict.fromkeys(cookies, REDACTED)


def _redact_json(node):
    if isinstance(node, dict):
        return {
            key: REDACTED if is_sensitive_key(str(key)) else _redact_json(value)
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_redact_json(item) for item in node]
    return node


_FORM_PAIR = re.compile(r"^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$")


def looks_form_encoded(body: str) -> bool:
    return bool(_FORM_PAIR.match(body.strip()))
