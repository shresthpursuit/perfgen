"""An HTML login page shaped like the one Entra's `/authorize` actually returns.

Not a copy - the values are synthetic - but the *shapes* are taken from
`docs/reference/pkce_entra_reference.jmx`, because those are what the extractor synthesis has to
cope with:

* `"sCtx":"…"` - the ordinary quoted-JSON-in-HTML case.
* `"hpgid":1104,` - unquoted, numeric, terminated by a comma rather than a quote.
* `client-request-id=…\\u0026` - inside a URL inside a JavaScript string, so the ampersand arrives
  JSON-escaped. This is the case that decides boundary-versus-regex: as a regex the terminator
  needs `\\\\u0026` and is written wrong more often than right.
* A repeated `"nonce":"…"` - two different values under one key, so the anchor is ambiguous and no
  extractor may be offered.
* Decoys the low-entropy filter must still reject: `true`, `0`, `en-US`.
"""

from __future__ import annotations

S_CTX = "AQABAAEAAAAmoFfGtYxvRrNriQdPKIZ-abc123def456"
S_FT = "AQABAAEAAAD--DLA3VO7QrddgJg7Wevrxyz789uvw012"
CANARY = "BB7pQmVJqNvKlmnop123456789abcdefghij"
SESSION_ID = "11112222-3333-4444-5555-666677778888"
CLIENT_REQUEST_ID = "99998888-7777-6666-5555-444433332222"
HPGID = "1104"
INSTRUMENTATION_KEY = "aaaabbbb-cccc-dddd-eeee-ffff00001111"

# Two values, one key. Nothing here is extractable without guessing which one was meant.
NONCE_FIRST = "firstnoncevalue0123456789abcdef"
NONCE_SECOND = "secondnoncevalue9876543210fedcba"


def login_page() -> str:
    """The page as one string.

    The escaped ampersand is built from a named constant rather than written inline, so no amount
    of shell or editor quoting can quietly turn those six characters into one.
    """
    escaped_amp = "\\u0026"
    return (
        "<!DOCTYPE html><html><head><title>Sign in</title></head><body>"
        "<script type='text/javascript'>"
        "//<![CDATA[\n"
        "$Config={"
        '"iMaxStackForKnockoutAsyncComponents":10000,'
        f'"sCtx":"{S_CTX}",'
        f'"sFT":"{S_FT}",'
        f'"canary":"{CANARY}",'
        f'"sessionId":"{SESSION_ID}",'
        f'"hpgid":{HPGID},'
        '"hpgact":1800,'
        f'"instrumentationKey":"{INSTRUMENTATION_KEY}",'
        '"fShowPersistentCookiesWarning":false,'
        '"isCookieBannerShown":true,'
        '"country":"en-US",'
        '"iProductIcon":0,'
        f'"urlPost":"/common/login?client-request-id={CLIENT_REQUEST_ID}{escaped_amp}mkt=en-US",'
        f'"nonce":"{NONCE_FIRST}",'
        '"apiCanary":{'
        f'"nonce":"{NONCE_SECOND}"'
        "},"
        '"urlCancel":"https://login.microsoftonline.com/common/reprocess"'
        "};\n"
        "//]]>\n"
        "</script>"
        "<form id='credentials' method='post'><input name='loginfmt' type='email'></form>"
        "</body></html>"
    )
