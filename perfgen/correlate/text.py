"""Finding values in a body no structured parser can read, and building an extractor for them.

Entra's `/authorize` answers with an HTML page carrying `"sCtx":"…"`, `"sFT":"…"` and
`"canary":"…"` inside a JavaScript config blob. `parse_body` returns None for it, so the
correlation scan contributes nothing and the login steps have no values to send.

Structured parsing hands you a *location* for free - `$.data[0].id` is both the answer and the
extractor. Raw text hands you a byte offset, which is useless as an extractor, so this module has
to synthesise one from surrounding context. That is where it can go quietly wrong, and the two
rules below are what keep it honest.

**Anchor on a key, never on a character window.** Taking N characters to the left of the match
produces context that may include a *neighbouring value that changes every run* - an extractor that
matches the recorded body and nothing afterwards. The failure is silent: JMeter substitutes the
extractor's default and the script carries on. So a value is only extractable if something
key-shaped sits immediately before it (`"sCtx":"`, `client-request-id=`, `"hpgid":`). If nothing
does, no extractor is offered at all.

**Prefer a boundary over a regex.** JMeter's Boundary Extractor takes two literal strings and needs
no escaping, which removes the single most common way a hand-written extractor breaks. The
reference script's `client-request-id=([A-Za-z0-9-]+)\\u0026` is the case in point: as a boundary
the right-hand side is the literal six characters `&`, with nothing to escape at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# How far back a key is allowed to sit. Long enough for `"instrumentationKey":"`, short enough that
# an unrelated key several fields away cannot be mistaken for this value's own.
_MAX_ANCHOR_DISTANCE = 40

# Longer than any credential or opaque token these flows carry. A match longer than this means the
# terminator was never found and the "value" ran on into the rest of the document.
_MAX_VALUE_LENGTH = 4096

# A key immediately before the value: optionally quoted, then `:` or `=`, then an optional opening
# quote. Anchored to the end of the preceding text, so it must abut the match.
_ANCHOR = re.compile(
    r"""(?P<quote>["'])?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})(?P=quote)?\s*(?P<sep>[:=])\s*
        (?P<open>["'])?$""",
    re.VERBOSE,
)

# What a value of this kind stops at. Order matters: the JSON-escaped ampersand is checked before
# the bare one because a URL embedded in a JavaScript string carries `&`, not `&`, and taking
# the bare `&` first would never match while `&` sat one character later. This six-character
# literal is also the clearest argument for boundaries over regex - as a regex it needs `\\\\u0026`
# and gets written wrong.
_CLOSERS = ('"', "'", "\\u0026", "&", ",", "<", ";", " ")


# A hidden form input: `<input type="hidden" name="request" value="...">`. Not an Entra shape -
# it is how HTML carries state through an auto-submitted interstitial, and SAML's POST binding
# looks identical. Two separate attributes, so the `key:value` anchoring above cannot see it: the
# name and the value are not adjacent, and what sits between them varies by tag.
#
# Only `name` before `value` is matched. The reverse order cannot produce a left boundary at all -
# the value would come first - and offering nothing is the rule when a reliable boundary cannot be
# built.
_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.IGNORECASE)


def _input_anchor(key_regex: str) -> re.Pattern[str]:
    return re.compile(
        r"\bname=(?P<nq>[\"']?)" + key_regex + r"(?P=nq)[^>]*?\bvalue=(?P<vq>[\"'])",
        re.IGNORECASE,
    )


@dataclass
class TextMatch:
    """One occurrence of a value in a body, with the context needed to extract it again."""

    value: str
    key: str
    left: str
    right: str
    occurrences: int
    """How many times `left` appears in the whole body. More than one means ambiguous."""

    @property
    def unique(self) -> bool:
        return self.occurrences == 1


def find_value(body: str, value: str) -> TextMatch | None:
    """Locate `value` in `body` and describe how to extract it, or return None.

    Returns None when the value is absent, when nothing key-shaped precedes it, or when no closing
    boundary can be found - all three mean "no extractor", never "guess one".
    """
    if not body or not value or value not in body:
        return None

    inside_input = _value_in_input(body, value)
    if inside_input is not None:
        return inside_input

    start = body.find(value)
    preceding = body[max(0, start - _MAX_ANCHOR_DISTANCE) : start]
    anchor = _ANCHOR.search(preceding)
    if anchor is None:
        return None

    left = anchor.group(0)
    right = _closing_boundary(body, start + len(value), anchor.group("open"))
    if right is None:
        return None

    return TextMatch(
        value=value,
        key=anchor.group("key"),
        left=left,
        right=right,
        occurrences=body.count(left),
    )


def key_pattern(key: str) -> str:
    """A pattern matching this key however it is spelled, separators aside.

    `{client_request_id}` has to find `client-request-id=` in the page, because the structured path
    already works that way - `normalise_field` strips separators from both sides, so `{userId}`
    finds `user_id`. Matching literally here would mean one placeholder style resolving in one
    context and not the other, with nothing in either to explain why.

    The key is split on separators *and* on case boundaries, then rejoined allowing any separator
    between the parts: `sessionId` -> `session[^A-Za-z0-9]*Id`, which finds `sessionId`,
    `session_id` and `session-id` alike.
    """
    parts = re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", key)
    if not parts:
        return re.escape(key)
    return r"[^A-Za-z0-9]*".join(re.escape(part) for part in parts)


def find_by_key(body: str, key: str) -> TextMatch | None:
    """Locate the value a *named* key carries. The probe's direction, not the scan's.

    The correlation scan works backwards - it has a value and wants the context that produces it.
    The probe works forwards: a declared step says `{sCtx}` and it needs a value before it can send
    the request at all. Same anchoring rules, same verification, opposite starting point.
    """
    if not body or not key:
        return None

    # Exact spelling first, loosened only if that finds nothing. Specificity matters more than it
    # looks: `sCtx` loosened to `s[^A-Za-z0-9]*Ctx` also matches `s?ctx=` in a `/reprocess?ctx=`
    # URL, and on a real login page that decoy sits 3KB *before* the real `"sCtx":"`. Trying the
    # exact form first means the loose form only ever has to cover the spellings it was added for.
    patterns = [re.escape(key)]
    loosened = key_pattern(key)
    if loosened != patterns[0]:
        patterns.append(loosened)

    for pattern in patterns:
        anchor = re.compile(
            # The key has to sit where a key can sit - after a delimiter, not in the middle of
            # something. Without this, `canary` matched the literal `CANARY:` *inside the canary's
            # own value* (`...=7:1:CANARY:g+uu...`) and returned the tail: 44 characters where the
            # real value is 99. It verified, because that context occurred exactly once. A
            # plausible, verifiable, silently wrong value is the failure this whole module exists
            # to avoid, so the anchor must be anchored itself.
            r"(?<![A-Za-z0-9:_-])"
            r'(?P<quote>["\'])?' + pattern + r'(?P=quote)?\s*[:=]\s*(?P<open>["\'])?',
            re.IGNORECASE,
        )
        # Every match, not just the first. A document this size will contain near-misses, and the
        # one that verifies is the answer - taking `search()` and giving up discards the real key
        # because something vaguely like it appeared earlier.
        for found in anchor.finditer(body):
            match = _match_at(body, found, key)
            if match is not None and verify(body, match):
                return match

    # Nothing key-shaped carried it. Try a hidden form input, where the name and the value are two
    # separate attributes and so invisible to the anchoring above.
    for pattern in patterns:
        for found in _input_anchor(pattern).finditer(body):
            match = _input_match_at(body, found, key)
            if match is not None and verify(body, match):
                return match
    return None


def _input_match_at(body: str, found: re.Match[str], key: str) -> TextMatch | None:
    """Build a TextMatch from a `name=... value="` hit inside an `<input>` tag."""
    left = found.group(0)
    quote = found.group("vq")
    start = found.end()
    end = body.find(quote, start)
    if end < 0 or end == start:
        return None
    value = body[start:end]
    if len(value) > _MAX_VALUE_LENGTH:
        return None
    return TextMatch(value=value, key=key, left=left, right=quote, occurrences=body.count(left))


def _match_at(body: str, found: re.Match[str], key: str) -> TextMatch | None:
    """Build a TextMatch from one anchor hit, or None if no boundary closes it."""
    left = found.group(0)
    start = found.end()
    opened = found.group("open")

    if opened:
        # Opened with a quote, so only that quote closes it - a comma inside a quoted value is
        # part of the value, not the end of it.
        end = body.find(opened, start)
        closer = opened
    else:
        candidates = [(body.find(c, start), c) for c in _CLOSERS if body.find(c, start) >= 0]
        if not candidates:
            return None
        end, closer = min(candidates)

    if end < 0 or end == start:
        return None
    value = body[start:end]
    if len(value) > _MAX_VALUE_LENGTH:
        # A runaway match means the anchor was wrong, not that the value is enormous.
        return None

    return TextMatch(value=value, key=key, left=left, right=closer, occurrences=body.count(left))


def _value_in_input(body: str, value: str) -> TextMatch | None:
    """When the value is a hidden input's, anchor on that input's own name.

    The generic left-context scan would otherwise settle on `value="`, which every input on the
    page shares - ambiguous, so rejected, so no extractor at all. Anchoring on `name="request"
    value="` names the one field meant, and it is the boundary the emitted script needs to read
    an auto-submitted interstitial back.
    """
    for tag in _INPUT_TAG.finditer(body):
        if value not in tag.group(0):
            continue
        named = re.search(
            r"\bname=([\"']?)(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)\1[^>]*?\bvalue=(?P<vq>[\"'])",
            tag.group(0),
            re.IGNORECASE,
        )
        if named is None:
            continue
        left = named.group(0)
        quote = named.group("vq")
        start = tag.start() + named.end()
        end = body.find(quote, start)
        if end < 0 or body[start:end] != value:
            continue
        return TextMatch(
            value=value,
            key=named.group("key"),
            left=left,
            right=quote,
            occurrences=body.count(left),
        )
    return None


def _closing_boundary(body: str, end: int, opened_with: str | None) -> str | None:
    """What terminates the value. The quote it opened with, if it opened with one."""
    tail = body[end : end + 8]
    if not tail:
        return None
    if opened_with and tail.startswith(opened_with):
        return opened_with
    for closer in _CLOSERS:
        if tail.startswith(closer):
            return closer
    return None


def verify(body: str, match: TextMatch) -> bool:
    """Run the synthesised boundary extraction against the recorded body.

    The guard that matters. An extractor is trusted only if executing it here reproduces exactly
    the value that was correlated, exactly once - not because its context looked plausible. An
    expression that cannot be demonstrated to work on the one body we have is not offered at all.
    """
    if not match.unique:
        return False
    start = body.find(match.left)
    if start < 0:
        return False
    start += len(match.left)
    end = body.find(match.right, start)
    if end < 0:
        return False
    return body[start:end] == match.value


def index_text(body: str, wanted: list[str]) -> dict[str, TextMatch]:
    """Find each wanted value in an unparseable body, keyed by the key that anchors it.

    The search direction is inverted compared with structured parsing, and it has to be: an HTML
    blob cannot be enumerated into leaves, but the values a later request carries are a short,
    known list. So this asks "does this body contain that value" rather than "what values does this
    body hold".
    """
    found: dict[str, TextMatch] = {}
    for value in wanted:
        match = find_value(body, value)
        if match is not None and verify(body, match):
            found.setdefault(match.key, match)
    return found
