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


def find_by_key(body: str, key: str) -> TextMatch | None:
    """Locate the value a *named* key carries. The probe's direction, not the scan's.

    The correlation scan works backwards - it has a value and wants the context that produces it.
    The probe works forwards: a declared step says `{sCtx}` and it needs a value before it can send
    the request at all. Same anchoring rules, same verification, opposite starting point.
    """
    if not body or not key:
        return None

    anchor = re.compile(
        r'(?P<quote>["\'])?' + re.escape(key) + r'(?P=quote)?\s*[:=]\s*(?P<open>["\'])?',
        re.IGNORECASE,
    )
    found = anchor.search(body)
    if found is None:
        return None

    left = found.group(0)
    start = found.end()
    opened = found.group("open")

    if opened:
        # Opened with a quote, so only that quote closes it - a comma inside a quoted value is
        # part of the value, not the end of it.
        end = body.find(opened, start)
        closer = opened
    else:
        candidates = [
            (body.find(c, start), c) for c in _CLOSERS if body.find(c, start) >= 0
        ]
        if not candidates:
            return None
        end, closer = min(candidates)

    if end < 0 or end == start:
        return None
    value = body[start:end]
    if len(value) > _MAX_VALUE_LENGTH:
        # A runaway match means the anchor was wrong, not that the value is enormous.
        return None

    return TextMatch(
        value=value, key=key, left=left, right=closer, occurrences=body.count(left)
    )


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
