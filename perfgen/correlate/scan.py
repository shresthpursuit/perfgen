"""Finding values the server generated that a later request carried back.

Candidate detection is deterministic and has a right answer: flatten every response into
`(location, value)` pairs, then look for those exact strings in every later request. No model is
involved and none is needed.

The two filters are what make the output usable rather than noise. Without them a real API
produces hundreds of "correlations" on `true`, `200`, `USD` and every value the client itself
sent, and a reviewer stops reading. Both are required:

* **Low entropy.** Short strings, booleans, common enums, small integers, and anything appearing
  across many different responses. These match by coincidence, not by causation.
* **Client-originated.** If a value is in request N *and* response N, the server echoed back what
  the client sent. It came from the spec, not from the server, so wiring an extractor for it adds
  a moving part that replaces a constant with the same constant.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from perfgen.correlate.models import Candidate, Rejection, ScanResult
from perfgen.probe.records import ProbeRecord, RecordedCall
from perfgen.probe.redact import REDACTED

# Values shorter than this match by accident far more often than by causation.
MIN_VALUE_LENGTH = 8

# An integer smaller than this is a count, a status, a page number - not an identifier.
MIN_INTERESTING_INT = 100_000

# A value coming back from this many different responses is ambient, not a link between two.
UBIQUITY_LIMIT = 3

COMMON_ENUMS = frozenset(
    {
        "true", "false", "null", "none", "nil", "yes", "no",
        "ok", "success", "error", "failed", "pending", "active", "inactive",
        "enabled", "disabled", "open", "closed", "new", "draft", "standard",
        "usd", "eur", "gbp", "jpy", "aud", "cad",
        "get", "post", "put", "patch", "delete",
        "application/json", "text/plain", "utf-8",
        "asc", "desc", "all", "any", "default",
    }
)

_NUMERIC = re.compile(r"^-?\d+$")
_FLOAT = re.compile(r"^-?\d+\.\d+$")


# --------------------------------------------------------------------------------------------
# Indexing responses
# --------------------------------------------------------------------------------------------


def _walk_json(node: Any, path: str, out: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _walk_json(value, f"{path}.{key}", out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk_json(value, f"{path}[{index}]", out)
    elif isinstance(node, bool) or node is None:
        return  # booleans and nulls are never identifiers
    elif isinstance(node, str | int | float):
        out.append((path, str(node)))


def response_values(call: RecordedCall) -> list[tuple[str, str, str]]:
    """Every scalar a response produced, as (kind, location, value)."""
    if call.response is None:
        return []

    found: list[tuple[str, str, str]] = []

    if call.response.body:
        try:
            payload = json.loads(call.response.body)
        except (ValueError, TypeError):
            payload = None
        if payload is not None:
            leaves: list[tuple[str, str]] = []
            _walk_json(payload, "$", leaves)
            found.extend(("response_body", path, value) for path, value in leaves)

    for name, value in call.response.headers.items():
        if value and value != REDACTED:
            found.append(("response_header", name, value))

    for name, value in call.response.cookies.items():
        if value and value != REDACTED:
            found.append(("cookie", name, value))

    return found


def request_text(call: RecordedCall) -> dict[str, str]:
    """The places a later request could carry a value, keyed by where they are."""
    parts = urlsplit(call.request.url)
    text = {
        "path": parts.path,
        "query": parts.query,
        "body": call.request.body or "",
    }
    for name, value in call.request.headers.items():
        if value and value != REDACTED:
            text[f"header:{name}"] = value
    return text


# --------------------------------------------------------------------------------------------
# Filters
# --------------------------------------------------------------------------------------------


def low_entropy_reason(value: str, distinct_sources: int) -> str | None:
    """Why this value is not worth correlating, or None if it might be."""
    stripped = value.strip()

    if len(stripped) < MIN_VALUE_LENGTH:
        return f"only {len(stripped)} characters long; short values match by coincidence"
    if stripped.lower() in COMMON_ENUMS:
        return f"{stripped!r} is a common constant, not an identifier"
    if _NUMERIC.match(stripped) and abs(int(stripped)) < MIN_INTERESTING_INT:
        return f"{stripped} is a small integer - a count or a status, not an identifier"
    if _FLOAT.match(stripped):
        return f"{stripped} is a decimal number, not an identifier"
    if distinct_sources >= UBIQUITY_LIMIT:
        return (
            f"appears in {distinct_sources} different responses, so it is ambient rather than a "
            f"link between two particular calls"
        )
    return None


def is_client_originated(value: str, source_call: RecordedCall) -> bool:
    """True when the server merely echoed back something the client had just sent it."""
    return any(value in text for text in request_text(source_call).values())


# --------------------------------------------------------------------------------------------
# The scan
# --------------------------------------------------------------------------------------------


def find_candidates(record: ProbeRecord) -> ScanResult:
    """Scan a traffic record for values produced by one call and reused by a later one."""
    result = ScanResult()
    calls = record.calls

    # How many distinct responses each value came back from, for the ubiquity check.
    appearances: dict[str, set[int]] = {}
    indexed: list[list[tuple[str, str, str]]] = []
    for position, call in enumerate(calls):
        values = response_values(call)
        indexed.append(values)
        for _, _, value in values:
            appearances.setdefault(value, set()).add(position)

    next_id = 1
    seen: set[tuple[str, int, int]] = set()

    for source_position, call in enumerate(calls):
        for kind, location, value in indexed[source_position]:
            if value == REDACTED or not value.strip():
                continue

            for used_position in range(source_position + 1, len(calls)):
                later = calls[used_position]
                if later.flow_id is None:
                    continue  # the auth call is never a consumer of flow data

                where = _find_use(value, later)
                if where is None:
                    continue

                key = (value, source_position, used_position)
                if key in seen:
                    continue
                seen.add(key)

                reason = low_entropy_reason(value, len(appearances.get(value, ())))
                if reason is not None:
                    result.rejected.append(
                        Rejection(
                            value=value,
                            filter_name="low_entropy",
                            reason=reason,
                            source_step_name=call.name,
                            used_step_name=later.name,
                        )
                    )
                    continue

                if is_client_originated(value, call):
                    result.rejected.append(
                        Rejection(
                            value=value,
                            filter_name="client_originated",
                            reason=(
                                "the same value is in this call's own request, so the server "
                                "echoed back what the client sent; it is static, not generated"
                            ),
                            source_step_name=call.name,
                            used_step_name=later.name,
                        )
                    )
                    continue

                used_kind, used_detail = where
                result.candidates.append(
                    Candidate(
                        id=next_id,
                        value=value,
                        source_flow_id=call.flow_id,
                        source_step_index=call.step_index,
                        source_step_name=call.name,
                        source_kind=kind,
                        source_location=location,
                        used_flow_id=later.flow_id,
                        used_step_index=later.step_index or 0,
                        used_step_name=later.name,
                        used_kind=used_kind,
                        used_detail=used_detail,
                    )
                )
                next_id += 1

    return result


def _find_use(value: str, call: RecordedCall) -> tuple[str, str] | None:
    """Where in this request the value appears, if it does."""
    for where, text in request_text(call).items():
        if value and value in text:
            if where.startswith("header:"):
                return "header", where.split(":", 1)[1]
            return where, _snippet(text, value)
    return None


def _snippet(text: str, value: str, width: int = 24) -> str:
    """A little context around the match, so a reviewer can see how it was used."""
    index = text.find(value)
    start = max(0, index - width)
    end = min(len(text), index + len(value) + width)
    return ("..." if start > 0 else "") + text[start:end] + ("..." if end < len(text) else "")
