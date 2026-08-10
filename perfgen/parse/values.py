"""Turning what the workbook says into what the IR means.

The workbook is written for a human: `OAuth2 client credentials`, `All flows`, `%`, `Yes`,
`Duration (min)`. The IR is written for a machine. Every conversion lives here so there is one
place to look when a spec is rejected for a value the user believes they typed correctly.

Unrecognised values are never guessed at. They come back as `None` and the caller records a gap.
"""

from __future__ import annotations

from perfgen.ir.models import (
    AuthStrategy,
    AuthType,
    Method,
    ProfileId,
    SlaMetric,
    SlaUnit,
    ThroughputUnit,
)
from perfgen.parse.sheets import cell_text, normalise

AUTH_TYPES: dict[str, AuthType] = {
    "none": AuthType.NONE,
    "oauth2 client credentials": AuthType.OAUTH2_CLIENT_CREDENTIALS,
    "oauth2 password": AuthType.OAUTH2_PASSWORD,
    "oauth2 pkce": AuthType.OAUTH2_PKCE,
    "bearer static": AuthType.BEARER_STATIC,
    "api key": AuthType.API_KEY,
    "basic": AuthType.BASIC,
}

ACCOUNT_MODELS: dict[str, AuthStrategy] = {
    "single shared": AuthStrategy.SHARED_SETUP,
    "one per user": AuthStrategy.PER_THREAD,
}

PROFILE_IDS: dict[str, ProfileId] = {
    "baseline": ProfileId.BASELINE,
    "peak load": ProfileId.PEAK,
    "peak": ProfileId.PEAK,
    "capacity / overload": ProfileId.CAPACITY,
    "capacity/overload": ProfileId.CAPACITY,
    "capacity": ProfileId.CAPACITY,
    "endurance": ProfileId.ENDURANCE,
}

SLA_METRICS: dict[str, SlaMetric] = {
    "response time 50th percentile": SlaMetric.RESPONSE_TIME_P50,
    "response time 90th percentile": SlaMetric.RESPONSE_TIME_P90,
    "response time 95th percentile": SlaMetric.RESPONSE_TIME_P95,
    "response time 99th percentile": SlaMetric.RESPONSE_TIME_P99,
    "error rate": SlaMetric.ERROR_RATE,
    "throughput": SlaMetric.THROUGHPUT,
}

SLA_UNITS: dict[str, SlaUnit] = {
    "ms": SlaUnit.MS,
    "s": SlaUnit.S,
    "%": SlaUnit.PERCENT,
    "percent": SlaUnit.PERCENT,
    "tps": SlaUnit.TPS,
    "tpm": SlaUnit.TPM,
    "tph": SlaUnit.TPH,
}

THROUGHPUT_UNITS: dict[str, ThroughputUnit] = {
    "tps": ThroughputUnit.TPS,
    "tpm": ThroughputUnit.TPM,
    "tph": ThroughputUnit.TPH,
}

METHODS: dict[str, Method] = {m.value.casefold(): m for m in Method}

_TRUE = {"yes", "y", "true", "1"}
_FALSE = {"no", "n", "false", "0"}


def as_bool(value: object) -> bool | None:
    key = normalise(value)
    if key in _TRUE:
        return True
    if key in _FALSE:
        return False
    return None


def as_int(value: object) -> int | None:
    """Read a whole number, tolerating Excel handing back a float like 25.0."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        number = float(str(value).strip().replace(",", ""))
    except ValueError:
        return None
    if number != int(number):
        return None
    return int(number)


def as_float(value: object) -> float | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        return float(str(value).strip().replace(",", ""))
    except ValueError:
        return None


def as_text(value: object) -> str | None:
    return cell_text(value)


def as_lines(value: object) -> list[str]:
    """A newline-separated cell into a list, tolerating commas and stray blank lines."""
    text = cell_text(value)
    if text is None:
        return []
    separator = "\n" if "\n" in text else ","
    return [part.strip() for part in text.split(separator) if part.strip()]


def lookup(table: dict, value: object):
    """Map workbook text to an IR enum, returning None when it is not a known value."""
    return table.get(normalise(value))


def minutes_to_seconds(value: object) -> int | None:
    minutes = as_float(value)
    return None if minutes is None else int(round(minutes * 60))


def seconds_to_ms(value: object) -> int | None:
    seconds = as_float(value)
    return None if seconds is None else int(round(seconds * 1000))


def sla_scope(value: object) -> str | None:
    """`All flows` becomes `all`; anything else is taken as a flow id."""
    text = cell_text(value)
    if text is None:
        return None
    if normalise(text) in {"all flows", "all", "all flow"}:
        return "all"
    return text


def infer_content_type(body: str | None) -> str | None:
    """Content type is inferred from the request body when the sheet does not carry a column."""
    if not body:
        return None
    stripped = body.lstrip()
    if stripped.startswith(("{", "[")):
        return "application/json"
    if stripped.startswith("<"):
        return "application/xml"
    if "=" in stripped and "\n" not in stripped.strip():
        return "application/x-www-form-urlencoded"
    return None
