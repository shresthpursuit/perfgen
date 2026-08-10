"""Stable names for generated elements and JMeter properties.

Transaction Controller names must be stable and sortable so that two runs of the generator over the
same spec produce diffable output and results group predictably in a report.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def slug(text: str) -> str:
    """Lowercase, underscore-separated, alphanumeric only."""
    return _NON_ALNUM.sub("_", text.strip().lower()).strip("_")


def transaction_name(flow_id: str, step_index: int, step_name: str) -> str:
    """`{flow_id}_{step_index:02d}_{step_name_slug}` — stable and sortable."""
    return f"{flow_id}_{step_index:02d}_{slug(step_name)}"


def users_prop(flow_id: str) -> str:
    """Per-flow, never per-profile: one JMX serves every profile via property files (D1)."""
    return f"users_{flow_id}"


def throughput_prop(flow_id: str) -> str:
    return f"tput_{flow_id}"


RAMPUP_PROP = "rampup_s"
DURATION_PROP = "duration_s"


def prop_ref(name: str, default: object) -> str:
    """`${__P(name,default)}`."""
    return f"${{__P({name},{default})}}"


def var_ref(name: str, scope_is_global: bool) -> str:
    """A `global`-scoped value lives in a JMeter property; the others are thread variables."""
    return f"${{__P({name})}}" if scope_is_global else f"${{{name}}}"


def java_hash_code(text: str) -> int:
    """Java's String.hashCode(), which JMeter uses to key assertion test strings."""
    h = 0
    for char in text:
        h = (31 * h + ord(char)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return h


def split_base_url(base_url: str) -> tuple[str, str, str]:
    """Split a base URL into (protocol, host, port), port empty when the scheme default applies."""
    protocol, host, port, _ = split_url(base_url)
    return protocol, host, port


def split_url(url: str) -> tuple[str, str, str, str]:
    """Split a full URL into (protocol, host, port, path)."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise ValueError(f"URL must include a scheme and host: {url!r}")
    port = "" if parts.port is None else str(parts.port)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return parts.scheme, parts.hostname, port, path


def env_var(reference_name: str) -> str:
    """`perf-client-id` -> `PERF_CLIENT_ID`, per the brief's secrets resolution rule."""
    return _NON_ALNUM.sub("_", reference_name.strip().lower()).strip("_").upper()


def env_lookup(reference_name: str) -> str:
    """A run-time environment lookup that works in stock JMeter.

    `${__env(...)}` is NOT a core JMeter function - it ships with the third-party jpgc Custom
    Functions plugin. An unknown function is not an error in JMeter: it is passed through as
    literal text, so a script using `__env` silently authenticates with the string
    "${__env(PERF_CLIENT_ID)}" and fails in a way that looks like a credentials problem.

    `__groovy` is core, so `System.getenv` is the portable way to read a secret at run time. Only
    the variable's name is ever written here - never its value.
    """
    return f"${{__groovy(System.getenv('{env_var(reference_name)}'))}}"


def match_credential_ref(param_name: str, credential_refs: list[str]) -> str | None:
    """Find the credential reference that supplies a token request parameter.

    The IR lists parameter names and credential reference names as two independent lists with no
    mapping between them, so the emitter matches by name: a reference supplies a parameter when its
    normalised form equals the parameter, or ends with `_<parameter>`. `perf-client-secret` thus
    supplies `client_secret`, while `grant_type` matches nothing and is not a secret.

    Deterministic: candidates are sorted, and the shortest (most specific) match wins.
    """
    target = _NON_ALNUM.sub("_", param_name.strip().lower()).strip("_")
    candidates = [
        ref
        for ref in credential_refs
        if (norm := _NON_ALNUM.sub("_", ref.strip().lower()).strip("_")) == target
        or norm.endswith(f"_{target}")
    ]
    if not candidates:
        return None
    return sorted(candidates, key=lambda r: (len(r), r))[0]
